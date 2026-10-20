"""Racine de composition du moteur de remédiation."""

from __future__ import annotations

from dataclasses import dataclass

import httpx
from ra_common.db import Database
from ra_common.ratelimit import SlidingWindowLimiter
from ra_common.security import TokenVerifier
from ra_common.security.resource_server import ResourceServerSecurity
from ra_common.security.service_token import ServiceTokenClient
from ra_common.sse import EventBroadcaster, StreamTicketSigner

from app.connectors.docker import DockerConnector
from app.connectors.platform import AuthAdminConnector, PaymentAdminConnector, ProbeConnector
from app.connectors.registry import ActionRegistry
from app.core.config import Settings
from app.repositories.incidents import AlertRepository, IncidentRepository
from app.repositories.observations import HealthRepository, PhaseRepository, PlaybookRepository
from app.repositories.runs import ExecutionRepository, VerificationRepository
from app.services.events import SupervisionEvents
from app.services.intake import AlertIntake
from app.services.monitor import HealthMonitor
from app.services.orchestrator import Orchestrator
from app.services.phases import PhaseTracker
from app.services.queries import SupervisionQueries
from app.services.runner import PlaybookRunner
from app.services.verifier import SyntheticVerifier

AUDIENCE_CONTROL = "remediation-control"
AUDIENCE_SUPERVISION = "remediation-supervision"


@dataclass(slots=True)
class Container:
    settings: Settings
    db: Database
    http: httpx.AsyncClient
    probe_http: httpx.AsyncClient
    security: ResourceServerSecurity
    control_verifier: TokenVerifier
    supervision_verifier: TokenVerifier
    docker: DockerConnector
    events: SupervisionEvents
    tickets: StreamTicketSigner
    webhook_limiter: SlidingWindowLimiter
    phases: PhaseTracker
    intake: AlertIntake
    orchestrator: Orchestrator
    verifier: SyntheticVerifier
    monitor: HealthMonitor
    queries: SupervisionQueries
    playbooks: PlaybookRepository
    incidents: IncidentRepository

    @classmethod
    def build(cls, settings: Settings) -> Container:
        db = Database(
            host=settings.db_host,
            port=settings.db_port,
            database=settings.db_name,
            user=settings.db_user,
            password=settings.db_password.get_secret_value(),
            application_name=settings.service_name,
            min_size=2,
            max_size=settings.db_pool_max_size,
            connect_timeout_seconds=settings.db_connect_timeout_seconds,
        )
        # keepalive_expiry < timeout keep-alive d'uvicorn (5 s) : évite de réutiliser une
        # connexion que le serveur est en train de fermer (ReadError / RemoteProtocolError).
        http = httpx.AsyncClient(timeout=10.0, limits=httpx.Limits(keepalive_expiry=2.0))
        probe_http = httpx.AsyncClient(timeout=5.0, limits=httpx.Limits(max_keepalive_connections=0))
        security = ResourceServerSecurity(
            auth_base_url=settings.auth_base_url,
            issuer=settings.auth_issuer,
            audience=AUDIENCE_SUPERVISION,
            client_id=settings.client_id,
            client_secret=settings.client_secret.get_secret_value(),
            poll_interval_seconds=settings.revocation_poll_seconds,
            leeway_seconds=settings.clock_leeway_seconds,
        )
        # Listener CONTROL : jetons du détecteur (aud remediation-control) et des
        # administrateurs humains (aud remediation-supervision) ; rôles vérifiés par route.
        control_verifier = TokenVerifier(
            issuer=settings.auth_issuer,
            audience=[AUDIENCE_CONTROL, AUDIENCE_SUPERVISION],
            key_resolver=security.jwks,
            revocation_checker=security.revocations,
            leeway_seconds=settings.clock_leeway_seconds,
        )
        token_url = f"{settings.auth_base_url.rstrip('/')}/v1/oauth/token"
        remediation_payment_tokens = ServiceTokenClient(
            token_url=token_url,
            client_id=settings.client_id,
            client_secret=settings.client_secret.get_secret_value(),
            audience="payment-api",
            http_client=http,
        )
        synthetic_tokens = ServiceTokenClient(
            token_url=token_url,
            client_id=settings.synthetic_client_id,
            client_secret=settings.synthetic_client_secret.get_secret_value(),
            audience="payment-api",
            http_client=http,
        )

        incidents, alerts = IncidentRepository(), AlertRepository()
        executions, verifications = ExecutionRepository(), VerificationRepository()
        health_repository, phase_repository, playbooks = HealthRepository(), PhaseRepository(), PlaybookRepository()
        events = SupervisionEvents(EventBroadcaster())

        docker = DockerConnector(http, settings.docker_proxy_url, settings.restartable)
        registry = ActionRegistry(
            docker=docker,
            payment=PaymentAdminConnector(http, settings.payment_base_url, remediation_payment_tokens),
            auth=AuthAdminConnector(http, settings.auth_base_url, security.feed_client),
            probes=ProbeConnector(http, settings.monitored),
        )
        phases = PhaseTracker(
            db=db,
            incidents=incidents,
            phases=phase_repository,
            events=events,
            restored_hold_seconds=settings.restored_hold_seconds,
        )
        verifier = SyntheticVerifier(
            db=db, repository=verifications, http=http, tokens=synthetic_tokens, events=events, settings=settings
        )
        intake = AlertIntake(
            db=db, incidents=incidents, alerts=alerts, events=events, phases=phases, min_confidence=settings.min_confidence
        )
        orchestrator = Orchestrator(
            db=db,
            incidents=incidents,
            executions=executions,
            verifications=verifications,
            playbooks=playbooks,
            registry=registry,
            runner=PlaybookRunner(db=db, executions=executions, registry=registry, events=events),
            verifier=verifier,
            events=events,
            phases=phases,
            workers=settings.workers,
            max_per_target_per_hour=settings.max_per_target_per_hour,
        )
        intake.bind_dispatcher(orchestrator.dispatch)
        monitor = HealthMonitor(
            db=db,
            http=probe_http,
            health=health_repository,
            incidents=incidents,
            intake=intake,
            verifier=verifier,
            phases=phases,
            events=events,
            settings=settings,
        )
        phases.bind_health(monitor.snapshot)

        return cls(
            settings=settings,
            db=db,
            http=http,
            probe_http=probe_http,
            security=security,
            control_verifier=control_verifier,
            supervision_verifier=security.verifier,
            docker=docker,
            events=events,
            tickets=StreamTicketSigner(
                settings.stream_ticket_secret.get_secret_value().encode(),
                purpose="remediation-supervision-sse",
            ),
            webhook_limiter=SlidingWindowLimiter(),
            phases=phases,
            intake=intake,
            orchestrator=orchestrator,
            verifier=verifier,
            monitor=monitor,
            queries=SupervisionQueries(
                db=db,
                incidents=incidents,
                alerts=alerts,
                executions=executions,
                verifications=verifications,
                health=health_repository,
                phases_repository=phase_repository,
                phases=phases,
                monitor=monitor,
                events=events,
            ),
            playbooks=playbooks,
            incidents=incidents,
        )

    async def start(self) -> None:
        await self.db.connect()
        await self.security.start()
        await self.orchestrator.validate_catalog()
        await self.phases.load()
        await self.orchestrator.start()
        self.monitor.start()

    async def stop(self) -> None:
        await self.monitor.stop()
        await self.orchestrator.stop()
        await self.security.stop()
        await self.http.aclose()
        await self.probe_http.aclose()
        await self.db.close()
