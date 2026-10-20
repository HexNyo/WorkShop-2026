"""Surveillance continue : santé des services, STM planifiée, watchdog intégré, rétention.

Le watchdog est une détection de secours indépendante du moteur ML/SIEM : il émet
lui-même une alerte (source `watchdog`) lorsqu'un service reste DOWN plusieurs
sondages consécutifs, ou lorsque la transaction synthétique planifiée échoue.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from datetime import UTC, datetime, timedelta

import httpx
from ra_common.db import UNAVAILABLE_ERRORS, Database
from ra_common.logging import log_event

from app.core.config import Settings
from app.domain.models import AlertSubmission, Category, IncidentStatus, ServiceHealth, ServiceStatus, Severity
from app.domain.security import fingerprint
from app.observability import SERVICE_HEALTH
from app.repositories.incidents import IncidentRepository
from app.repositories.observations import HealthRepository
from app.services.events import SupervisionEvents
from app.services.intake import AlertIntake
from app.services.phases import PhaseTracker
from app.services.verifier import SyntheticVerifier

logger = logging.getLogger("remediation.monitor")
_DEGRADED_LATENCY_MS = 500
_HEARTBEAT_SECONDS = 15.0
_HEALTH_VALUE = {ServiceStatus.UP: 2, ServiceStatus.DEGRADED: 1, ServiceStatus.DOWN: 0, ServiceStatus.UNKNOWN: 0}

STM_FAILURE_ALERTS: dict[str, tuple[Category, str, Severity]] = {
    "DATA_INTEGRITY": (Category.DATA_INTEGRITY_VIOLATION, "payment-api", Severity.CRITICAL),
    "AUTH_M2M_TOKEN": (Category.SERVICE_UNAVAILABLE, "auth-service", Severity.CRITICAL),
}


def classify(http_status: int | None, body_status: str | None, latency_ms: int | None, failures: int) -> ServiceStatus:
    if http_status == 200:
        if body_status == "warn" or (latency_ms is not None and latency_ms > _DEGRADED_LATENCY_MS):
            return ServiceStatus.DEGRADED
        return ServiceStatus.UP
    return ServiceStatus.DOWN if failures >= 2 else ServiceStatus.DEGRADED


class HealthMonitor:
    def __init__(
        self,
        *,
        db: Database,
        http: httpx.AsyncClient,
        health: HealthRepository,
        incidents: IncidentRepository,
        intake: AlertIntake,
        verifier: SyntheticVerifier,
        phases: PhaseTracker,
        events: SupervisionEvents,
        settings: Settings,
    ) -> None:
        self._db = db
        self._http = http
        self._repository = health
        self._incidents = incidents
        self._intake = intake
        self._verifier = verifier
        self._phases = phases
        self._events = events
        self._settings = settings
        self._targets = settings.monitored
        self.health: dict[str, ServiceHealth] = {}
        self._last_published: dict[str, float] = {}
        self._watchdog_raised: set[str] = set()
        self._tasks: list[asyncio.Task[None]] = []

    def snapshot(self) -> dict[str, ServiceStatus]:
        return {name: item.status for name, item in self.health.items()}

    def start(self) -> None:
        self._tasks = [asyncio.create_task(self._loop(self._poll_once, self._settings.health_poll_seconds), name="health-poll")]
        if self._settings.scheduled_stm_seconds > 0:
            self._tasks.append(
                asyncio.create_task(self._loop(self._scheduled_stm, self._settings.scheduled_stm_seconds), name="scheduled-stm")
            )
        self._tasks.append(asyncio.create_task(self._loop(self._retention, 600), name="health-retention"))

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await task

    async def _loop(self, job, interval: float) -> None:
        while True:
            started = time.monotonic()
            try:
                await job()
            except asyncio.CancelledError:
                raise
            except UNAVAILABLE_ERRORS as exc:
                logger.warning("%s skipped: %s", job.__name__, exc.__class__.__name__, extra={"event": "monitor.skipped"})
            except Exception:  # noqa: BLE001 - la surveillance ne doit jamais s'arrêter
                logger.exception("monitor job failed", extra={"event": "monitor.error"})
            await asyncio.sleep(max(interval - (time.monotonic() - started), 0.1))

    # ------------------------------------------------------------------ santé
    async def _probe(self, service: str, url: str) -> ServiceHealth:
        previous = self.health.get(service)
        failures = previous.consecutive_failures if previous else 0
        started = time.perf_counter()
        http_status: int | None = None
        body_status: str | None = None
        detail: str | None = None
        try:
            response = await self._http.get(url, timeout=self._settings.health_timeout_seconds)
            http_status = response.status_code
            body = response.json() if response.content else {}
            body_status = body.get("status")
            failing = [name for name, results in body.get("checks", {}).items() if results[0]["status"] != "pass"]
            detail = ", ".join(f"{name}={body['checks'][name][0].get('observedValue', 'fail')}" for name in failing) or None
        except (httpx.HTTPError, ValueError) as exc:
            detail = exc.__class__.__name__
        latency = int((time.perf_counter() - started) * 1000)
        failures = 0 if http_status == 200 else failures + 1
        status = classify(http_status, body_status, latency, failures)
        return ServiceHealth(
            service=service,
            status=status,
            latency_ms=latency if http_status is not None else None,
            checked_at=datetime.now(UTC),
            detail=detail,
            consecutive_failures=failures,
        )

    async def _probe_database(self) -> ServiceHealth:
        try:
            latency = int(await self._db.ping())
            status = ServiceStatus.UP if latency < _DEGRADED_LATENCY_MS else ServiceStatus.DEGRADED
            return ServiceHealth("database", status, latency, datetime.now(UTC))
        except (*UNAVAILABLE_ERRORS, RuntimeError) as exc:
            previous = self.health.get("database")
            failures = (previous.consecutive_failures if previous else 0) + 1
            status = ServiceStatus.DOWN if failures >= 2 else ServiceStatus.DEGRADED
            return ServiceHealth("database", status, None, datetime.now(UTC), exc.__class__.__name__, failures)

    async def _poll_once(self) -> None:
        results = await asyncio.gather(*(self._probe(name, url) for name, url in self._targets.items()), self._probe_database())
        results.append(ServiceHealth("remediation-engine", ServiceStatus.UP, 0, datetime.now(UTC)))
        now = time.monotonic()
        for result in results:
            previous = self.health.get(result.service)
            self.health[result.service] = result
            SERVICE_HEALTH.labels(service=result.service).set(_HEALTH_VALUE[result.status])
            status_changed = previous is None or previous.status is not result.status
            if status_changed or now - self._last_published.get(result.service, 0) >= _HEARTBEAT_SECONDS:
                self._last_published[result.service] = now
                self._events.publish(
                    "service.health",
                    {
                        "service": result.service,
                        "status": result.status.value,
                        "latency_ms": result.latency_ms,
                        "detail": result.detail,
                    },
                )
            if status_changed and previous is not None:
                log_event(
                    logger,
                    logging.WARNING if result.status is not ServiceStatus.UP else logging.INFO,
                    "service.health_changed",
                    f"{result.service} {previous.status.value} -> {result.status.value}",
                    service=result.service,
                    detail=result.detail,
                )
        with contextlib.suppress(*UNAVAILABLE_ERRORS):
            async with self._db.transaction() as conn:
                for result in results:
                    await self._repository.add_sample(
                        conn,
                        service=result.service,
                        status=result.status.value,
                        latency_ms=result.latency_ms,
                        http_status=None,
                        details={"detail": result.detail} if result.detail else {},
                    )
        await self._watchdog(results)
        # Recalcul systématique : la phase RESTORED expire avec le temps.
        await self._phases.refresh()

    async def _watchdog(self, results: list[ServiceHealth]) -> None:
        if not self._settings.watchdog_enabled:
            return
        for result in results:
            if result.status is ServiceStatus.UP:
                self._watchdog_raised.discard(result.service)
                continue
            if (
                result.service in self._targets
                and result.consecutive_failures >= self._settings.watchdog_down_polls
                and result.service not in self._watchdog_raised
            ):
                self._watchdog_raised.add(result.service)
                await self._raise(
                    category=Category.SERVICE_UNAVAILABLE,
                    service=result.service,
                    severity=Severity.CRITICAL,
                    title=f"{result.service} unavailable for {result.consecutive_failures} consecutive probes",
                    external_id=f"watchdog-down-{result.service}-{int(time.time())}",
                    evidence={"consecutive_failures": result.consecutive_failures, "detail": result.detail},
                )

    async def _raise(
        self, *, category: Category, service: str, severity: Severity, title: str, external_id: str, evidence: dict
    ) -> None:
        alert = AlertSubmission(
            source="watchdog",
            external_id=external_id,
            detected_at=datetime.now(UTC),
            category=category,
            severity=severity,
            confidence=1.0,
            title=title,
            description="raised by the remediation engine built-in watchdog",
            target_service=service,
            target_principal_id=None,
            target_account_id=None,
            fingerprint=fingerprint(
                explicit=None, category=category.value, service=service, principal_id=None, account_id=None
            ),
            payload={"source": "watchdog", "evidence": evidence},
        )
        await self._intake.submit(alert)

    # ------------------------------------------------------------ STM planifiée
    async def _scheduled_stm(self) -> None:
        async with self._db.connection() as conn:
            open_incidents = await self._incidents.list_open(conn)
        # Un incident ESCALATED attend un humain : il ne doit pas masquer une autre panne (ex. intégrité),
        # sinon sa vérification manuelle échoue indéfiniment sans qu'aucun playbook ne la corrige.
        if any(incident.status != IncidentStatus.ESCALATED for incident in open_incidents):
            return  # pas de sonde concurrente pendant un incident actif (les vérifications dédiées priment)
        outcome = await self._verifier.run(incident_id=None, execution_id=None, trigger_source="SCHEDULED")
        if outcome.passed or not self._settings.watchdog_enabled:
            return
        category, service, severity = STM_FAILURE_ALERTS.get(
            outcome.failed_check or "", (Category.SERVICE_UNAVAILABLE, "payment-api", Severity.HIGH)
        )
        await self._raise(
            category=category,
            service=service,
            severity=severity,
            title=f"scheduled synthetic transaction failed at {outcome.failed_check}",
            external_id=f"watchdog-stm-{outcome.run_id}",
            evidence={"verification_run_id": str(outcome.run_id), "failed_check": outcome.failed_check},
        )

    async def _retention(self) -> None:
        async with self._db.transaction() as conn:
            purged = await self._repository.purge(conn, timedelta(hours=self._settings.health_retention_hours))
        if purged:
            log_event(logger, logging.INFO, "monitor.retention", "old health samples purged", purged=purged)
