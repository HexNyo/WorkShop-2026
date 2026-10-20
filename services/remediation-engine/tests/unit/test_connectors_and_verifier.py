"""Connecteurs et protocole STM contre des services simulés (httpx.MockTransport)."""

from __future__ import annotations

import json
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from uuid import UUID, uuid4

import httpx
import jwt
import pytest
from ra_common.security.service_token import ServiceTokenClient
from ra_common.sse import EventBroadcaster

from app.connectors.base import ActionError, StepContext
from app.connectors.docker import DockerConnector
from app.connectors.registry import ActionRegistry
from app.core.config import Settings
from app.domain.models import Category, Incident, IncidentStatus, Severity
from app.services.events import SupervisionEvents
from app.services.verifier import CHECKS, SyntheticVerifier


def make_incident() -> Incident:
    now = datetime.now(UTC)
    return Incident(
        id=uuid4(), fingerprint="0" * 64, category=Category.SERVICE_UNAVAILABLE, severity=Severity.CRITICAL,
        status=IncidentStatus.REMEDIATING, status_reason="r", title="t", target_service="payment-api",
        target_principal_id=None, target_account_id=None, playbook_code="PB-SERVICE-RESTART", attempt_count=1,
        alert_count=1, resolution=None, last_error=None, opened_at=now, remediation_started_at=now,
        verified_at=None, closed_at=None, updated_at=now,
    )


CTX = StepContext(incident=make_incident(), playbook_code="PB-SERVICE-RESTART", seq=1, phase="REMEDIATION")


# ------------------------------------------------------------------- docker
async def test_docker_restart_targets_labelled_container_only() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(f"{request.method} {request.url.path}")
        if request.url.path == "/containers/json":
            filters = json.loads(request.url.params["filters"])
            assert "resilience.remediable=true" in filters["label"]
            return httpx.Response(200, json=[{"Id": "a" * 64}])
        return httpx.Response(204)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        docker = DockerConnector(http, "http://proxy:2375", frozenset({"payment-api"}))
        output = await docker.restart(CTX, "payment-api", 10)
        assert output == {"service": "payment-api", "container_id": "a" * 12}
        assert calls == ["GET /containers/json", f"POST /containers/{'a' * 64}/restart"]
        with pytest.raises(ActionError) as excinfo:
            await docker.restart(CTX, "database", 10)
        assert excinfo.value.fatal, "the database is never restarted automatically"


async def test_registry_validates_parameters() -> None:
    registry = ActionRegistry(docker=None, payment=None, auth=None, probes=None)  # type: ignore[arg-type]
    assert "docker.restart_container" in registry.actions
    with pytest.raises(ActionError, match="not allowed"):
        registry.validate("shell.exec", {})
    with pytest.raises(ActionError, match="invalid parameters"):
        registry.validate("payment.set_write_mode", {"mode": "OPEN_BAR"})
    with pytest.raises(ActionError, match="invalid parameters"):
        registry.validate("auth.disable_principal", {"reason": "lowercase"})
    assert registry.validate("payment.purge_stale", {}).older_than_seconds == 120


# -------------------------------------------------------------- STM (V1→V9)
class FakeRepo:
    def __init__(self) -> None:
        self.checks: list[tuple[str, bool]] = []
        self.finished: dict | None = None

    async def create(self, _conn, **_kwargs) -> UUID:
        return uuid4()

    async def add_check(self, _conn, *, code, passed, **_kwargs) -> None:
        self.checks.append((code, passed))

    async def finish(self, _conn, _run_id, **kwargs):
        self.finished = kwargs
        return datetime.now(UTC)


class FakeDb:
    @asynccontextmanager
    async def transaction(self):
        yield None


class FakePayment:
    """Simule payment-api : comptes RA-9xxx, transactions idempotentes, grand livre, intégrité."""

    def __init__(self, *, integrity_status: str = "pass", ready: bool = True) -> None:
        self.balances = {"RA-9000-0001": 1000, "RA-9000-0002": 1000}
        self.ids = {"RA-9000-0001": str(uuid4()), "RA-9000-0002": str(uuid4())}
        self.by_key: dict[str, dict] = {}
        self.ledger: list[dict] = []
        self.integrity_status = integrity_status
        self.ready = ready

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/v1/oauth/token":
            now = int(time.time())
            token = jwt.encode({"aud": ["payment-api"], "roles": ["svc.synthetic"], "iat": now, "exp": now + 300}, "k" * 32)
            return httpx.Response(200, json={"access_token": token, "token_type": "Bearer", "expires_in": 300})
        if path == "/health/readiness":
            return httpx.Response(200 if self.ready else 503, json={"status": "pass" if self.ready else "fail"})
        if path == "/health/integrity":
            return httpx.Response(200 if self.integrity_status != "fail" else 503, json={"status": self.integrity_status, "checks": {}})
        if path == "/v1/accounts":
            return httpx.Response(200, json={"items": [
                {"id": self.ids[number], "account_number": number, "balance": {"minor": minor}}
                for number, minor in self.balances.items()
            ]})
        if path == "/v1/transactions" and request.method == "POST":
            key = request.headers["idempotency-key"]
            if key in self.by_key:
                return httpx.Response(200, json=self.by_key[key], headers={"Idempotent-Replayed": "true"})
            body = json.loads(request.content)
            debit = next(n for n, i in self.ids.items() if i == body["debit_account_id"])
            credit = body["credit_account_number"]
            self.balances[debit] -= 1
            self.balances[credit] += 1
            tx = {"id": str(uuid4()), "status": "EXECUTED"}
            self.ledger.append({"transaction_id": tx["id"], "direction": "CREDIT", "account": credit})
            self.by_key[key] = tx
            return httpx.Response(201, json=tx)
        if path.startswith("/v1/transactions/"):
            return httpx.Response(200, json={"history": [{"status": s} for s in ("PENDING", "VALIDATED", "EXECUTED")]})
        if path.endswith("/ledger"):
            account = next(n for n, i in self.ids.items() if i in path)
            return httpx.Response(200, json={"items": [e for e in reversed(self.ledger) if e["account"] == account]})
        return httpx.Response(404)


def settings() -> Settings:
    return Settings(
        db_password="x" * 32, auth_issuer="https://auth.test", client_secret="x" * 32, synthetic_client_secret="x" * 32,
        webhook_hmac_secret="x" * 32, stream_ticket_secret="x" * 32, payment_base_url="http://payment",
        stm_stability_interval_seconds=0.1,
    )


async def run_stm(fake: FakePayment) -> tuple[bool, str | None, FakeRepo, list]:
    repo = FakeRepo()
    events = SupervisionEvents(EventBroadcaster())
    async with httpx.AsyncClient(transport=httpx.MockTransport(fake.handler)) as http:
        tokens = ServiceTokenClient(token_url="http://auth/v1/oauth/token", client_id="svc-synthetic", client_secret="s" * 32, http_client=http)
        verifier = SyntheticVerifier(db=FakeDb(), repository=repo, http=http, tokens=tokens, events=events, settings=settings())  # type: ignore[arg-type]
        outcome = await verifier.run(incident_id=uuid4(), execution_id=None, trigger_source="REMEDIATION")
    published = [event.type for event in events.broadcaster._buffer]  # noqa: SLF001 - inspection de test
    return outcome.passed, outcome.failed_check, repo, published


async def test_stm_passes_all_nine_checks_and_restores_probe_balances() -> None:
    fake = FakePayment()
    passed, failed, repo, published = await run_stm(fake)
    assert passed and failed is None
    assert [code for code, ok in repo.checks if ok] == list(CHECKS)
    assert fake.balances == {"RA-9000-0001": 1000, "RA-9000-0002": 1000}, "compensation restores the probes"
    assert repo.finished["passed"] is True and len(repo.finished["transaction_ids"]) == 2
    assert published[0] == "verification.started" and published[-1] == "verification.completed"
    assert published.count("verification.check") == 9


async def test_stm_fails_fast_on_integrity_violation() -> None:
    passed, failed, repo, _ = await run_stm(FakePayment(integrity_status="fail"))
    assert not passed and failed == "DATA_INTEGRITY"
    assert repo.checks[-1] == ("DATA_INTEGRITY", False) and len(repo.checks) == 8


async def test_stm_fails_on_unready_api() -> None:
    passed, failed, repo, _ = await run_stm(FakePayment(ready=False))
    assert not passed and failed == "API_READINESS" and len(repo.checks) == 1


# ------------------------------------------------------- STM planifiée
class _MonitorDb:
    @asynccontextmanager
    async def connection(self):
        yield None


@pytest.mark.parametrize(("status", "raised"), [(IncidentStatus.ESCALATED, True), (IncidentStatus.REMEDIATING, False)])
async def test_scheduled_stm_not_masked_by_escalated_incident(status: IncidentStatus, raised: bool) -> None:
    from dataclasses import replace
    from types import SimpleNamespace

    from app.services.monitor import HealthMonitor
    from app.services.verifier import VerificationOutcome

    incident = replace(make_incident(), status=status)
    submitted: list = []

    async def run(**_: object) -> VerificationOutcome:
        return VerificationOutcome(run_id=uuid4(), passed=False, failed_check="DATA_INTEGRITY", transaction_ids=[])

    async def submit(alert: object) -> None:
        submitted.append(alert)

    async def list_open(_conn: object) -> list[Incident]:
        return [incident]

    monitor = HealthMonitor(
        db=_MonitorDb(), http=None, health=None, incidents=SimpleNamespace(list_open=list_open),  # type: ignore[arg-type]
        intake=SimpleNamespace(submit=submit), verifier=SimpleNamespace(run=run), phases=None,  # type: ignore[arg-type]
        events=None, settings=settings(),  # type: ignore[arg-type]
    )
    await monitor._scheduled_stm()
    assert [alert.category for alert in submitted] == ([Category.DATA_INTEGRITY_VIOLATION] if raised else [])
