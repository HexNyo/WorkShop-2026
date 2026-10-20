"""Tests de bout en bout : plateforme complète (auth, payment, moteur, proxy Docker)."""

from __future__ import annotations

import json
import os
import time
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime

import httpx
import pytest

from app.domain.security import sign

AUTH_URL = os.environ.get("E2E_AUTH_URL", "http://auth-service:8000")
PAYMENT_URL = os.environ.get("E2E_PAYMENT_URL", "http://payment-api:8000")
CONTROL_URL = os.environ.get("E2E_CONTROL_URL", "http://remediation-engine:8001")
SUPERVISION_URL = os.environ.get("E2E_SUPERVISION_URL", "http://remediation-engine:8002")
HMAC_SECRET = os.environ.get("E2E_WEBHOOK_HMAC_SECRET", "").encode()

BOB = "00000000-0000-4000-8000-000000000003"
SYNTHETIC_ACCOUNT_A = "90000000-0000-4000-8000-000000000001"
CLOSED = {"RESOLVED", "SUPPRESSED"}


def secret(username: str) -> str:
    value = os.environ.get("AUTH_BOOTSTRAP_" + username.upper().replace("-", "_") + "_SECRET")
    if not value:
        pytest.fail(f"secret for {username} missing in the test runner environment")
    return value


def _wait(client: httpx.Client, path: str) -> None:
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            if client.get(path).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(1)
    pytest.fail(f"{client.base_url}{path} not ready")


@pytest.fixture(scope="session")
def auth() -> Iterator[httpx.Client]:
    with httpx.Client(base_url=AUTH_URL, timeout=10) as client:
        _wait(client, "/health/readiness")
        yield client


@pytest.fixture(scope="session")
def payment() -> Iterator[httpx.Client]:
    with httpx.Client(base_url=PAYMENT_URL, timeout=30) as client:
        _wait(client, "/health/readiness")
        yield client


@pytest.fixture(scope="session")
def control() -> Iterator[httpx.Client]:
    with httpx.Client(base_url=CONTROL_URL, timeout=30) as client:
        _wait(client, "/health/readiness")
        yield client


@pytest.fixture(scope="session")
def supervision() -> Iterator[httpx.Client]:
    with httpx.Client(base_url=SUPERVISION_URL, timeout=30) as client:
        _wait(client, "/health/readiness")
        yield client


class Tokens:
    def __init__(self, auth_client: httpx.Client) -> None:
        self._auth = auth_client
        self._cache: dict[tuple[str, str | None], tuple[str, float]] = {}

    def __call__(self, principal: str, audience: str | None = None) -> dict[str, str]:
        key = (principal, audience)
        cached = self._cache.get(key)
        if cached is None or cached[1] < time.monotonic():
            if principal.startswith("svc-"):
                response = self._auth.post(
                    "/v1/oauth/token",
                    data={"grant_type": "client_credentials", "client_id": principal, "client_secret": secret(principal),
                          **({"audience": audience} if audience else {})},
                )
            else:
                response = self._auth.post("/v1/auth/login", json={"username": principal, "password": secret(principal)})
            assert response.status_code == 200, response.text
            cached = (response.json()["access_token"], time.monotonic() + 120)
            self._cache[key] = cached
        return {"Authorization": f"Bearer {cached[0]}"}


@pytest.fixture(scope="session")
def as_(auth: httpx.Client) -> Tokens:
    return Tokens(auth)


def alert_body(category: str, *, service: str = "payment-api", severity: str = "CRITICAL", confidence: float = 0.97,
               principal_id: str | None = None, account_id: str | None = None, fingerprint: str | None = None,
               external_id: str | None = None) -> dict:
    return {
        "schema_version": "1.0",
        "source": "e2e-detector",
        "external_id": external_id or f"e2e-{uuid.uuid4().hex}",
        "detected_at": datetime.now(UTC).isoformat(),
        "category": category,
        "severity": severity,
        "confidence": confidence,
        "title": f"e2e {category.lower()} on {service}",
        "target": {"service": service, "principal_id": principal_id, "account_id": account_id},
        "fingerprint": fingerprint,
        "evidence": {"source": "e2e"},
        "labels": {"suite": "e2e"},
    }


def send_alert(control: httpx.Client, as_: Tokens, body: dict, *, signature: str | None = "valid",
               principal: str = "svc-detector") -> httpx.Response:
    raw = json.dumps(body, separators=(",", ":")).encode()
    audience = {"svc-detector": "remediation-control"}.get(principal, "payment-api" if principal.startswith("svc-") else None)
    headers = {"Content-Type": "application/json", **as_(principal, audience)}
    if signature == "valid":
        headers["X-RA-Signature"] = sign(HMAC_SECRET, raw, int(time.time()))
    elif signature is not None:
        headers["X-RA-Signature"] = signature
    return control.post("/v1/alerts", content=raw, headers=headers)


def wait_incident(supervision: httpx.Client, as_: Tokens, incident_id: str, statuses: set[str], timeout: float = 180) -> dict:
    deadline = time.monotonic() + timeout
    detail: dict = {}
    while time.monotonic() < deadline:
        response = supervision.get(f"/v1/incidents/{incident_id}", headers=as_("noc-operator"))
        assert response.status_code == 200, response.text
        detail = response.json()
        if detail["status"] in statuses:
            return detail
        time.sleep(1)
    pytest.fail(f"incident {incident_id} stuck in {detail.get('status')}: {detail.get('status_reason')} / {detail.get('last_error')}")


def lab(payment: httpx.Client, as_: Tokens, body: dict) -> httpx.Response:
    return payment.post("/lab/v1/faults", json=body, headers=as_("admin"))


@pytest.fixture(scope="session")
def lab_enabled(payment: httpx.Client, as_: Tokens) -> None:
    if payment.get("/lab/v1/faults", headers=as_("admin")).status_code == 404:
        pytest.skip("chaos lab disabled (CHAOS_LAB_ENABLED=false)")
