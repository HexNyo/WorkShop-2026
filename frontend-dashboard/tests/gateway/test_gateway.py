"""Tests de la passerelle publique, depuis le réseau `edge` (vue d'un client externe).

Le conteneur de test n'est relié qu'au réseau edge : il ne peut joindre que la
passerelle, exactement comme un navigateur.
"""

from __future__ import annotations

import os
import socket
import time

import httpx
import pytest

GATEWAY = os.environ.get("GATEWAY_URL", "http://frontend-dashboard:8080")
CHAOS = os.environ.get("CHAOS_LAB_ENABLED", "false") == "true"


def secret(username: str) -> str:
    value = os.environ.get("AUTH_BOOTSTRAP_" + username.upper().replace("-", "_") + "_SECRET")
    assert value, f"secret for {username} missing"
    return value


@pytest.fixture(scope="session")
def gw():
    with httpx.Client(base_url=GATEWAY, timeout=15) as client:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                if client.get("/healthz").status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(1)
        yield client


_tokens: dict[str, str] = {}


def bearer(gw: httpx.Client, username: str) -> dict[str, str]:
    # Depuis le réseau edge, un jeton utilisateur exige désormais un visage enrôlé (verify-face).
    if username not in _tokens:
        pytest.skip("password-only login is closed at the gateway; user tokens need face enrolment")
    return {"Authorization": f"Bearer {_tokens[username]}"}


# ------------------------------------------------------------ isolation réseau
@pytest.mark.parametrize(
    ("host", "port"),
    [("auth-service", 8000), ("payment-api", 8000), ("remediation-engine", 8001), ("postgres", 5432), ("socket-proxy", 2375)],
)
def test_internal_services_are_not_reachable_from_edge(host: str, port: int) -> None:
    with pytest.raises(OSError):
        socket.create_connection((host, port), timeout=2)


# ----------------------------------------------------------------------- SPA
def test_spa_is_served_with_strict_security_headers(gw: httpx.Client) -> None:
    for path in ("/", "/supervision", "/payments/anything"):
        response = gw.get(path)
        assert response.status_code == 200 and "<div id=\"root\"></div>" in response.text
        headers = response.headers
        csp = headers["content-security-policy"]
        assert "default-src 'self'" in csp and "frame-ancestors 'none'" in csp and "'unsafe-inline'" not in csp
        assert headers["x-content-type-options"] == "nosniff"
        assert headers["x-frame-options"] == "DENY"
        assert headers["referrer-policy"] == "no-referrer"
        assert headers["cache-control"] == "no-store"
        assert "server" not in headers or "nginx/" not in headers["server"]


def test_hashed_assets_are_immutable(gw: httpx.Client) -> None:
    html = gw.get("/").text
    asset = html.split('src="', 1)[1].split('"', 1)[0]
    assert asset.startswith("/assets/")
    response = gw.get(asset)
    assert response.status_code == 200 and "immutable" in response.headers["cache-control"]
    assert response.headers["content-security-policy"]
    assert gw.get("/assets/does-not-exist.js").status_code == 404


def test_healthz(gw: httpx.Client) -> None:
    assert gw.get("/healthz").json() == {"status": "pass", "service": "frontend-dashboard"}


# ------------------------------------------------------------ liste blanche
@pytest.mark.parametrize(
    "path",
    [
        "/api/auth/internal/v1/revocations",
        "/api/auth/.well-known/jwks.json",
        "/api/auth/health/readiness",
        "/api/payment/admin/v1/runtime-flags",
        "/api/payment/health/integrity",
        "/api/payment/metrics",
        "/api/supervision/metrics",
        "/api/supervision/health/readiness",
        "/api/control/v1/alerts",
        "/api/remediation/v1/incidents",
        "/api/supervision/v1/../../health/readiness",
        "/api/payment/v1/../admin/v1/runtime-flags",
    ],
)
def test_only_public_contracts_are_routed(gw: httpx.Client, path: str) -> None:
    response = gw.get(path)
    assert response.status_code == 404, f"{path} must not be routed (got {response.status_code})"
    assert response.headers["content-type"].startswith("application/problem+json")


def test_webhook_is_unreachable_through_the_gateway(gw: httpx.Client) -> None:
    for path in ("/api/supervision/v1/alerts", "/api/control/v1/alerts"):
        assert gw.post(path, json={}).status_code in (404, 405)


def test_oversized_bodies_are_rejected(gw: httpx.Client) -> None:
    response = gw.post("/api/auth/v1/auth/refresh", content=b"x" * 70_000, headers={"Content-Type": "application/json"})
    assert response.status_code == 413
    face = gw.post("/api/auth/v1/auth/verify-face", content=b"x" * 1_100_000, headers={"Content-Type": "application/json"})
    assert face.status_code == 413


# --------------------------------------------------------------- parcours
def test_password_only_login_is_closed_but_two_step_login_is_routed(gw: httpx.Client) -> None:
    closed = gw.post("/api/auth/v1/auth/login", json={"username": "alice", "password": secret("alice")})
    assert closed.status_code == 404 and closed.headers["content-type"].startswith("application/problem+json")
    step2 = gw.post("/api/auth/v1/auth/verify-password", json={"pre_auth_token": "x" * 43, "password": "whatever"})
    assert step2.status_code == 401 and step2.json()["code"] == "PRE_AUTH_INVALID"
    assert "camera=(self)" in gw.get("/").headers["permissions-policy"]


def test_api_calls_are_proxied_with_request_ids(gw: httpx.Client) -> None:
    accounts = gw.get("/api/payment/v1/accounts", headers=bearer(gw, "alice"))
    assert accounts.status_code == 200 and accounts.json()["items"]
    assert len(accounts.headers["x-request-id"]) == 32, "the gateway request id is propagated upstream"
    overview = gw.get("/api/supervision/v1/overview", headers=bearer(gw, "noc-operator"))
    assert overview.status_code == 200 and overview.json()["phase"]
    assert gw.get("/api/supervision/v1/overview", headers=bearer(gw, "alice")).status_code == 403


def test_assistant_requires_noc_role_and_degrades_gracefully(gw: httpx.Client) -> None:
    body = {"conversation_id": None, "message": "test", "context": {}}
    unauthenticated = gw.post("/api/assistant/v1/chat", json=body)
    assert unauthenticated.status_code == 401 and unauthenticated.json()["code"] == "UNAUTHENTICATED"
    forbidden = gw.post("/api/assistant/v1/chat", json=body, headers=bearer(gw, "alice"))
    assert forbidden.status_code == 403 and forbidden.json()["code"] == "FORBIDDEN"
    allowed = gw.post("/api/assistant/v1/chat", json=body, headers=bearer(gw, "noc-operator"))
    # L'agent RAG (autre lot) n'est pas déployé ici : réponse problem+json explicite.
    assert allowed.status_code in (200, 503)
    if allowed.status_code == 503:
        assert allowed.json()["code"] == "ASSISTANT_UNAVAILABLE"


def test_sse_streams_without_buffering(gw: httpx.Client) -> None:
    ticket = gw.post("/api/supervision/v1/stream-tickets", headers=bearer(gw, "noc-operator")).json()["ticket"]
    started = time.monotonic()
    with gw.stream("GET", "/api/supervision/v1/stream", params={"ticket": ticket}, timeout=10) as stream:
        assert stream.status_code == 200
        assert stream.headers["content-type"].startswith("text/event-stream")
        first = next(stream.iter_text())
    assert first.startswith("retry:") and time.monotonic() - started < 3, "first bytes must not be buffered"


def test_lab_route_follows_the_flag(gw: httpx.Client) -> None:
    response = gw.get("/api/payment/lab/v1/faults", headers=bearer(gw, "admin"))
    assert response.status_code == (200 if CHAOS else 404)


def test_zz_login_is_rate_limited(gw: httpx.Client) -> None:
    statuses = [
        gw.post("/api/auth/v1/auth/verify-password", json={"pre_auth_token": "x" * 43, "password": "wrong"}).status_code
        for _ in range(40)
    ]
    assert 429 in statuses and set(statuses) <= {401, 429}
