"""Tests de bout en bout contre un auth-service réel (docker compose --profile test)."""

from __future__ import annotations

import os
import time
from collections.abc import Iterator

import httpx
import pytest

BASE_URL = os.environ.get("AUTH_E2E_BASE_URL", "http://auth-service:8000")
CSRF = {"X-Requested-With": "ra-dashboard"}

PRINCIPAL_IDS = {
    "admin": "00000000-0000-4000-8000-000000000001",
    "alice": "00000000-0000-4000-8000-000000000002",
    "bob": "00000000-0000-4000-8000-000000000003",
    "merchant": "00000000-0000-4000-8000-000000000004",
    "noc-operator": "00000000-0000-4000-8000-000000000005",
    "svc-remediation": "00000000-0000-4000-8000-000000000101",
    "svc-detector": "00000000-0000-4000-8000-000000000103",
}


def secret(username: str) -> str:
    variable = "AUTH_BOOTSTRAP_" + username.upper().replace("-", "_") + "_SECRET"
    value = os.environ.get(variable)
    if not value:
        pytest.fail(f"{variable} must be provided to the e2e test runner")
    return value


@pytest.fixture(scope="session")
def client() -> Iterator[httpx.Client]:
    with httpx.Client(base_url=BASE_URL, timeout=10.0) as http:
        deadline = time.monotonic() + 60
        while True:
            try:
                if http.get("/health/readiness").status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            if time.monotonic() > deadline:
                pytest.fail("auth-service did not become ready")
            time.sleep(1)
        yield http


def login(client: httpx.Client, username: str, password: str | None = None) -> httpx.Response:
    return client.post("/v1/auth/login", json={"username": username, "password": password or secret(username)})


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def refresh_cookie(response: httpx.Response) -> str:
    # Le cookie est Secure + Path=/api/auth/... : on le rejoue explicitement en HTTP interne.
    for header in response.headers.get_list("set-cookie"):
        name, _, rest = header.partition("=")
        if name == "ra_refresh":
            return rest.split(";", 1)[0]
    raise AssertionError("refresh cookie not set")


def service_token(client: httpx.Client, client_id: str, audience: str | None = None) -> str:
    form = {"grant_type": "client_credentials", "client_id": client_id, "client_secret": secret(client_id)}
    if audience:
        form["audience"] = audience
    response = client.post("/v1/oauth/token", data=form)
    assert response.status_code == 200, response.text
    return response.json()["access_token"]
