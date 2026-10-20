"""Tests de bout en bout contre payment-api + auth-service réels (docker compose --profile test)."""

from __future__ import annotations

import os
import time
import uuid
from collections.abc import Iterator

import httpx
import pytest

AUTH_URL = os.environ.get("E2E_AUTH_URL", "http://auth-service:8000")
PAYMENT_URL = os.environ.get("E2E_PAYMENT_URL", "http://payment-api:8000")

ACCOUNTS = {
    "alice": "10000000-0000-4000-8000-000000000001",
    "alice-savings": "10000000-0000-4000-8000-000000000002",
    "bob": "10000000-0000-4000-8000-000000000003",
    "bob-usd": "10000000-0000-4000-8000-000000000004",
    "merchant": "10000000-0000-4000-8000-000000000005",
    "syn-a": "90000000-0000-4000-8000-000000000001",
    "syn-b": "90000000-0000-4000-8000-000000000002",
}
NUMBERS = {
    "alice": "RA-1000-0001",
    "alice-savings": "RA-1000-0002",
    "bob": "RA-1000-0003",
    "bob-usd": "RA-1000-0004",
    "merchant": "RA-2000-0001",
    "syn-a": "RA-9000-0001",
    "syn-b": "RA-9000-0002",
}


def secret(username: str) -> str:
    variable = "AUTH_BOOTSTRAP_" + username.upper().replace("-", "_") + "_SECRET"
    value = os.environ.get(variable)
    if not value:
        pytest.fail(f"{variable} must be provided to the e2e test runner")
    return value


def _wait_ready(client: httpx.Client, path: str) -> None:
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            response = client.get(path)
            if response.status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(1)
    pytest.fail(f"{client.base_url}{path} did not become ready")


@pytest.fixture(scope="session")
def auth() -> Iterator[httpx.Client]:
    with httpx.Client(base_url=AUTH_URL, timeout=10.0) as client:
        _wait_ready(client, "/health/readiness")
        yield client


@pytest.fixture(scope="session")
def api() -> Iterator[httpx.Client]:
    with httpx.Client(base_url=PAYMENT_URL, timeout=15.0) as client:
        _wait_ready(client, "/health/readiness")
        yield client


class Tokens:
    def __init__(self, auth_client: httpx.Client) -> None:
        self._auth = auth_client
        self._cache: dict[str, tuple[str, float]] = {}

    def fresh_user(self, username: str) -> str:
        response = self._auth.post("/v1/auth/login", json={"username": username, "password": secret(username)})
        assert response.status_code == 200, response.text
        return response.json()["access_token"]

    def fresh_service(self, client_id: str, audience: str = "payment-api") -> str:
        response = self._auth.post(
            "/v1/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": secret(client_id),
                "audience": audience,
            },
        )
        assert response.status_code == 200, response.text
        return response.json()["access_token"]

    def __call__(self, principal: str) -> dict[str, str]:
        cached = self._cache.get(principal)
        if cached is None or cached[1] < time.monotonic():
            token = self.fresh_service(principal) if principal.startswith("svc-") else self.fresh_user(principal)
            cached = (token, time.monotonic() + 200)
            self._cache[principal] = cached
        return {"Authorization": f"Bearer {cached[0]}"}


@pytest.fixture(scope="session")
def as_(auth: httpx.Client) -> Tokens:
    return Tokens(auth)


def new_key(prefix: str = "e2e") -> str:
    return f"{prefix}-{uuid.uuid4().hex}"


def pay(
    api: httpx.Client,
    headers: dict[str, str],
    debit: str,
    credit: str,
    value: str,
    *,
    currency: str = "EUR",
    key: str | None = None,
    auto_execute: bool = True,
    description: str | None = "e2e",
) -> httpx.Response:
    body = {
        "debit_account_id": ACCOUNTS[debit],
        "credit_account_number": NUMBERS[credit],
        "amount": {"value": value, "currency": currency},
        "auto_execute": auto_execute,
    }
    if description is not None:
        body["description"] = description
    return api.post("/v1/transactions", json=body, headers={**headers, "Idempotency-Key": key or new_key()})


def balance(api: httpx.Client, headers: dict[str, str], account: str) -> int:
    response = api.get(f"/v1/accounts/{ACCOUNTS[account]}", headers=headers)
    assert response.status_code == 200, response.text
    return response.json()["balance"]["minor"]
