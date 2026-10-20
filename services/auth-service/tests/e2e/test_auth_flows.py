from __future__ import annotations

import time

import httpx
import jwt
import pytest

from tests.e2e.conftest import (
    BASE_URL,
    CSRF,
    PRINCIPAL_IDS,
    bearer,
    login,
    refresh_cookie,
    secret,
    service_token,
)


# --------------------------------------------------------------------- publication
def test_health_jwks_and_metrics(client: httpx.Client) -> None:
    readiness = client.get("/health/readiness")
    assert readiness.status_code == 200
    assert readiness.headers["content-type"].startswith("application/health+json")
    assert readiness.json()["checks"]["postgres:connectivity"][0]["status"] == "pass"

    jwks = client.get("/.well-known/jwks.json").json()
    assert jwks["keys"] and all("d" not in key for key in jwks["keys"])

    assert "X-Request-ID" in readiness.headers
    assert "ra_http_requests_total" in client.get("/metrics").text


# ------------------------------------------------------------------ login humain
def test_login_issues_scoped_token_and_secure_cookie(client: httpx.Client) -> None:
    response = login(client, "alice")
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    assert body["token_type"] == "Bearer" and body["expires_in"] == 300
    assert body["principal"]["roles"] == ["payment.customer"]

    cookie_header = next(h for h in response.headers.get_list("set-cookie") if h.startswith("ra_refresh="))
    for attribute in ("HttpOnly", "Secure", "SameSite=strict", "Path=/api/auth/v1/auth"):
        assert attribute.lower() in cookie_header.lower()

    claims = jwt.decode(body["access_token"], options={"verify_signature": False})
    assert claims["sub"] == PRINCIPAL_IDS["alice"]
    assert {"payment-api", "auth-service"} <= set(claims["aud"])

    me = client.get("/v1/me", headers=bearer(body["access_token"]))
    assert me.status_code == 200 and me.json()["username"] == "alice"


def test_bad_credentials_are_generic(client: httpx.Client) -> None:
    for username in ("alice", "nobody-here"):
        response = login(client, username, "definitely-wrong-password")
        assert response.status_code == 401
        assert response.headers["content-type"].startswith("application/problem+json")
        assert response.json()["code"] == "INVALID_CREDENTIALS"
    # Un compte de service ne peut pas se connecter comme un humain.
    assert login(client, "svc-synthetic", secret("svc-synthetic")).status_code == 401


def test_validation_errors_never_echo_input(client: httpx.Client) -> None:
    response = client.post("/v1/auth/login", json={"username": "al", "password": "TopSecretValue", "extra": 1})
    assert response.status_code == 422
    assert "TopSecretValue" not in response.text
    assert {error["location"] for error in response.json()["errors"]} >= {"body.username", "body.extra"}


def test_lockout_after_repeated_failures_and_admin_unlock(client: httpx.Client) -> None:
    for _ in range(5):
        assert login(client, "merchant", "wrong-password-xyz").status_code == 401
    locked = login(client, "merchant")
    assert locked.status_code == 403 and locked.json()["code"] == "ACCOUNT_LOCKED"
    assert int(locked.headers["retry-after"]) > 0

    admin = login(client, "admin").json()["access_token"]
    unlocked = client.post(
        f"/internal/v1/principals/{PRINCIPAL_IDS['merchant']}/enable",
        json={"reason": "SUPPORT_UNLOCK"},
        headers=bearer(admin),
    )
    assert unlocked.status_code == 200, unlocked.text
    assert login(client, "merchant").status_code == 200


# ---------------------------------------------------------- refresh & réutilisation
def test_refresh_rotation_and_reuse_detection(client: httpx.Client) -> None:
    first = login(client, "bob")
    cookie_1 = refresh_cookie(first)

    assert client.post("/v1/auth/refresh", headers={"Cookie": f"ra_refresh={cookie_1}"}).status_code == 403, (
        "refresh without anti-CSRF header must be refused"
    )

    rotated = client.post("/v1/auth/refresh", headers={**CSRF, "Cookie": f"ra_refresh={cookie_1}"})
    assert rotated.status_code == 200, rotated.text
    cookie_2 = refresh_cookie(rotated)
    assert cookie_2 != cookie_1

    reused = client.post("/v1/auth/refresh", headers={**CSRF, "Cookie": f"ra_refresh={cookie_1}"})
    assert reused.status_code == 409 and reused.json()["code"] == "REFRESH_TOKEN_REUSED"
    assert "ra_refresh=;" in reused.headers["set-cookie"]

    # La famille entière est révoquée : le jeton légitime le plus récent est aussi invalidé.
    assert client.post("/v1/auth/refresh", headers={**CSRF, "Cookie": f"ra_refresh={cookie_2}"}).status_code == 401


def test_logout_revokes_access_and_refresh(client: httpx.Client) -> None:
    response = login(client, "alice")
    token, cookie = response.json()["access_token"], refresh_cookie(response)
    assert client.post("/v1/auth/logout", headers={**bearer(token), "Cookie": f"ra_refresh={cookie}"}).status_code == 204
    assert client.get("/v1/me", headers=bearer(token)).status_code == 401
    assert client.post("/v1/auth/refresh", headers={**CSRF, "Cookie": f"ra_refresh={cookie}"}).status_code == 401


def test_self_revocation_and_admin_only_foreign_revocation(client: httpx.Client) -> None:
    alice = login(client, "alice").json()["access_token"]
    other_jti = jwt.decode(login(client, "alice").json()["access_token"], options={"verify_signature": False})["jti"]
    forbidden = client.post("/v1/tokens/revoke", json={"jti": other_jti}, headers=bearer(alice))
    assert forbidden.status_code == 403
    assert client.post("/v1/tokens/revoke", headers=bearer(alice)).status_code == 204
    assert client.get("/v1/me", headers=bearer(alice)).status_code == 401


# --------------------------------------------------------------- client_credentials
def test_client_credentials_audiences(client: httpx.Client) -> None:
    token = service_token(client, "svc-synthetic", "payment-api")
    claims = jwt.decode(token, options={"verify_signature": False})
    assert claims["aud"] == ["payment-api"] and claims["roles"] == ["svc.synthetic"] and claims["pkind"] == "SERVICE"

    remediation = jwt.decode(service_token(client, "svc-remediation", "payment-api"), options={"verify_signature": False})
    assert remediation["roles"] == ["svc.remediation"], "roles must be scoped to the requested audience"

    wrong_target = client.post(
        "/v1/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "svc-synthetic",
            "client_secret": secret("svc-synthetic"),
            "audience": "auth-service",
        },
    )
    assert wrong_target.status_code == 400 and wrong_target.json()["error"] == "invalid_target"

    bad_secret = client.post(
        "/v1/oauth/token",
        data={"grant_type": "client_credentials", "client_id": "svc-synthetic", "client_secret": "x" * 40},
    )
    assert bad_secret.status_code == 401 and bad_secret.json()["error"] == "invalid_client"

    humans_rejected = client.post(
        "/v1/oauth/token",
        data={"grant_type": "client_credentials", "client_id": "alice", "client_secret": secret("alice")},
    )
    assert humans_rejected.status_code == 401

    assert client.post("/v1/oauth/token", data={"grant_type": "password"}).json()["error"] == "unsupported_grant_type"
    assert client.post("/v1/oauth/token", json={"grant_type": "client_credentials"}).json()["error"] == "invalid_request"


# ------------------------------------------------------ confinement par la remédiation
def test_remediation_containment_and_guards(client: httpx.Client) -> None:
    remediation = service_token(client, "svc-remediation", "auth-service")
    bob_token = login(client, "bob").json()["access_token"]
    assert client.get("/v1/me", headers=bearer(bob_token)).status_code == 200

    revoked = client.post(
        f"/internal/v1/principals/{PRINCIPAL_IDS['bob']}/revoke-tokens",
        json={"reason": "ANOMALOUS_TRAFFIC", "incident_id": "c7d1b3f4-8a7e-4f3a-9a8e-2d1b0c9e8f7a"},
        headers=bearer(remediation),
    )
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["is_active"] is True
    assert client.get("/v1/me", headers=bearer(bob_token)).status_code == 401

    time.sleep(1.1)  # not_before est arrondi à la seconde suivante
    assert login(client, "bob").status_code == 200, "revocation alone must not lock the user out"

    for target in ("svc-detector", "admin"):
        denied = client.post(
            f"/internal/v1/principals/{PRINCIPAL_IDS[target]}/disable",
            json={"reason": "CREDENTIAL_COMPROMISE"},
            headers=bearer(remediation),
        )
        assert denied.status_code == 403, f"remediation must not disable {target}"

    disabled = client.post(
        f"/internal/v1/principals/{PRINCIPAL_IDS['bob']}/disable",
        json={"reason": "CREDENTIAL_COMPROMISE"},
        headers=bearer(remediation),
    )
    assert disabled.status_code == 200 and disabled.json()["is_active"] is False
    assert login(client, "bob").status_code == 401

    # Réactivation : décision humaine (auth.admin) exclusivement.
    assert (
        client.post(
            f"/internal/v1/principals/{PRINCIPAL_IDS['bob']}/enable",
            json={"reason": "INCIDENT_CLOSED"},
            headers=bearer(remediation),
        ).status_code
        == 403
    )
    admin = login(client, "admin").json()["access_token"]
    enabled = client.post(
        f"/internal/v1/principals/{PRINCIPAL_IDS['bob']}/enable",
        json={"reason": "INCIDENT_CLOSED"},
        headers=bearer(admin),
    )
    assert enabled.status_code == 200 and enabled.json()["is_active"] is True
    time.sleep(1.1)
    assert login(client, "bob").status_code == 200


def test_synthetic_token_cannot_reach_auth_admin(client: httpx.Client) -> None:
    synthetic = service_token(client, "svc-synthetic")
    response = client.post(
        f"/internal/v1/principals/{PRINCIPAL_IDS['bob']}/revoke-tokens",
        json={"reason": "TEST"},
        headers=bearer(synthetic),
    )
    assert response.status_code == 401, "a payment-api audience token is not valid on auth-service"


# --------------------------------------------- passerelle, introspection, administration
def test_gateway_authz_check(client: httpx.Client) -> None:
    noc = login(client, "noc-operator").json()["access_token"]
    allowed = client.get("/internal/v1/authz/check", params={"role": "noc.viewer"}, headers=bearer(noc))
    assert allowed.status_code == 204
    assert allowed.headers["x-auth-sub"] == PRINCIPAL_IDS["noc-operator"]
    alice = login(client, "alice").json()["access_token"]
    assert client.get("/internal/v1/authz/check", params={"role": "noc.viewer"}, headers=bearer(alice)).status_code == 403
    assert client.get("/internal/v1/authz/check", params={"role": "noc.viewer"}).status_code == 401


def test_introspection_requires_resource_server_role(client: httpx.Client) -> None:
    alice = login(client, "alice").json()["access_token"]
    resource_server = service_token(client, "svc-payment-api")
    active = client.post("/v1/tokens/introspect", data={"token": alice}, headers=bearer(resource_server))
    assert active.status_code == 200 and active.json()["active"] is True and active.json()["sub"] == PRINCIPAL_IDS["alice"]
    inactive = client.post("/v1/tokens/introspect", data={"token": "garbage"}, headers=bearer(resource_server))
    assert inactive.json() == {"active": False}
    assert client.post("/v1/tokens/introspect", data={"token": alice}, headers=bearer(alice)).status_code == 403


def test_admin_principal_listing(client: httpx.Client) -> None:
    admin = login(client, "admin").json()["access_token"]
    page = client.get("/v1/admin/principals", params={"limit": 3}, headers=bearer(admin))
    assert page.status_code == 200
    body = page.json()
    assert len(body["items"]) == 3 and body["next_cursor"] == body["items"][-1]["username"]
    assert all("secret_hash" not in item for item in body["items"])
    second = client.get("/v1/admin/principals", params={"limit": 50, "cursor": body["next_cursor"]}, headers=bearer(admin))
    assert {item["username"] for item in second.json()["items"]}.isdisjoint({item["username"] for item in body["items"]})
    alice = login(client, "alice").json()["access_token"]
    assert client.get("/v1/admin/principals", headers=bearer(alice)).status_code == 403


# ------------------------------------- intégration ra_common (vue d'un resource server)
@pytest.mark.asyncio
async def test_resource_server_verification_with_jwks_and_revocation_feed(client: httpx.Client) -> None:
    from ra_common.security import TokenError, TokenVerifier
    from ra_common.security.jwks import JwksKeyResolver
    from ra_common.security.revocation import RevocationFeed
    from ra_common.security.service_token import ServiceTokenClient

    response = login(client, "alice")
    token, cookie = response.json()["access_token"], refresh_cookie(response)
    issuer = jwt.decode(token, options={"verify_signature": False})["iss"]

    async with httpx.AsyncClient(base_url=BASE_URL, timeout=5.0) as http:
        feed = RevocationFeed(
            feed_url=f"{BASE_URL}/internal/v1/revocations",
            token_client=ServiceTokenClient(
                token_url=f"{BASE_URL}/v1/oauth/token",
                client_id="svc-payment-api",
                client_secret=secret("svc-payment-api"),
                audience="auth-service",
                http_client=http,
            ),
            http_client=http,
        )
        verifier = TokenVerifier(
            issuer=issuer,
            audience="payment-api",
            key_resolver=JwksKeyResolver(f"{BASE_URL}/.well-known/jwks.json", http_client=http),
            revocation_checker=feed,
        )
        await feed.sync_once()
        claims = await verifier.verify(token)
        assert claims.sub == PRINCIPAL_IDS["alice"]

        client.post("/v1/auth/logout", headers={**bearer(token), "Cookie": f"ra_refresh={cookie}"})
        await feed.sync_once()
        with pytest.raises(TokenError) as excinfo:
            await verifier.verify(token)
        assert excinfo.value.reason == "revoked"
