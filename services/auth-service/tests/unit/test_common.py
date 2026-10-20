"""Tests de la bibliothèque partagée ra_common (exécutés avec la suite auth-service)."""

from __future__ import annotations

import json
import logging
import time

import httpx
import jwt

from ra_common.health import CheckResult, aggregate, health_response
from ra_common.logging import JsonFormatter, redact
from ra_common.middleware import parse_traceparent, sanitize_identifier
from ra_common.security.jwks import JwksKeyResolver
from ra_common.security.revocation import RevocationFeed
from ra_common.security.service_token import ServiceTokenClient
from ra_common.security.tokens import AccessTokenClaims


def test_redaction_masks_secrets_recursively() -> None:
    data = {"password": "p", "nested": {"client_secret": "s", "Authorization": "Bearer x", "ok": 1}, "list": [{"token": "t"}]}
    assert redact(data) == {
        "password": "[REDACTED]",
        "nested": {"client_secret": "[REDACTED]", "Authorization": "[REDACTED]", "ok": 1},
        "list": [{"token": "[REDACTED]"}],
    }


def test_json_formatter_outputs_single_line_json() -> None:
    record = logging.LogRecord("x", logging.INFO, __file__, 1, "hello %s", ("world",), None)
    record.attributes = {"secret_value": "nope", "amount": 3}
    line = JsonFormatter("svc", "1.0").format(record)
    payload = json.loads(line)
    assert payload["message"] == "hello world" and payload["service"] == "svc"
    assert payload["attributes"] == {"secret_value": "[REDACTED]", "amount": 3}
    assert "\n" not in line


def test_traceparent_and_identifiers() -> None:
    trace = "4bf92f3577b34da6a3ce929d0e0e4736"
    assert parse_traceparent(f"00-{trace}-00f067aa0ba902b7-01") == trace
    assert parse_traceparent("00-" + "0" * 32 + "-00f067aa0ba902b7-01") is None
    assert parse_traceparent("garbage") is None
    assert sanitize_identifier("abc-123") == "abc-123"
    assert sanitize_identifier("bad\nvalue") is None
    assert sanitize_identifier("x" * 200) is None


def test_health_aggregation() -> None:
    assert aggregate({"a": CheckResult("pass"), "b": CheckResult("warn")}) == "warn"
    response = health_response(service="s", version="1", checks={"a": CheckResult("fail")})
    assert response.status_code == 503
    assert response.media_type == "application/health+json"


def _claims(sub: str, jti: str, iat: int) -> AccessTokenClaims:
    return AccessTokenClaims(
        iss="i", sub=sub, aud=["a"], iat=iat, nbf=iat, exp=iat + 300, jti=jti, typ="access", pkind="USER", name="n"
    )


async def test_service_token_client_caches_and_revocation_feed_applies_rules() -> None:
    token_calls = {"count": 0}
    now = int(time.time())

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/oauth/token":
            token_calls["count"] += 1
            return httpx.Response(200, json={"access_token": "svc-token", "token_type": "Bearer", "expires_in": 300})
        assert request.headers["authorization"] == "Bearer svc-token"
        since = int(request.url.params["since"])
        items = [] if since >= 2 else [
            {"seq": 1, "kind": "JTI", "jti": "revoked-jti", "expires_at": "2999-01-01T00:00:00Z"},
            {
                "seq": 2,
                "kind": "PRINCIPAL",
                "principal_id": "bob",
                "not_before": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
                "expires_at": "2999-01-01T00:00:00Z",
            },
        ]
        return httpx.Response(200, json={"cursor": 2, "items": items})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://auth") as client:
        tokens = ServiceTokenClient(
            token_url="http://auth/v1/oauth/token", client_id="svc", client_secret="x" * 32, http_client=client
        )
        feed = RevocationFeed(feed_url="http://auth/internal/v1/revocations", token_client=tokens, http_client=client)
        await feed.sync_once()
        await feed.sync_once()
        assert token_calls["count"] == 1, "service token must be cached"
        assert await feed.is_revoked(_claims("alice", "revoked-jti", now))
        assert await feed.is_revoked(_claims("bob", "other", now - 10))
        assert not await feed.is_revoked(_claims("bob", "other", now))
        assert not await feed.is_revoked(_claims("alice", "fine", now))
        assert feed.seconds_since_sync is not None


async def test_jwks_resolver_loads_rsa_keys(signing_keys) -> None:
    calls = {"count": 0}

    def handler(_: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        return httpx.Response(200, json=signing_keys.jwks())

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        resolver = JwksKeyResolver("http://auth/.well-known/jwks.json", http_client=client)
        key = await resolver.resolve("test-kid")
        assert key is not None and resolver.loaded
        assert await resolver.resolve("unknown") is None
        assert calls["count"] == 1, "unknown kid must not hammer the issuer"
        token = jwt.encode({"a": 1}, signing_keys.private_key, algorithm="RS256")
        assert jwt.decode(token, key, algorithms=["RS256"]) == {"a": 1}
