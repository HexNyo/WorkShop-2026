"""Assemblage prêt à l'emploi pour un resource server (payment-api, remediation-engine).

Valide localement les jetons (JWKS en cache) et applique le flux de révocation
publié par auth-service, avec une identité de service dédiée (svc.resource_server).
"""

from __future__ import annotations

import logging

import httpx

from ra_common.health import CheckResult
from ra_common.security.jwks import JwksKeyResolver
from ra_common.security.revocation import RevocationFeed
from ra_common.security.service_token import ServiceTokenClient
from ra_common.security.verifier import TokenVerifier

logger = logging.getLogger("ra_common.security.resource_server")

REVOCATION_STALE_SECONDS = 30.0


class ResourceServerSecurity:
    def __init__(
        self,
        *,
        auth_base_url: str,
        issuer: str,
        audience: str | list[str],
        client_id: str,
        client_secret: str,
        poll_interval_seconds: float = 5.0,
        leeway_seconds: int = 10,
    ) -> None:
        base = auth_base_url.rstrip("/")
        self.http = httpx.AsyncClient(timeout=5.0)
        self.jwks = JwksKeyResolver(f"{base}/.well-known/jwks.json", http_client=self.http)
        self.feed_client = ServiceTokenClient(
            token_url=f"{base}/v1/oauth/token",
            client_id=client_id,
            client_secret=client_secret,
            audience="auth-service",
            http_client=self.http,
        )
        self.revocations = RevocationFeed(
            feed_url=f"{base}/internal/v1/revocations",
            token_client=self.feed_client,
            http_client=self.http,
            poll_interval_seconds=poll_interval_seconds,
        )
        self.verifier = TokenVerifier(
            issuer=issuer,
            audience=audience,
            key_resolver=self.jwks,
            revocation_checker=self.revocations,
            leeway_seconds=leeway_seconds,
        )

    async def start(self) -> None:
        """Ne bloque jamais le démarrage : un auth-service indisponible rend le service
        non prêt (readiness), sans l'empêcher de démarrer puis de se rétablir seul."""
        try:
            await self.jwks.refresh()
        except (httpx.HTTPError, ValueError) as exc:
            logger.warning("initial JWKS load failed: %s", exc, extra={"event": "jwks.initial_load_failed"})
        await self.revocations.start()

    async def stop(self) -> None:
        await self.revocations.stop()
        await self.http.aclose()

    def health_checks(self) -> dict[str, CheckResult]:
        checks = {
            "auth:jwks": CheckResult("pass", round(self.jwks.age_seconds or 0, 1), "s_since_refresh")
            if self.jwks.loaded
            else CheckResult("fail", output="signing keys not loaded"),
        }
        age = self.revocations.seconds_since_sync
        if age is None:
            checks["auth:revocation-feed"] = CheckResult("fail", output="never synchronised")
        else:
            status = "pass" if age <= REVOCATION_STALE_SECONDS else "fail"
            checks["auth:revocation-feed"] = CheckResult(status, round(age, 1), "s_since_sync")
        return checks
