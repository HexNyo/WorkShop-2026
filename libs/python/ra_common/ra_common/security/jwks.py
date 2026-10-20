"""Résolution des clés publiques de l'émetteur via son endpoint JWKS (avec cache)."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import httpx
import jwt

logger = logging.getLogger("ra_common.security.jwks")


class JwksKeyResolver:
    def __init__(
        self,
        jwks_url: str,
        *,
        http_client: httpx.AsyncClient,
        refresh_interval_seconds: int = 600,
        min_refetch_interval_seconds: int = 30,
    ) -> None:
        self._url = jwks_url
        self._http = http_client
        self._refresh_interval = refresh_interval_seconds
        self._min_refetch = min_refetch_interval_seconds
        self._keys: dict[str, Any] = {}
        self._fetched_at: float | None = None
        self._attempted_at: float = 0.0
        self._lock = asyncio.Lock()

    @property
    def loaded(self) -> bool:
        return bool(self._keys)

    @property
    def age_seconds(self) -> float | None:
        return None if self._fetched_at is None else time.monotonic() - self._fetched_at

    async def resolve(self, kid: str) -> Any | None:
        stale = self._fetched_at is None or time.monotonic() - self._fetched_at > self._refresh_interval
        if stale or kid not in self._keys:
            await self._refresh_if_allowed()
        return self._keys.get(kid)

    async def refresh(self) -> None:
        async with self._lock:
            await self._fetch()

    async def _refresh_if_allowed(self) -> None:
        async with self._lock:
            # Anti-martèlement : un `kid` inconnu ne déclenche pas plus d'un appel par fenêtre.
            if time.monotonic() - self._attempted_at < self._min_refetch and self._keys:
                return
            try:
                await self._fetch()
            except (httpx.HTTPError, ValueError) as exc:
                logger.warning("JWKS refresh failed: %s", exc, extra={"event": "jwks.refresh_failed"})

    async def _fetch(self) -> None:
        self._attempted_at = time.monotonic()
        response = await self._http.get(self._url, timeout=3.0)
        response.raise_for_status()
        document = response.json()
        keys: dict[str, Any] = {}
        for entry in document.get("keys", []):
            if entry.get("kty") != "RSA" or entry.get("use", "sig") != "sig" or entry.get("alg", "RS256") != "RS256":
                continue
            kid = entry.get("kid")
            if not kid:
                continue
            keys[kid] = jwt.PyJWK(entry, algorithm="RS256").key
        if not keys:
            raise ValueError("JWKS document contains no usable RS256 signing key")
        self._keys = keys
        self._fetched_at = time.monotonic()
        logger.info("JWKS refreshed (%d key(s))", len(keys), extra={"event": "jwks.refreshed"})
