"""Synchronisation du flux de révocation publié par auth-service.

Règle appliquée : un jeton est révoqué si son `jti` figure dans le flux, ou si
son `iat` est antérieur au `not_before` publié pour son principal.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from datetime import UTC, datetime

import httpx

from ra_common.security.service_token import ServiceTokenClient, ServiceTokenError
from ra_common.security.tokens import AccessTokenClaims

logger = logging.getLogger("ra_common.security.revocation")


def _epoch(value: str) -> float:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC).timestamp()


class RevocationFeed:
    def __init__(
        self,
        *,
        feed_url: str,
        token_client: ServiceTokenClient,
        http_client: httpx.AsyncClient,
        poll_interval_seconds: float = 5.0,
        page_limit: int = 500,
    ) -> None:
        self._url = feed_url
        self._tokens = token_client
        self._http = http_client
        self._interval = poll_interval_seconds
        self._limit = page_limit
        self._cursor = 0
        self._jtis: dict[str, float] = {}
        self._principals: dict[str, tuple[float, float]] = {}
        self._synced_at: float | None = None
        self._task: asyncio.Task[None] | None = None

    # --- RevocationChecker ----------------------------------------------------
    async def is_revoked(self, claims: AccessTokenClaims) -> bool:
        return self.is_revoked_ids(jti=claims.jti, sub=claims.sub, iat=claims.iat)

    def is_revoked_ids(self, *, jti: str, sub: str, iat: int) -> bool:
        if jti in self._jtis:
            return True
        entry = self._principals.get(sub)
        return entry is not None and iat < entry[0]

    # --- état ---------------------------------------------------------------
    @property
    def seconds_since_sync(self) -> float | None:
        return None if self._synced_at is None else time.monotonic() - self._synced_at

    # --- cycle de vie ----------------------------------------------------------
    async def start(self) -> None:
        with contextlib.suppress(httpx.HTTPError, ServiceTokenError, ValueError):
            await self.sync_once()
        self._task = asyncio.create_task(self._run(), name="revocation-feed")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task

    async def _run(self) -> None:
        while True:
            await asyncio.sleep(self._interval)
            try:
                await self.sync_once()
            except (httpx.HTTPError, ServiceTokenError, ValueError, KeyError) as exc:
                logger.warning("revocation feed sync failed: %s", exc, extra={"event": "revocation.sync_failed"})

    async def sync_once(self) -> None:
        while True:
            headers = await self._tokens.authorization_header()
            response = await self._http.get(
                self._url, params={"since": self._cursor, "limit": self._limit}, headers=headers, timeout=3.0
            )
            if response.status_code == 401:
                self._tokens.invalidate()
            response.raise_for_status()
            body = response.json()
            items = body["items"]
            for item in items:
                expires = _epoch(item["expires_at"])
                if item["kind"] == "JTI":
                    self._jtis[item["jti"]] = expires
                else:
                    not_before = _epoch(item["not_before"])
                    current = self._principals.get(item["principal_id"])
                    if current is None or not_before > current[0]:
                        self._principals[item["principal_id"]] = (not_before, expires)
            self._cursor = int(body["cursor"])
            if len(items) < self._limit:
                break
        self._purge()
        self._synced_at = time.monotonic()

    def _purge(self) -> None:
        now = time.time()
        self._jtis = {jti: exp for jti, exp in self._jtis.items() if exp > now}
        self._principals = {sub: entry for sub, entry in self._principals.items() if entry[1] > now}
