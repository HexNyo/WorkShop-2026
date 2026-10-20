"""Client OAuth2 `client_credentials` avec cache du jeton de service."""

from __future__ import annotations

import asyncio
import time

import httpx


class ServiceTokenError(Exception):
    pass


class ServiceTokenClient:
    def __init__(
        self,
        *,
        token_url: str,
        client_id: str,
        client_secret: str,
        http_client: httpx.AsyncClient,
        audience: str | None = None,
        refresh_margin_seconds: int = 30,
    ) -> None:
        if len(client_secret) < 16:
            raise ValueError("client_secret must contain at least 16 characters")
        self._url = token_url
        self._client_id = client_id
        self._secret = client_secret
        self._audience = audience
        self._http = http_client
        self._margin = refresh_margin_seconds
        self._token: str | None = None
        self._expires_at = 0.0
        self._lock = asyncio.Lock()

    async def get_token(self) -> str:
        if self._token and time.monotonic() < self._expires_at - self._margin:
            return self._token
        async with self._lock:
            if self._token and time.monotonic() < self._expires_at - self._margin:
                return self._token
            form = {"grant_type": "client_credentials", "client_id": self._client_id, "client_secret": self._secret}
            if self._audience:
                form["audience"] = self._audience
            try:
                response = await self._http.post(self._url, data=form, timeout=5.0)
            except httpx.HTTPError as exc:
                raise ServiceTokenError(f"token endpoint unreachable: {exc.__class__.__name__}") from exc
            if response.status_code != 200:
                error = response.json().get("error", "unknown") if response.content else "unknown"
                raise ServiceTokenError(f"token request rejected ({response.status_code}, {error})")
            body = response.json()
            self._token = body["access_token"]
            self._expires_at = time.monotonic() + int(body["expires_in"])
            return self._token

    def invalidate(self) -> None:
        self._token = None
        self._expires_at = 0.0

    async def authorization_header(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {await self.get_token()}"}
