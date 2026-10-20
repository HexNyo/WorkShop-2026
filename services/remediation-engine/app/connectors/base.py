"""Socle des connecteurs : contexte d'étape, erreurs, appels HTTP avec reprise."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

import httpx
from ra_common.context import outgoing_headers
from ra_common.security.service_token import ServiceTokenClient, ServiceTokenError

from app.domain.models import Incident


class ActionError(Exception):
    """Échec d'une action. `fatal` : inutile de retenter (ex. grand livre compromis)."""

    def __init__(self, message: str, *, fatal: bool = False, output: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.fatal = fatal
        self.output = output


@dataclass(frozen=True, slots=True)
class StepContext:
    incident: Incident
    playbook_code: str
    seq: int
    phase: str

    @property
    def reason(self) -> str:
        return f"{self.playbook_code} {self.phase.lower()} step {self.seq}"


_RETRYABLE_STATUS = {502, 503, 504}


async def call(
    http: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    tokens: ServiceTokenClient | None = None,
    json: Any = None,
    params: dict[str, Any] | None = None,
    correlation_id: str | None = None,
    attempts: int = 3,
    timeout: float = 10.0,
    extra_headers: dict[str, str] | None = None,
) -> httpx.Response:
    """Appel sortant avec propagation de la corrélation et reprise sur erreur transitoire."""
    last_error: Exception | None = None
    for attempt in range(attempts):
        headers = {**outgoing_headers(), **(extra_headers or {})}
        if correlation_id:
            headers["X-Correlation-ID"] = correlation_id
        try:
            if tokens is not None:
                headers.update(await tokens.authorization_header())
            response = await http.request(method, url, json=json, params=params, headers=headers, timeout=timeout)
        except (httpx.TransportError, ServiceTokenError) as exc:
            last_error = exc
        else:
            if response.status_code == 401 and tokens is not None and attempt + 1 < attempts:
                tokens.invalidate()
                continue
            if response.status_code not in _RETRYABLE_STATUS or attempt + 1 == attempts:
                return response
            last_error = httpx.HTTPStatusError(f"HTTP {response.status_code}", request=response.request, response=response)
        await asyncio.sleep(0.5 * (2**attempt))
    raise ActionError(f"{method} {url} failed: {last_error.__class__.__name__}: {last_error}")


def expect(response: httpx.Response, *statuses: int) -> dict[str, Any]:
    body: dict[str, Any] = {}
    if response.content:
        try:
            parsed = response.json()
            body = parsed if isinstance(parsed, dict) else {"body": parsed}
        except ValueError:
            body = {"body": response.text[:500]}
    if response.status_code not in statuses:
        code = body.get("code") or body.get("error") or f"HTTP_{response.status_code}"
        raise ActionError(
            f"{response.request.method} {response.request.url.path} -> {response.status_code} {code}: "
            f"{body.get('detail') or body.get('error_description') or ''}".strip(),
            output={"status": response.status_code, "code": code},
        )
    return body
