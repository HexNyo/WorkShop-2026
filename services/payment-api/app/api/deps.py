"""Dépendances des routes : conteneur, appelant authentifié + quota, pagination."""

from __future__ import annotations

import base64
import binascii
from collections.abc import Awaitable, Callable
from datetime import datetime
from uuid import UUID

from fastapi import Depends, Request
from ra_common.security import AccessTokenClaims, require_roles

from app.container import Container
from app.domain.errors import MalformedRequest, RateLimited
from app.domain.models import Caller
from app.services.rate_limit import SlidingWindowLimiter


def get_container(request: Request) -> Container:
    return request.app.state.container


def caller(*roles: str) -> Callable[..., Awaitable[Caller]]:
    """Authentifie, contrôle les rôles puis applique le quota dynamique par principal.

    Les comptes de service (sondes synthétiques, remédiation) sont exemptés du quota :
    un bridage anti-abus ne doit jamais empêcher la vérification de la reprise."""

    async def dependency(
        request: Request, claims: AccessTokenClaims = Depends(require_roles(*roles))
    ) -> Caller:
        current = Caller.from_claims(claims)
        if not current.is_service:
            container: Container = request.app.state.container
            limit = (await container.flags.get()).max_requests_per_minute_per_principal
            delay = container.rate_limiter.check(claims.sub, limit)
            if delay is not None:
                raise RateLimited(SlidingWindowLimiter.retry_after(delay))
        return current

    return dependency


# ------------------------------------------------------------------ curseurs
def encode_time_cursor(created_at: datetime, identifier: UUID) -> str:
    return base64.urlsafe_b64encode(f"{created_at.isoformat()}|{identifier}".encode()).decode().rstrip("=")


def decode_time_cursor(cursor: str | None) -> tuple[datetime, UUID] | None:
    if not cursor:
        return None
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode()
        timestamp, identifier = raw.split("|", 1)
        return datetime.fromisoformat(timestamp), UUID(identifier)
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise MalformedRequest("Invalid pagination cursor") from exc


def decode_seq_cursor(cursor: str | None) -> int | None:
    if not cursor:
        return None
    if not cursor.isdigit():
        raise MalformedRequest("Invalid pagination cursor")
    return int(cursor)
