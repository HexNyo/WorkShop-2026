"""Dépendances FastAPI : authentification Bearer et contrôle d'accès par rôles.

Le service doit exposer `app.state.token_verifier` (instance de TokenVerifier).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import Depends, Request

from ra_common.context import principal_id_var
from ra_common.metrics import AUTH_REJECTIONS
from ra_common.problem import forbidden, unauthenticated
from ra_common.security.tokens import AccessTokenClaims
from ra_common.security.verifier import TokenError, TokenVerifier

_MESSAGES = {
    "expired": "The access token has expired",
    "revoked": "The access token has been revoked",
    "wrong_audience": "The access token is not intended for this service",
}


def extract_bearer(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


async def authenticate(request: Request) -> AccessTokenClaims:
    token = extract_bearer(request)
    if token is None:
        AUTH_REJECTIONS.labels(reason="missing_token").inc()
        raise unauthenticated("A bearer token is required")
    verifier: TokenVerifier = request.app.state.token_verifier
    try:
        claims = await verifier.verify(token)
    except TokenError as exc:
        AUTH_REJECTIONS.labels(reason=exc.reason).inc()
        raise unauthenticated(_MESSAGES.get(exc.reason, "The access token is invalid")) from exc
    principal_id_var.set(claims.sub)
    request.state.claims = claims
    return claims


def require_roles(*roles: str) -> Callable[..., Awaitable[AccessTokenClaims]]:
    """Exige au moins un des rôles listés (aucun rôle listé = authentification seule)."""

    async def dependency(claims: AccessTokenClaims = Depends(authenticate)) -> AccessTokenClaims:
        if roles and not claims.has_any_role(*roles):
            AUTH_REJECTIONS.labels(reason="forbidden").inc()
            raise forbidden()
        return claims

    return dependency
