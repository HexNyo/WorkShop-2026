"""Émission des jetons d'accès et vérification de révocation côté émetteur."""

from __future__ import annotations

import time
from collections.abc import Sequence
from uuid import uuid4

import jwt

from app.core.db import Database
from app.core.keys import SigningKeys
from app.domain.models import IssuedAccessToken, Principal
from app.repositories.revocations import RevocationRepository
from ra_common.security.tokens import AccessTokenClaims


class TokenService:
    def __init__(self, *, keys: SigningKeys, issuer: str, access_ttl_seconds: int) -> None:
        self._keys = keys
        self._issuer = issuer
        self._ttl = access_ttl_seconds

    @property
    def access_ttl_seconds(self) -> int:
        return self._ttl

    def issue(self, principal: Principal, *, audiences: Sequence[str], roles: Sequence[str]) -> IssuedAccessToken:
        if not audiences:
            raise ValueError("at least one audience is required")
        now = int(time.time())
        jti = uuid4()
        payload = {
            "iss": self._issuer,
            "sub": str(principal.id),
            "aud": list(audiences),
            "iat": now,
            "nbf": now,
            "exp": now + self._ttl,
            "jti": str(jti),
            "typ": "access",
            "pkind": principal.kind.value,
            "name": principal.display_name,
            "roles": list(roles),
        }
        token = jwt.encode(payload, self._keys.private_key, algorithm="RS256", headers={"kid": self._keys.kid, "typ": "JWT"})
        return IssuedAccessToken(
            token=token,
            jti=jti,
            issued_at=now,
            expires_at=now + self._ttl,
            audiences=tuple(audiences),
            roles=tuple(roles),
        )


class DatabaseRevocationChecker:
    """L'émetteur consulte directement sa base (pas de latence de propagation)."""

    def __init__(self, db: Database, revocations: RevocationRepository) -> None:
        self._db = db
        self._revocations = revocations

    async def is_revoked(self, claims: AccessTokenClaims) -> bool:
        async with self._db.connection() as conn:
            return await self._revocations.is_revoked(
                conn, jti=claims.jti, principal_id=claims.sub, issued_at=claims.iat
            )
