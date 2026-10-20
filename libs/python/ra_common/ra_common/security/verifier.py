"""Vérification cryptographique et sémantique des jetons d'accès (RS256)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol

import jwt
from pydantic import ValidationError

from ra_common.security.tokens import AccessTokenClaims

ALGORITHM = "RS256"
_REQUIRED_CLAIMS = ["exp", "iat", "nbf", "iss", "aud", "sub", "jti"]


class TokenError(Exception):
    """Jeton refusé ; `reason` est un code court, sûr à journaliser et à exposer."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class KeyResolver(Protocol):
    async def resolve(self, kid: str) -> Any | None: ...


class RevocationChecker(Protocol):
    async def is_revoked(self, claims: AccessTokenClaims) -> bool: ...


class StaticKeyResolver:
    """Clés publiques connues localement (utilisé par l'émetteur lui-même)."""

    def __init__(self, keys: Mapping[str, Any]) -> None:
        self._keys = dict(keys)

    async def resolve(self, kid: str) -> Any | None:
        return self._keys.get(kid)


class TokenVerifier:
    def __init__(
        self,
        *,
        issuer: str,
        audience: str | list[str] | None,
        key_resolver: KeyResolver,
        revocation_checker: RevocationChecker,
        leeway_seconds: int = 10,
    ) -> None:
        self._issuer = issuer
        self._audience = audience
        self._keys = key_resolver
        self._revocations = revocation_checker
        self._leeway = leeway_seconds

    async def verify(self, token: str) -> AccessTokenClaims:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise TokenError("malformed") from exc
        if header.get("alg") != ALGORITHM:
            raise TokenError("unsupported_algorithm")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise TokenError("missing_kid")
        key = await self._keys.resolve(kid)
        if key is None:
            raise TokenError("unknown_key")

        options: dict[str, Any] = {"require": _REQUIRED_CLAIMS}
        if self._audience is None:
            options["verify_aud"] = False
        try:
            payload = jwt.decode(
                token,
                key,
                algorithms=[ALGORITHM],
                audience=self._audience,
                issuer=self._issuer,
                leeway=self._leeway,
                options=options,
            )
        except jwt.ExpiredSignatureError as exc:
            raise TokenError("expired") from exc
        except jwt.ImmatureSignatureError as exc:
            raise TokenError("not_yet_valid") from exc
        except jwt.InvalidAudienceError as exc:
            raise TokenError("wrong_audience") from exc
        except jwt.InvalidIssuerError as exc:
            raise TokenError("wrong_issuer") from exc
        except jwt.PyJWTError as exc:
            raise TokenError("invalid") from exc

        try:
            claims = AccessTokenClaims.model_validate(payload)
        except ValidationError as exc:
            raise TokenError("invalid_claims") from exc

        if await self._revocations.is_revoked(claims):
            raise TokenError("revoked")
        return claims
