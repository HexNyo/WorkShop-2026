"""Vérification des jetons d'accès et contrôle d'accès par rôles."""

from ra_common.security.rbac import authenticate, require_roles
from ra_common.security.tokens import AccessTokenClaims
from ra_common.security.verifier import KeyResolver, RevocationChecker, StaticKeyResolver, TokenError, TokenVerifier

__all__ = [
    "AccessTokenClaims",
    "KeyResolver",
    "RevocationChecker",
    "StaticKeyResolver",
    "TokenError",
    "TokenVerifier",
    "authenticate",
    "require_roles",
]
