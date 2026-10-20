"""Erreurs du domaine, traduites en réponses HTTP par la couche API."""

from __future__ import annotations


class DomainError(Exception):
    """Racine des erreurs métier de l'auth-service."""


class InvalidCredentials(DomainError):
    pass


class AccountLocked(DomainError):
    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__("account temporarily locked")
        self.retry_after_seconds = max(retry_after_seconds, 1)


class FaceRejected(DomainError):
    """Visage non reconnu (ou compte inéligible), ou identifiant temporairement bloqué."""

    def __init__(self, retry_after_seconds: int, *, locked: bool) -> None:
        super().__init__("face not recognized")
        self.retry_after_seconds = max(retry_after_seconds, 1)
        self.locked = locked


class NoUsableFace(DomainError):
    pass


class PreAuthInvalid(DomainError):
    pass


class RefreshTokenInvalid(DomainError):
    pass


class RefreshTokenReused(DomainError):
    pass


class PrincipalNotFound(DomainError):
    pass


class PolicyViolation(DomainError):
    pass


class InvalidState(DomainError):
    pass


class OAuthError(DomainError):
    """Erreur du endpoint token, au format RFC 6749 § 5.2."""

    def __init__(self, error: str, description: str, status: int = 400) -> None:
        super().__init__(description)
        self.error = error
        self.description = description
        self.status = status
