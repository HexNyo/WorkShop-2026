"""Entités du domaine d'authentification (indépendantes du transport et de la base)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from uuid import UUID


class PrincipalKind(StrEnum):
    USER = "USER"
    SERVICE = "SERVICE"


@dataclass(frozen=True, slots=True)
class Principal:
    id: UUID
    kind: PrincipalKind
    username: str
    display_name: str
    secret_hash: str
    is_active: bool
    failed_login_count: int
    locked_until: datetime | None
    tokens_valid_after: datetime
    last_login_at: datetime | None
    created_at: datetime
    roles: tuple[str, ...]
    is_privileged: bool
    face_enrolled: bool = False

    @property
    def has_secret(self) -> bool:
        return self.secret_hash != "!"

    def is_locked(self, now: datetime) -> bool:
        return self.locked_until is not None and self.locked_until > now


@dataclass(frozen=True, slots=True)
class RefreshToken:
    id: UUID
    family_id: UUID
    principal_id: UUID
    issued_at: datetime
    expires_at: datetime
    used_at: datetime | None
    revoked_at: datetime | None


@dataclass(frozen=True, slots=True)
class IssuedAccessToken:
    token: str
    jti: UUID
    issued_at: int
    expires_at: int
    audiences: tuple[str, ...]
    roles: tuple[str, ...]

    @property
    def expires_in(self) -> int:
        return self.expires_at - self.issued_at


@dataclass(frozen=True, slots=True)
class LoginResult:
    access: IssuedAccessToken
    refresh_token: str
    refresh_expires_at: datetime
    principal: Principal


@dataclass(frozen=True, slots=True)
class ContainmentResult:
    principal_id: UUID
    is_active: bool
    tokens_valid_after: datetime
    refresh_tokens_revoked: int


@dataclass(frozen=True, slots=True)
class RevocationEntry:
    seq: int
    kind: str
    jti: UUID | None
    principal_id: UUID | None
    not_before: datetime | None
    expires_at: datetime
