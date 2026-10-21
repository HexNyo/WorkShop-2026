"""DTO d'entrée/sortie de l'API (validation stricte, aucun champ inconnu accepté)."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

import base64

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from app.core.config import MIN_SECRET_LENGTH
from app.domain.models import Principal

REASON_PATTERN = r"^[A-Z][A-Z_]{2,63}$"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


# --- entrées ---------------------------------------------------------------------
class LoginRequest(StrictModel):
    username: str = Field(min_length=3, max_length=64)
    password: SecretStr = Field(min_length=1, max_length=256)


MAX_IMAGE_BASE64 = 1_000_000  # ≈ 730 Ko de JPEG ; une capture 640x480 en fait ~60


class FaceImage(StrictModel):
    """Capture webcam en base64 (sans préfixe data:)."""

    image: bytes

    @field_validator("image", mode="before")
    @classmethod
    def _decode(cls, value: object) -> bytes:
        if not isinstance(value, str) or not 0 < len(value) <= MAX_IMAGE_BASE64:
            raise ValueError("base64-encoded JPEG expected")
        return base64.b64decode(value, validate=True)


class FaceLoginRequest(FaceImage):
    username: str = Field(min_length=3, max_length=64)


class PasswordStepRequest(StrictModel):
    pre_auth_token: str = Field(min_length=32, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    password: SecretStr = Field(min_length=1, max_length=256)


class RevokeRequest(StrictModel):
    jti: UUID | None = None
    reason: str = Field("USER_REQUEST", pattern=REASON_PATTERN)


class ContainmentRequest(StrictModel):
    reason: str = Field(pattern=REASON_PATTERN)
    incident_id: UUID | None = None


class EnableRequest(StrictModel):
    reason: str = Field(pattern=REASON_PATTERN)


USERNAME_PATTERN = r"^[a-z0-9][a-z0-9._-]{2,63}$"


class CreateUserRequest(StrictModel):
    username: str = Field(pattern=USERNAME_PATTERN)
    display_name: str = Field(min_length=1, max_length=128)
    password: SecretStr = Field(min_length=MIN_SECRET_LENGTH, max_length=256)


class PasswordResetRequest(StrictModel):
    password: SecretStr = Field(min_length=MIN_SECRET_LENGTH, max_length=256)


class PasswordChangeRequest(StrictModel):
    current_password: SecretStr = Field(min_length=1, max_length=256)
    new_password: SecretStr = Field(min_length=MIN_SECRET_LENGTH, max_length=256)


# --- sorties ---------------------------------------------------------------------
class PrincipalView(BaseModel):
    id: UUID
    username: str
    display_name: str
    kind: Literal["USER", "SERVICE"]
    roles: list[str]

    @classmethod
    def of(cls, principal: Principal) -> PrincipalView:
        return cls(
            id=principal.id,
            username=principal.username,
            display_name=principal.display_name,
            kind=principal.kind.value,
            roles=list(principal.roles),
        )


class TokenResponse(BaseModel):
    access_token: str
    token_type: Literal["Bearer"] = "Bearer"
    expires_in: int
    principal: PrincipalView


class PreAuthResponse(BaseModel):
    pre_auth_token: str
    expires_in: int


class MeResponse(PrincipalView):
    token_expires_at: datetime


class OAuthTokenResponse(BaseModel):
    access_token: str
    token_type: Literal["Bearer"] = "Bearer"
    expires_in: int
    scope: str


class IntrospectionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    active: bool
    sub: str | None = None
    aud: list[str] | None = None
    roles: list[str] | None = None
    exp: int | None = None
    iat: int | None = None
    jti: str | None = None
    pkind: str | None = None


class RevocationItem(BaseModel):
    seq: int
    kind: Literal["JTI", "PRINCIPAL"]
    jti: UUID | None = None
    principal_id: UUID | None = None
    not_before: datetime | None = None
    expires_at: datetime


class RevocationFeedResponse(BaseModel):
    cursor: int
    items: list[RevocationItem]


class ContainmentResponse(BaseModel):
    principal_id: UUID
    is_active: bool
    tokens_valid_after: datetime
    refresh_tokens_revoked: int


class PrincipalAdminView(PrincipalView):
    is_active: bool
    locked_until: datetime | None
    last_login_at: datetime | None
    created_at: datetime
    face_enrolled: bool
    face_blocked_seconds: int

    @classmethod
    def of(cls, principal: Principal, face_blocked_seconds: int = 0) -> PrincipalAdminView:
        return cls(
            **PrincipalView.of(principal).model_dump(),
            is_active=principal.is_active,
            locked_until=principal.locked_until,
            last_login_at=principal.last_login_at,
            created_at=principal.created_at,
            face_enrolled=principal.face_enrolled,
            face_blocked_seconds=face_blocked_seconds,
        )


class PrincipalPage(BaseModel):
    items: list[PrincipalAdminView]
    next_cursor: str | None
