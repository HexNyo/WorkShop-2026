"""Modèle des claims d'un jeton d'accès RESILIENCE-ALPHA."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class AccessTokenClaims(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore")

    iss: str
    sub: str
    aud: tuple[str, ...]
    iat: int
    nbf: int
    exp: int
    jti: str
    typ: Literal["access"]
    pkind: Literal["USER", "SERVICE"]
    name: str
    roles: tuple[str, ...] = Field(default_factory=tuple)

    @field_validator("aud", mode="before")
    @classmethod
    def _normalize_audience(cls, value: object) -> object:
        return (value,) if isinstance(value, str) else value

    @field_validator("iat", "nbf", "exp", mode="before")
    @classmethod
    def _integer_dates(cls, value: object) -> object:
        return int(value) if isinstance(value, float) else value

    def has_any_role(self, *roles: str) -> bool:
        return any(role in self.roles for role in roles)
