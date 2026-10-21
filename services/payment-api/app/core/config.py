"""Configuration 12-factor : exclusivement par variables d'environnement préfixées PAYMENT_."""

from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import Field, SecretStr, ValidationInfo, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

MIN_SECRET_LENGTH = 16
ACCOUNT_NUMBER_PATTERN = r"^RA-[0-9]{4}-[0-9]{4}$"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PAYMENT_", case_sensitive=False, extra="ignore")

    service_name: str = "payment-api"
    version: str = "1.0.0"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    enable_docs: bool = False

    # --- base de données : deux identités distinctes (moindre privilège) -----------
    db_host: str = "mariadb"
    db_port: int = Field(3306, ge=1, le=65535)
    db_name: str = "ra_payment"
    db_user: str = "ra_payment_app"
    db_password: SecretStr
    db_pool_min_size: int = Field(2, ge=1, le=50)
    db_pool_max_size: int = Field(10, ge=1, le=100)
    db_maint_user: str = "ra_payment_maint"
    db_maint_password: SecretStr
    db_maint_pool_max_size: int = Field(3, ge=1, le=5)
    db_connect_timeout_seconds: int = Field(60, ge=1, le=600)

    # --- sécurité -------------------------------------------------------------------
    auth_base_url: str = "http://auth-service:8000"
    auth_issuer: str = Field(min_length=8)
    auth_audience: str = "payment-api"
    client_id: str = "svc-payment-api"
    client_secret: SecretStr
    revocation_poll_seconds: float = Field(5.0, ge=1.0, le=60.0)
    clock_leeway_seconds: int = Field(10, ge=0, le=60)
    stream_ticket_secret: SecretStr
    stream_ticket_ttl_seconds: int = Field(30, ge=5, le=300)

    # --- monitoring synthétique ------------------------------------------------------
    synthetic_principal_id: UUID = UUID("00000000-0000-4000-8000-000000000102")
    synthetic_account_a: str = Field("RA-9000-0001", pattern=ACCOUNT_NUMBER_PATTERN)
    synthetic_account_b: str = Field("RA-9000-0002", pattern=ACCOUNT_NUMBER_PATTERN)

    # --- comportement ---------------------------------------------------------------
    stale_after_seconds: int = Field(300, ge=60, le=86400)
    integrity_cache_seconds: float = Field(5.0, ge=0.0, le=60.0)
    integrity_refresh_per_minute: int = Field(6, ge=1, le=120)
    flags_cache_seconds: float = Field(2.0, ge=0.1, le=60.0)
    chaos_lab_enabled: bool = False

    @field_validator("db_password", "db_maint_password", "client_secret")
    @classmethod
    def _strong_secret(cls, value: SecretStr) -> SecretStr:
        if len(value.get_secret_value()) < MIN_SECRET_LENGTH:
            raise ValueError(f"must contain at least {MIN_SECRET_LENGTH} characters")
        return value

    @field_validator("stream_ticket_secret")
    @classmethod
    def _strong_ticket_secret(cls, value: SecretStr) -> SecretStr:
        if len(value.get_secret_value()) < 32:
            raise ValueError("must contain at least 32 characters")
        return value

    @field_validator("db_pool_max_size")
    @classmethod
    def _pool_bounds(cls, value: int, info: ValidationInfo) -> int:
        if value < info.data.get("db_pool_min_size", 1):
            raise ValueError("db_pool_max_size must be >= db_pool_min_size")
        return value
