"""Configuration 12-factor : exclusivement par variables d'environnement préfixées REMEDIATION_."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

MIN_SECRET_LENGTH = 16
ACCOUNT_NUMBER_PATTERN = r"^RA-[0-9]{4}-[0-9]{4}$"


def _parse_mapping(raw: str) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for entry in filter(None, (item.strip() for item in raw.split(","))):
        name, separator, url = entry.partition("=")
        if not separator or not name or not url.startswith(("http://", "https://")):
            raise ValueError(f"invalid entry '{entry}' (expected name=http://host:port/path)")
        mapping[name.strip()] = url.strip()
    return mapping


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="REMEDIATION_", case_sensitive=False, extra="ignore")

    service_name: str = "remediation-engine"
    version: str = "1.0.0"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    enable_docs: bool = False

    # --- deux listeners, chacun lié à l'adresse d'un seul réseau ----------------------
    control_bind_host: str = "127.0.0.1"
    control_port: int = Field(8001, ge=1, le=65535)
    supervision_bind_host: str = "127.0.0.1"
    supervision_port: int = Field(8002, ge=1, le=65535)

    # --- base de données ---------------------------------------------------------------
    db_host: str = "postgres"
    db_port: int = Field(5432, ge=1, le=65535)
    db_name: str = "resilience"
    db_user: str = "remediation_app"
    db_password: SecretStr
    db_pool_max_size: int = Field(10, ge=2, le=50)
    db_connect_timeout_seconds: int = Field(60, ge=1, le=600)

    # --- identités et services amont --------------------------------------------------
    auth_base_url: str = "http://auth-service:8000"
    auth_issuer: str = Field(min_length=8)
    client_id: str = "svc-remediation"
    client_secret: SecretStr
    synthetic_client_id: str = "svc-synthetic"
    synthetic_client_secret: SecretStr
    payment_base_url: str = "http://payment-api:8000"
    docker_proxy_url: str = "http://socket-proxy:2375"
    restartable_services: str = "auth-service,payment-api"
    monitored_services: str = (
        "auth-service=http://auth-service:8000/health/readiness,"
        "payment-api=http://payment-api:8000/health/readiness"
    )
    revocation_poll_seconds: float = Field(5.0, ge=1.0, le=60.0)
    clock_leeway_seconds: int = Field(10, ge=0, le=60)

    # --- webhook ------------------------------------------------------------------------
    webhook_hmac_secret: SecretStr
    webhook_tolerance_seconds: int = Field(300, ge=30, le=900)
    webhook_rate_per_minute: int = Field(120, ge=1, le=10_000)
    webhook_max_bytes: int = Field(65536, ge=1024, le=1_048_576)
    stream_ticket_secret: SecretStr

    # --- politique de remédiation ----------------------------------------------------------
    min_confidence: float = Field(0.60, ge=0.0, le=1.0)
    max_per_target_per_hour: int = Field(5, ge=1, le=100)
    restored_hold_seconds: int = Field(300, ge=0, le=3600)
    workers: int = Field(4, ge=1, le=32)
    chaos_lab_enabled: bool = False

    # --- surveillance -------------------------------------------------------------------------
    health_poll_seconds: float = Field(5.0, ge=1.0, le=60.0)
    health_timeout_seconds: float = Field(2.0, ge=0.5, le=10.0)
    health_retention_hours: int = Field(24, ge=1, le=720)
    scheduled_stm_seconds: int = Field(60, ge=0, le=3600)
    watchdog_enabled: bool = True
    watchdog_down_polls: int = Field(3, ge=1, le=60)

    # --- transaction synthétique ---------------------------------------------------------
    synthetic_account_a: str = Field("RA-9000-0001", pattern=ACCOUNT_NUMBER_PATTERN)
    synthetic_account_b: str = Field("RA-9000-0002", pattern=ACCOUNT_NUMBER_PATTERN)
    stm_amount: str = Field("0.01", pattern=r"^[0-9]+\.[0-9]{2}$")
    stm_currency: str = Field("EUR", pattern=r"^[A-Z]{3}$")
    stm_stability_samples: int = Field(3, ge=1, le=10)
    stm_stability_interval_seconds: float = Field(5.0, ge=0.1, le=30.0)

    @field_validator("db_password", "client_secret", "synthetic_client_secret")
    @classmethod
    def _strong_secret(cls, value: SecretStr) -> SecretStr:
        if len(value.get_secret_value()) < MIN_SECRET_LENGTH:
            raise ValueError(f"must contain at least {MIN_SECRET_LENGTH} characters")
        return value

    @field_validator("webhook_hmac_secret", "stream_ticket_secret")
    @classmethod
    def _strong_key(cls, value: SecretStr) -> SecretStr:
        if len(value.get_secret_value()) < 32:
            raise ValueError("must contain at least 32 characters")
        return value

    @field_validator("monitored_services")
    @classmethod
    def _valid_mapping(cls, value: str) -> str:
        _parse_mapping(value)
        return value

    @property
    def monitored(self) -> dict[str, str]:
        return _parse_mapping(self.monitored_services)

    @property
    def restartable(self) -> frozenset[str]:
        return frozenset(filter(None, (item.strip() for item in self.restartable_services.split(","))))
