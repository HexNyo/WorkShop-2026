"""Configuration 12-factor : exclusivement par variables d'environnement préfixées AUTH_."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

MIN_SECRET_LENGTH = 16


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AUTH_", case_sensitive=False, extra="ignore")

    service_name: str = "auth-service"
    version: str = "1.0.0"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    enable_docs: bool = False

    # --- base de données ---------------------------------------------------------
    db_host: str = "postgres"
    db_port: int = Field(5432, ge=1, le=65535)
    db_name: str = "resilience"
    db_user: str = "auth_app"
    db_password: SecretStr
    db_pool_min_size: int = Field(2, ge=1, le=50)
    db_pool_max_size: int = Field(10, ge=1, le=100)
    db_connect_timeout_seconds: int = Field(60, ge=1, le=600)

    # --- jetons -----------------------------------------------------------------------
    issuer: str = Field(min_length=8)
    jwt_private_key_pem_b64: SecretStr
    jwt_key_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")
    # Clés publiques antérieures (rotation) : "kid:base64(PEM)" séparés par des virgules.
    jwt_previous_public_keys: str = ""
    access_token_ttl_seconds: int = Field(300, ge=60, le=900)
    refresh_token_ttl_seconds: int = Field(28800, ge=900, le=86400)
    clock_leeway_seconds: int = Field(10, ge=0, le=60)

    # --- cookie de rafraîchissement ----------------------------------------------------
    refresh_cookie_name: str = Field("ra_refresh", pattern=r"^[A-Za-z0-9_-]{1,64}$")
    refresh_cookie_path: str = Field("/api/auth/v1/auth", pattern=r"^/[A-Za-z0-9/_-]*$")
    cookie_secure: bool = True
    csrf_header_value: str = "ra-dashboard"

    # --- politique de connexion ------------------------------------------------------
    max_failed_logins: int = Field(5, ge=3, le=20)
    lockout_seconds: int = Field(900, ge=60, le=86400)
    password_hash_concurrency: int = Field(4, ge=1, le=32)

    # --- étape faciale + LED ESP8266 ---------------------------------------------------
    # Seuil cosinus SFace (référence OpenCV 0.363) : à recalibrer selon la webcam et l'éclairage.
    face_match_threshold: float = Field(0.363, ge=0.0, le=1.0)
    # ex. http://192.168.137.50 ; vide = LED désactivée
    esp8266_url: str = Field("", pattern=r"^(https?://[A-Za-z0-9.:-]+)?$")

    # --- maintenance -----------------------------------------------------------------------
    maintenance_interval_seconds: int = Field(600, ge=30, le=86400)

    @field_validator("db_password", "jwt_private_key_pem_b64")
    @classmethod
    def _strong_secret(cls, value: SecretStr) -> SecretStr:
        if len(value.get_secret_value()) < MIN_SECRET_LENGTH:
            raise ValueError(f"must contain at least {MIN_SECRET_LENGTH} characters")
        return value

    @field_validator("db_pool_max_size")
    @classmethod
    def _pool_bounds(cls, value: int, info) -> int:  # noqa: ANN001 - signature imposée par pydantic
        minimum = info.data.get("db_pool_min_size", 1)
        if value < minimum:
            raise ValueError("db_pool_max_size must be >= db_pool_min_size")
        return value
