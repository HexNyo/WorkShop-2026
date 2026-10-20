"""Accès PostgreSQL de l'auth-service (pool asyncpg partagé via ra_common)."""

from __future__ import annotations

from ra_common.db import UNAVAILABLE_ERRORS, Database

from app.core.config import Settings

__all__ = ["UNAVAILABLE_ERRORS", "Database", "database_from_settings"]


def database_from_settings(settings: Settings) -> Database:
    return Database(
        host=settings.db_host,
        port=settings.db_port,
        database=settings.db_name,
        user=settings.db_user,
        password=settings.db_password.get_secret_value(),
        application_name=settings.service_name,
        min_size=settings.db_pool_min_size,
        max_size=settings.db_pool_max_size,
        connect_timeout_seconds=settings.db_connect_timeout_seconds,
    )
