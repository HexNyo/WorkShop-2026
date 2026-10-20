"""Accès PostgreSQL (asyncpg) commun aux services : pool, transactions, sonde.

Nécessite l'extra `postgres` (asyncpg).
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import asyncpg

logger = logging.getLogger("ra_common.db")

# Exceptions traduisant une indisponibilité (=> HTTP 503), par opposition à un bug.
UNAVAILABLE_ERRORS: tuple[type[BaseException], ...] = (
    OSError,
    asyncio.TimeoutError,
    asyncpg.PostgresConnectionError,
    asyncpg.InterfaceError,
    asyncpg.TooManyConnectionsError,
    asyncpg.CannotConnectNowError,
    asyncpg.QueryCanceledError,
    asyncpg.LockNotAvailableError,
    asyncpg.DeadlockDetectedError,
)


def sqlstate(exc: BaseException) -> str | None:
    """SQLSTATE d'une erreur PostgreSQL (y compris les codes applicatifs RAxxx)."""
    return getattr(exc, "sqlstate", None)


class Database:
    def __init__(
        self,
        *,
        host: str,
        port: int,
        database: str,
        user: str,
        password: str,
        application_name: str,
        min_size: int = 2,
        max_size: int = 10,
        connect_timeout_seconds: int = 60,
        acquire_timeout_seconds: float = 3.0,
        command_timeout_seconds: float = 5.0,
    ) -> None:
        self._params = {
            "host": host,
            "port": port,
            "database": database,
            "user": user,
            "password": password,
            "min_size": min_size,
            "max_size": max_size,
            "command_timeout": command_timeout_seconds,
            "timeout": 5,
            "server_settings": {"application_name": application_name},
        }
        self._connect_timeout = connect_timeout_seconds
        self._acquire_timeout = acquire_timeout_seconds
        self._label = f"{user}@{host}"
        self._pool: asyncpg.Pool | None = None

    @property
    def pool(self) -> asyncpg.Pool:
        if self._pool is None:
            raise RuntimeError("database pool is not initialised")
        return self._pool

    @property
    def connect_kwargs(self) -> dict:
        """Paramètres de connexion unitaire (ex. connexion LISTEN dédiée)."""
        return {key: self._params[key] for key in ("host", "port", "database", "user", "password", "server_settings")}

    async def connect(self) -> None:
        deadline = time.monotonic() + self._connect_timeout
        delay = 0.5
        while True:
            try:
                self._pool = await asyncpg.create_pool(init=self.init_connection, **self._params)
                logger.info("database pool ready (%s)", self._label, extra={"event": "db.connected"})
                return
            except UNAVAILABLE_ERRORS as exc:
                if time.monotonic() + delay > deadline:
                    raise
                logger.warning(
                    "database not reachable yet (%s), retrying in %.1fs",
                    exc.__class__.__name__,
                    delay,
                    extra={"event": "db.connect_retry"},
                )
                await asyncio.sleep(delay)
                delay = min(delay * 2, 5.0)

    @staticmethod
    async def init_connection(connection: asyncpg.Connection) -> None:
        await connection.set_type_codec("jsonb", encoder=json.dumps, decoder=json.loads, schema="pg_catalog")

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    @asynccontextmanager
    async def connection(self) -> AsyncIterator[asyncpg.Connection]:
        async with self.pool.acquire(timeout=self._acquire_timeout) as connection:
            yield connection

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[asyncpg.Connection]:
        async with self.pool.acquire(timeout=self._acquire_timeout) as connection, connection.transaction():
            yield connection

    async def ping(self) -> float:
        """Latence d'un aller-retour SQL, en millisecondes."""
        start = time.perf_counter()
        async with self.pool.acquire(timeout=2) as connection:
            await connection.fetchval("SELECT 1", timeout=2)
        return (time.perf_counter() - start) * 1000

    def pool_usage(self) -> tuple[int, int, int]:
        """(en cours d'utilisation, au repos, maximum)."""
        if self._pool is None:
            return 0, 0, 0
        size, idle = self._pool.get_size(), self._pool.get_idle_size()
        return size - idle, idle, self._pool.get_max_size()
