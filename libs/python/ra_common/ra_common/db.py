"""Accès MariaDB (aiomysql) commun aux services : pool, transactions, sonde.

La façade garde la forme de l'API asyncpg utilisée par les dépôts (`$n`, fetch /
fetchrow / fetchval / execute, transactions imbriquées en SAVEPOINT) et normalise
les valeurs : UUID (CHAR(36)), booléens (TINYINT(1)), horodatages UTC conscients.
Le JSON reste du texte en lecture (`json_value`) ; dict/list sont sérialisés en écriture.

Nécessite l'extra `mariadb` (aiomysql).
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import math
import re
import time
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import aiomysql
import pymysql
from pymysql.constants import CLIENT, FIELD_TYPE

logger = logging.getLogger("ra_common.db")

Record = dict[str, Any]


class DatabaseError(Exception):
    """Erreur renvoyée par MariaDB ; `sqlstate` porte aussi les codes applicatifs RAxxx."""

    def __init__(self, message: str, *, errno: int | None = None, sqlstate: str | None = None,
                 constraint_name: str | None = None) -> None:
        super().__init__(message)
        self.errno = errno
        self.sqlstate = sqlstate
        self.constraint_name = constraint_name


class UniqueViolationError(DatabaseError):
    pass


class ForeignKeyViolationError(DatabaseError):
    pass


class DatabaseUnavailable(DatabaseError):
    """Indisponibilité (réseau, saturation, verrou, délai) par opposition à un bug."""


# Exceptions traduisant une indisponibilité (=> HTTP 503).
UNAVAILABLE_ERRORS: tuple[type[BaseException], ...] = (OSError, asyncio.TimeoutError, DatabaseUnavailable)

# 1040 trop de connexions, 1205 délai de verrou, 1213 interblocage, 1927 connexion tuée,
# 1969 max_statement_time, 2002-2055 erreurs client/réseau.
_UNAVAILABLE_ERRNOS = {1040, 1053, 1205, 1213, 1927, 1969, 2002, 2003, 2006, 2013, 2014, 2055}
_SQLSTATE_BY_ERRNO = {
    1062: "23505", 1451: "23503", 1452: "23503", 4025: "23514", 1048: "23502",
    1305: "42883", 1142: "42501", 1143: "42501", 1370: "42501",
}
# SIGNAL SQLSTATE 'RAxxx' : PyMySQL ne transmet pas le SQLSTATE, les scripts le répètent en tête du message.
_SIGNALLED = re.compile(r"^([A-Z0-9]{5}) ")
_KEY_NAME = re.compile(r"for key '(?:[^']*\.)?([^'.]+)'")
_CHECK_NAME = re.compile(r"CONSTRAINT `([^`]+)`")
_FK_NAME = re.compile(r"CONSTRAINT `([^`]+)` FOREIGN KEY")
_PLACEHOLDER = re.compile(r"\$(\d+)")
_UUID_TEXT = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def sqlstate(exc: BaseException) -> str | None:
    """SQLSTATE d'une erreur MariaDB (y compris les codes applicatifs RAxxx)."""
    return getattr(exc, "sqlstate", None)


def json_value(value: Any) -> Any:
    """Décode une colonne JSON (MariaDB la renvoie en texte)."""
    return json.loads(value) if isinstance(value, str | bytes) else value


def translate(exc: pymysql.err.MySQLError) -> DatabaseError:
    errno = exc.args[0] if exc.args and isinstance(exc.args[0], int) else None
    message = str(exc.args[1]) if len(exc.args) > 1 else str(exc)
    if errno in _UNAVAILABLE_ERRNOS or isinstance(exc, pymysql.err.InterfaceError):
        return DatabaseUnavailable(message, errno=errno)
    if errno == 1062:
        name = _KEY_NAME.search(message)
        return UniqueViolationError(message, errno=errno, sqlstate="23505", constraint_name=name and name.group(1))
    if errno in (1451, 1452):
        name = _FK_NAME.search(message)
        return ForeignKeyViolationError(message, errno=errno, sqlstate="23503", constraint_name=name and name.group(1))
    signalled = _SIGNALLED.match(message) if errno == 1644 else None
    name = _CHECK_NAME.search(message) if errno == 4025 else None
    return DatabaseError(
        message,
        errno=errno,
        sqlstate=signalled.group(1) if signalled else _SQLSTATE_BY_ERRNO.get(errno),
        constraint_name=name and name.group(1),
    )


def _param(value: Any) -> Any:
    if isinstance(value, UUID | ipaddress.IPv4Address | ipaddress.IPv6Address):
        return str(value)
    if isinstance(value, datetime) and value.tzinfo is not None:
        return value.astimezone(UTC).replace(tzinfo=None)
    if isinstance(value, dict | list):
        return json.dumps(value, default=str, separators=(",", ":"))
    return value


def _converter(type_code: int, length: int):
    if type_code in (FIELD_TYPE.TINY, FIELD_TYPE.LONG) and length == 1:  # BOOLEAN, comparaisons, EXISTS
        return lambda value: value if value is None else bool(value)
    if type_code == FIELD_TYPE.STRING:  # CHAR : seules les colonnes d'identifiants font 36 caractères
        return lambda value: UUID(value) if isinstance(value, str) and _UUID_TEXT.match(value) else value
    if type_code in (FIELD_TYPE.DATETIME, FIELD_TYPE.TIMESTAMP):  # stockés en UTC (time_zone = +00:00)
        return lambda value: value.replace(tzinfo=UTC) if isinstance(value, datetime) else value
    return None


def _rows(description: Sequence[tuple] | None, raw: Sequence[tuple]) -> list[Record]:
    if not description:
        return []
    names = [column[0] for column in description]
    converters = [_converter(column[1], column[3]) for column in description]
    return [
        {name: (convert(value) if convert else value) for name, convert, value in zip(names, converters, row, strict=True)}
        for row in raw
    ]


def _prepare(query: str, args: Sequence[Any]) -> tuple[str, tuple[Any, ...]]:
    """`$n` (asyncpg) -> `%s` (PyMySQL), arguments réordonnés ; un `%` littéral est doublé."""
    order = [int(index) - 1 for index in _PLACEHOLDER.findall(query)]
    return _PLACEHOLDER.sub("%s", query.replace("%", "%%")), tuple(_param(args[index]) for index in order)


class Connection:
    def __init__(self, raw: aiomysql.Connection) -> None:
        self._raw = raw
        self._depth = 0

    async def _run(self, query: str, args: Sequence[Any]) -> tuple[list[Record], int]:
        sql, params = _prepare(query, args)
        try:
            async with self._raw.cursor() as cursor:
                await cursor.execute(sql, params)
                rows = _rows(cursor.description, await cursor.fetchall())
                count = cursor.rowcount
                while await cursor.nextset():  # CALL : jeu de résultats puis statut final
                    pass
        except pymysql.err.MySQLError as exc:
            raise translate(exc) from exc
        return rows, count

    async def fetch(self, query: str, *args: Any) -> list[Record]:
        return (await self._run(query, args))[0]

    async def fetchrow(self, query: str, *args: Any) -> Record | None:
        rows = (await self._run(query, args))[0]
        return rows[0] if rows else None

    async def fetchval(self, query: str, *args: Any) -> Any:
        row = await self.fetchrow(query, *args)
        return next(iter(row.values())) if row else None

    async def execute(self, query: str, *args: Any) -> str:
        """Statut au format asyncpg (« UPDATE 1 », « INSERT 0 1 ») : lignes trouvées (CLIENT.FOUND_ROWS)."""
        count = (await self._run(query, args))[1]
        verb = query.split(None, 1)[0].upper()
        return f"INSERT 0 {count}" if verb == "INSERT" else f"{verb} {count}"

    async def _statement(self, sql: str) -> None:
        try:
            async with self._raw.cursor() as cursor:
                await cursor.execute(sql)
        except pymysql.err.MySQLError as exc:
            raise translate(exc) from exc

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[Connection]:
        """Transaction, ou SAVEPOINT si une transaction est déjà ouverte sur cette connexion."""
        depth = self._depth
        await self._statement("START TRANSACTION" if depth == 0 else f"SAVEPOINT ra_sp{depth}")
        self._depth = depth + 1
        try:
            yield self
        except BaseException:
            self._depth = depth
            try:
                await self._statement("ROLLBACK" if depth == 0 else f"ROLLBACK TO SAVEPOINT ra_sp{depth}")
            except Exception:  # noqa: BLE001 - connexion inutilisable : ne jamais la rendre au pool
                self._raw.close()
            raise
        self._depth = depth
        await self._statement("COMMIT" if depth == 0 else f"RELEASE SAVEPOINT ra_sp{depth}")


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
        # Session : UTC, READ COMMITTED (sémantique PostgreSQL), mode strict, délais bornés.
        init_command = (
            "SET time_zone = '+00:00', tx_isolation = 'READ-COMMITTED', "
            "sql_mode = 'STRICT_ALL_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION', "
            f"max_statement_time = {command_timeout_seconds:g}, "
            f"innodb_lock_wait_timeout = {max(1, math.ceil(command_timeout_seconds))}, "
            "idle_transaction_timeout = 30"
        )
        self._params = {
            "host": host,
            "port": port,
            "db": database,
            "user": user,
            "password": password,
            "minsize": min_size,
            "maxsize": max_size,
            "connect_timeout": 5,
            "autocommit": True,
            "charset": "utf8mb4",
            "client_flag": CLIENT.FOUND_ROWS,
            "init_command": init_command,
            "program_name": application_name,
            "pool_recycle": 600,
        }
        self._connect_timeout = connect_timeout_seconds
        self._acquire_timeout = acquire_timeout_seconds
        self._label = f"{user}@{host}"
        self._pool: aiomysql.Pool | None = None

    @property
    def pool(self) -> aiomysql.Pool:
        if self._pool is None:
            raise RuntimeError("database pool is not initialised")
        return self._pool

    async def connect(self) -> None:
        deadline = time.monotonic() + self._connect_timeout
        delay = 0.5
        while True:
            try:
                self._pool = await aiomysql.create_pool(**self._params)
                logger.info("database pool ready (%s)", self._label, extra={"event": "db.connected"})
                return
            except (*UNAVAILABLE_ERRORS, pymysql.err.OperationalError) as exc:
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

    async def close(self) -> None:
        if self._pool is not None:
            self._pool.close()
            await self._pool.wait_closed()
            self._pool = None

    @asynccontextmanager
    async def _acquire(self, timeout: float) -> AsyncIterator[Connection]:
        try:
            raw = await asyncio.wait_for(self.pool.acquire(), timeout)
        except pymysql.err.MySQLError as exc:
            raise translate(exc) from exc
        try:
            yield Connection(raw)
        finally:
            self.pool.release(raw)

    @asynccontextmanager
    async def connection(self) -> AsyncIterator[Connection]:
        async with self._acquire(self._acquire_timeout) as connection:
            yield connection

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[Connection]:
        async with self._acquire(self._acquire_timeout) as connection, connection.transaction():
            yield connection

    async def ping(self) -> float:
        """Latence d'un aller-retour SQL, en millisecondes."""
        start = time.perf_counter()
        async with self._acquire(2) as connection:
            await connection.fetchval("SELECT 1")
        return (time.perf_counter() - start) * 1000

    def pool_usage(self) -> tuple[int, int, int]:
        """(en cours d'utilisation, au repos, maximum)."""
        if self._pool is None:
            return 0, 0, 0
        size, idle = self._pool.size, self._pool.freesize
        return size - idle, idle, self._pool.maxsize
