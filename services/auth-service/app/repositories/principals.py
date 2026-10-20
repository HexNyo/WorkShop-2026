"""Accès aux principaux et à leurs rôles (schéma auth)."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import asyncpg

from app.domain.models import Principal, PrincipalKind

_SELECT = """
SELECT p.id, p.kind::text AS kind, p.username, p.display_name, p.secret_hash, p.is_active,
       p.failed_login_count, p.locked_until, p.tokens_valid_after, p.last_login_at, p.created_at,
       COALESCE(array_agg(pr.role_code ORDER BY pr.role_code) FILTER (WHERE pr.role_code IS NOT NULL), '{}') AS roles,
       COALESCE(bool_or(r.is_privileged), false) AS is_privileged
  FROM auth.principals p
  LEFT JOIN auth.principal_roles pr ON pr.principal_id = p.id
  LEFT JOIN auth.roles r ON r.code = pr.role_code
"""


def _aware(value: datetime | None) -> datetime | None:
    # asyncpg décode ±infinity en datetime.min/max *naïfs* : on les ramène en UTC.
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


def _to_principal(row: asyncpg.Record) -> Principal:
    return Principal(
        id=UUID(str(row["id"])),
        kind=PrincipalKind(row["kind"]),
        username=row["username"],
        display_name=row["display_name"],
        secret_hash=row["secret_hash"],
        is_active=row["is_active"],
        failed_login_count=row["failed_login_count"],
        locked_until=_aware(row["locked_until"]),
        tokens_valid_after=_aware(row["tokens_valid_after"]),
        last_login_at=_aware(row["last_login_at"]),
        created_at=_aware(row["created_at"]),
        roles=tuple(row["roles"]),
        is_privileged=row["is_privileged"],
    )


class PrincipalRepository:
    async def get_by_username(self, conn: asyncpg.Connection, username: str) -> Principal | None:
        row = await conn.fetchrow(_SELECT + " WHERE p.username = $1 GROUP BY p.id", username)
        return _to_principal(row) if row else None

    async def get_by_id(self, conn: asyncpg.Connection, principal_id: UUID) -> Principal | None:
        row = await conn.fetchrow(_SELECT + " WHERE p.id = $1 GROUP BY p.id", principal_id)
        return _to_principal(row) if row else None

    async def lock(self, conn: asyncpg.Connection, principal_id: UUID) -> bool:
        """Verrou de ligne pour sérialiser les changements d'état d'un principal."""
        return await conn.fetchval("SELECT true FROM auth.principals WHERE id = $1 FOR UPDATE", principal_id) is True

    async def list_all(self, conn: asyncpg.Connection) -> list[Principal]:
        rows = await conn.fetch(_SELECT + " GROUP BY p.id ORDER BY p.username")
        return [_to_principal(row) for row in rows]

    async def list_page(self, conn: asyncpg.Connection, *, after_username: str | None, limit: int) -> list[Principal]:
        rows = await conn.fetch(
            _SELECT + " WHERE ($1::text IS NULL OR p.username > $1) GROUP BY p.id ORDER BY p.username LIMIT $2",
            after_username,
            limit,
        )
        return [_to_principal(row) for row in rows]

    async def record_login_failure(
        self, conn: asyncpg.Connection, principal_id: UUID, *, max_failures: int, lockout_seconds: int
    ) -> datetime | None:
        """Incrémente le compteur d'échecs ; renvoie la date de fin de verrouillage le cas échéant."""
        return await conn.fetchval(
            """
            UPDATE auth.principals
               SET failed_login_count = failed_login_count + 1,
                   locked_until = CASE WHEN failed_login_count + 1 >= $2
                                       THEN now() + make_interval(secs => $3)
                                       ELSE locked_until END
             WHERE id = $1
         RETURNING CASE WHEN locked_until > now() THEN locked_until END
            """,
            principal_id,
            max_failures,
            float(lockout_seconds),
        )

    async def record_login_success(self, conn: asyncpg.Connection, principal_id: UUID, new_hash: str | None) -> None:
        await conn.execute(
            """
            UPDATE auth.principals
               SET failed_login_count = 0,
                   locked_until = NULL,
                   last_login_at = now(),
                   secret_hash = COALESCE($2, secret_hash)
             WHERE id = $1
            """,
            principal_id,
            new_hash,
        )

    async def initialise_secret(self, conn: asyncpg.Connection, principal_id: UUID, secret_hash: str) -> bool:
        """Premier amorçage : pose le secret et active le principal (une seule fois)."""
        result = await conn.execute(
            "UPDATE auth.principals SET secret_hash = $2, is_active = true WHERE id = $1 AND secret_hash = '!'",
            principal_id,
            secret_hash,
        )
        return result.endswith(" 1")

    async def rotate_secret(self, conn: asyncpg.Connection, principal_id: UUID, secret_hash: str) -> None:
        await conn.execute("UPDATE auth.principals SET secret_hash = $2 WHERE id = $1", principal_id, secret_hash)

    async def bump_tokens_valid_after(self, conn: asyncpg.Connection, principal_id: UUID) -> datetime:
        """Invalide tout jeton émis avant la seconde suivante (les `iat` JWT sont entiers)."""
        return await conn.fetchval(
            """
            UPDATE auth.principals
               SET tokens_valid_after = GREATEST(tokens_valid_after, date_trunc('second', now()) + interval '1 second')
             WHERE id = $1
         RETURNING tokens_valid_after
            """,
            principal_id,
        )

    async def grant_role(self, conn: asyncpg.Connection, principal_id: UUID, role: str, granted_by: UUID) -> None:
        await conn.execute(
            "INSERT INTO auth.principal_roles (principal_id, role_code, granted_by) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
            principal_id,
            role,
            granted_by,
        )

    async def revoke_role(self, conn: asyncpg.Connection, principal_id: UUID, role: str) -> None:
        await conn.execute("DELETE FROM auth.principal_roles WHERE principal_id = $1 AND role_code = $2", principal_id, role)

    async def set_active(self, conn: asyncpg.Connection, principal_id: UUID, active: bool) -> None:
        if active:
            await conn.execute(
                "UPDATE auth.principals SET is_active = true, failed_login_count = 0, locked_until = NULL WHERE id = $1",
                principal_id,
            )
        else:
            await conn.execute("UPDATE auth.principals SET is_active = false WHERE id = $1", principal_id)
