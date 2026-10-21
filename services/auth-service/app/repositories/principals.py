"""Accès aux principaux et à leurs rôles (base ra_auth)."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from ra_common.db import Connection, Record

from app.domain.models import Principal, PrincipalKind

_SELECT = """
SELECT p.id, p.kind, p.username, p.display_name, p.secret_hash, p.is_active,
       p.failed_login_count, p.locked_until, p.tokens_valid_after, p.last_login_at, p.created_at,
       GROUP_CONCAT(pr.role_code ORDER BY pr.role_code SEPARATOR ',') AS roles,
       COALESCE(MAX(r.is_privileged), 0) AS is_privileged,
       EXISTS (SELECT 1 FROM ra_auth.face_embeddings f WHERE f.principal_id = p.id) AS face_enrolled
  FROM ra_auth.principals p
  LEFT JOIN ra_auth.principal_roles pr ON pr.principal_id = p.id
  LEFT JOIN ra_auth.roles r ON r.code = pr.role_code
"""


def _to_principal(row: Record) -> Principal:
    return Principal(
        id=UUID(str(row["id"])),
        kind=PrincipalKind(row["kind"]),
        username=row["username"],
        display_name=row["display_name"],
        secret_hash=row["secret_hash"],
        is_active=row["is_active"],
        failed_login_count=row["failed_login_count"],
        locked_until=row["locked_until"],
        tokens_valid_after=row["tokens_valid_after"],
        last_login_at=row["last_login_at"],
        created_at=row["created_at"],
        roles=tuple(row["roles"].split(",")) if row["roles"] else (),
        is_privileged=bool(row["is_privileged"]),
        face_enrolled=bool(row["face_enrolled"]),
    )


class PrincipalRepository:
    async def get_by_username(self, conn: Connection, username: str) -> Principal | None:
        row = await conn.fetchrow(_SELECT + " WHERE p.username = $1 GROUP BY p.id", username)
        return _to_principal(row) if row else None

    async def get_by_id(self, conn: Connection, principal_id: UUID) -> Principal | None:
        row = await conn.fetchrow(_SELECT + " WHERE p.id = $1 GROUP BY p.id", principal_id)
        return _to_principal(row) if row else None

    async def lock(self, conn: Connection, principal_id: UUID) -> bool:
        """Verrou de ligne pour sérialiser les changements d'état d'un principal."""
        return await conn.fetchval("SELECT 1 FROM ra_auth.principals WHERE id = $1 FOR UPDATE", principal_id) is not None

    async def lock_all(self, conn: Connection) -> None:
        """Verrouille tous les principaux (ordre de clé) : sérialise les amorçages concurrents."""
        await conn.fetch("SELECT id FROM ra_auth.principals ORDER BY id FOR UPDATE")

    async def list_all(self, conn: Connection) -> list[Principal]:
        rows = await conn.fetch(_SELECT + " GROUP BY p.id ORDER BY p.username")
        return [_to_principal(row) for row in rows]

    async def list_page(self, conn: Connection, *, after_username: str | None, limit: int) -> list[Principal]:
        rows = await conn.fetch(
            _SELECT + " WHERE ($1 IS NULL OR p.username > $1) GROUP BY p.id ORDER BY p.username LIMIT $2",
            after_username,
            limit,
        )
        return [_to_principal(row) for row in rows]

    async def record_login_failure(
        self, conn: Connection, principal_id: UUID, *, max_failures: int, lockout_seconds: int
    ) -> datetime | None:
        """Incrémente le compteur d'échecs ; renvoie la date de fin de verrouillage le cas échéant."""
        # MariaDB évalue les SET de gauche à droite sur les valeurs déjà modifiées : locked_until d'abord.
        await conn.execute(
            """
            UPDATE ra_auth.principals
               SET locked_until = CASE WHEN failed_login_count + 1 >= $2
                                       THEN CURRENT_TIMESTAMP(6) + INTERVAL $3 SECOND
                                       ELSE locked_until END,
                   failed_login_count = failed_login_count + 1
             WHERE id = $1
            """,
            principal_id,
            max_failures,
            lockout_seconds,
        )
        return await conn.fetchval(
            "SELECT CASE WHEN locked_until > CURRENT_TIMESTAMP(6) THEN locked_until END FROM ra_auth.principals WHERE id = $1",
            principal_id,
        )

    async def record_login_success(self, conn: Connection, principal_id: UUID, new_hash: str | None) -> None:
        await conn.execute(
            """
            UPDATE ra_auth.principals
               SET failed_login_count = 0,
                   locked_until = NULL,
                   last_login_at = CURRENT_TIMESTAMP(6),
                   secret_hash = COALESCE($2, secret_hash)
             WHERE id = $1
            """,
            principal_id,
            new_hash,
        )

    async def initialise_secret(self, conn: Connection, principal_id: UUID, secret_hash: str) -> bool:
        """Premier amorçage : pose le secret et active le principal (une seule fois)."""
        result = await conn.execute(
            "UPDATE ra_auth.principals SET secret_hash = $2, is_active = true WHERE id = $1 AND secret_hash = '!'",
            principal_id,
            secret_hash,
        )
        return result.endswith(" 1")

    async def create_user(self, conn: Connection, username: str, display_name: str, secret_hash: str) -> UUID:
        principal_id = uuid4()
        await conn.execute(
            "INSERT INTO ra_auth.principals (id, kind, username, display_name, secret_hash) VALUES ($1, 'USER', $2, $3, $4)",
            principal_id,
            username,
            display_name,
            secret_hash,
        )
        return principal_id

    async def rotate_secret(self, conn: Connection, principal_id: UUID, secret_hash: str) -> None:
        await conn.execute("UPDATE ra_auth.principals SET secret_hash = $2 WHERE id = $1", principal_id, secret_hash)

    async def bump_tokens_valid_after(self, conn: Connection, principal_id: UUID) -> datetime:
        """Invalide tout jeton émis avant la seconde suivante (les `iat` JWT sont entiers)."""
        await conn.execute(
            """
            UPDATE ra_auth.principals
               SET tokens_valid_after = GREATEST(tokens_valid_after, CURRENT_TIMESTAMP + INTERVAL 1 SECOND)
             WHERE id = $1
            """,
            principal_id,
        )
        return await conn.fetchval("SELECT tokens_valid_after FROM ra_auth.principals WHERE id = $1", principal_id)

    async def grant_role(self, conn: Connection, principal_id: UUID, role: str, granted_by: UUID) -> None:
        # Idempotent sans UPDATE sur la table ; l'appelant détient le verrou du principal (lock).
        await conn.execute(
            """
            INSERT INTO ra_auth.principal_roles (principal_id, role_code, granted_by)
            SELECT $1, $2, $3 FROM DUAL
             WHERE NOT EXISTS (SELECT 1 FROM ra_auth.principal_roles WHERE principal_id = $1 AND role_code = $2)
            """,
            principal_id,
            role,
            granted_by,
        )

    async def revoke_role(self, conn: Connection, principal_id: UUID, role: str) -> None:
        await conn.execute("DELETE FROM ra_auth.principal_roles WHERE principal_id = $1 AND role_code = $2", principal_id, role)

    async def set_active(self, conn: Connection, principal_id: UUID, active: bool) -> None:
        if active:
            await conn.execute(
                "UPDATE ra_auth.principals SET is_active = true, failed_login_count = 0, locked_until = NULL WHERE id = $1",
                principal_id,
            )
        else:
            await conn.execute("UPDATE ra_auth.principals SET is_active = false WHERE id = $1", principal_id)
