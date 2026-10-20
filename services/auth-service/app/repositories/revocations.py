"""Flux de révocation des jetons d'accès."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

import asyncpg

from app.domain.models import RevocationEntry


class RevocationRepository:
    async def revoke_jti(
        self, conn: asyncpg.Connection, *, jti: UUID, principal_id: UUID | None, expires_at: datetime, reason: str
    ) -> None:
        await conn.execute(
            """
            INSERT INTO auth.revocation_events (kind, jti, principal_id, expires_at, reason)
            VALUES ('JTI', $1, $2, $3, $4)
            ON CONFLICT (jti) WHERE kind = 'JTI' DO NOTHING
            """,
            jti,
            principal_id,
            expires_at,
            reason,
        )

    async def revoke_principal(
        self, conn: asyncpg.Connection, *, principal_id: UUID, not_before: datetime, expires_at: datetime, reason: str
    ) -> None:
        await conn.execute(
            """
            INSERT INTO auth.revocation_events (kind, principal_id, not_before, expires_at, reason)
            VALUES ('PRINCIPAL', $1, $2, $3, $4)
            """,
            principal_id,
            not_before,
            expires_at,
            reason,
        )

    async def is_revoked(self, conn: asyncpg.Connection, *, jti: str, principal_id: str, issued_at: int) -> bool:
        """Vérité terrain côté émetteur : jti révoqué, principal inconnu/inactif, ou jeton antérieur au not_before."""
        try:
            jti_uuid, principal_uuid = UUID(jti), UUID(principal_id)
        except ValueError:
            return True
        return await conn.fetchval(
            """
            SELECT EXISTS (SELECT 1 FROM auth.revocation_events WHERE kind = 'JTI' AND jti = $1)
                OR COALESCE((SELECT NOT p.is_active OR p.tokens_valid_after > to_timestamp($3)
                               FROM auth.principals p WHERE p.id = $2), true)
            """,
            jti_uuid,
            principal_uuid,
            float(issued_at),
        )

    async def list_since(self, conn: asyncpg.Connection, *, since: int, limit: int) -> list[RevocationEntry]:
        rows = await conn.fetch(
            """
            SELECT seq, kind::text AS kind, jti, principal_id, not_before, expires_at
              FROM auth.revocation_events
             WHERE seq > $1 AND expires_at > now()
             ORDER BY seq
             LIMIT $2
            """,
            since,
            limit,
        )
        return [
            RevocationEntry(
                seq=row["seq"],
                kind=row["kind"],
                jti=UUID(str(row["jti"])) if row["jti"] else None,
                principal_id=UUID(str(row["principal_id"])) if row["principal_id"] else None,
                not_before=row["not_before"],
                expires_at=row["expires_at"],
            )
            for row in rows
        ]

    async def max_seq(self, conn: asyncpg.Connection) -> int:
        return await conn.fetchval("SELECT COALESCE(max(seq), 0) FROM auth.revocation_events")

    async def purge_expired(self, conn: asyncpg.Connection) -> int:
        result = await conn.execute("DELETE FROM auth.revocation_events WHERE expires_at < now()")
        return int(result.split()[-1])
