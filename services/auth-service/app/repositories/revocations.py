"""Flux de révocation des jetons d'accès."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from ra_common.db import Connection, UniqueViolationError

from app.domain.models import RevocationEntry


class RevocationRepository:
    async def revoke_jti(
        self, conn: Connection, *, jti: UUID, principal_id: UUID | None, expires_at: datetime, reason: str
    ) -> None:
        try:
            await conn.execute(
                """
                INSERT INTO ra_auth.revocation_events (kind, jti, principal_id, expires_at, reason)
                SELECT 'JTI', $1, $2, $3, $4 FROM DUAL
                 WHERE NOT EXISTS (SELECT 1 FROM ra_auth.revocation_events WHERE jti = $1)
                """,
                jti,
                principal_id,
                expires_at,
                reason,
            )
        except UniqueViolationError:
            pass  # révocation concurrente du même jti : InnoDB n'annule que l'instruction fautive

    async def revoke_principal(
        self, conn: Connection, *, principal_id: UUID, not_before: datetime, expires_at: datetime, reason: str
    ) -> None:
        await conn.execute(
            """
            INSERT INTO ra_auth.revocation_events (kind, principal_id, not_before, expires_at, reason)
            VALUES ('PRINCIPAL', $1, $2, $3, $4)
            """,
            principal_id,
            not_before,
            expires_at,
            reason,
        )

    async def is_revoked(self, conn: Connection, *, jti: str, principal_id: str, issued_at: int) -> bool:
        """Vérité terrain côté émetteur : jti révoqué, principal inconnu/inactif, ou jeton antérieur au not_before."""
        try:
            jti_uuid, principal_uuid = UUID(jti), UUID(principal_id)
        except ValueError:
            return True
        return bool(
            await conn.fetchval(
                """
                SELECT EXISTS (SELECT 1 FROM ra_auth.revocation_events WHERE kind = 'JTI' AND jti = $1)
                    OR COALESCE((SELECT NOT p.is_active OR p.tokens_valid_after > FROM_UNIXTIME($3)
                                   FROM ra_auth.principals p WHERE p.id = $2), true)
                """,
                jti_uuid,
                principal_uuid,
                issued_at,
            )
        )

    async def list_since(self, conn: Connection, *, since: int, limit: int) -> list[RevocationEntry]:
        rows = await conn.fetch(
            """
            SELECT seq, kind, jti, principal_id, not_before, expires_at
              FROM ra_auth.revocation_events
             WHERE seq > $1 AND expires_at > CURRENT_TIMESTAMP(6)
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

    async def max_seq(self, conn: Connection) -> int:
        return await conn.fetchval("SELECT COALESCE(MAX(seq), 0) FROM ra_auth.revocation_events")

    async def purge_expired(self, conn: Connection) -> int:
        result = await conn.execute("DELETE FROM ra_auth.revocation_events WHERE expires_at < CURRENT_TIMESTAMP(6)")
        return int(result.split()[-1])
