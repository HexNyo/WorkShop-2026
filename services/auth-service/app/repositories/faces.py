"""Empreintes faciales des utilisateurs (base ra_auth)."""

from __future__ import annotations

from uuid import UUID

from ra_common.db import Connection


class FaceRepository:
    async def get(self, conn: Connection, principal_id: UUID) -> bytes | None:
        return await conn.fetchval("SELECT embedding FROM ra_auth.face_embeddings WHERE principal_id = $1", principal_id)

    async def delete(self, conn: Connection, principal_id: UUID) -> bool:
        return await conn.execute("DELETE FROM ra_auth.face_embeddings WHERE principal_id = $1", principal_id) == "DELETE 1"

    async def upsert(self, conn: Connection, principal_id: UUID, embedding: bytes, enrolled_by: UUID | None) -> None:
        await conn.execute(
            """
            INSERT INTO ra_auth.face_embeddings (principal_id, embedding, enrolled_by) VALUES ($1, $2, $3)
            ON DUPLICATE KEY UPDATE
               embedding = VALUES(embedding), enrolled_at = CURRENT_TIMESTAMP(6), enrolled_by = VALUES(enrolled_by)
            """,
            principal_id,
            embedding,
            enrolled_by,
        )
