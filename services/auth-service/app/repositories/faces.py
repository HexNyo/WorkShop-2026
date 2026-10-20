"""Empreintes faciales des utilisateurs (schéma auth)."""

from __future__ import annotations

from uuid import UUID

import asyncpg


class FaceRepository:
    async def get(self, conn: asyncpg.Connection, principal_id: UUID) -> bytes | None:
        return await conn.fetchval("SELECT embedding FROM auth.face_embeddings WHERE principal_id = $1", principal_id)

    async def upsert(self, conn: asyncpg.Connection, principal_id: UUID, embedding: bytes, enrolled_by: UUID | None) -> None:
        await conn.execute(
            """
            INSERT INTO auth.face_embeddings (principal_id, embedding, enrolled_by) VALUES ($1, $2, $3)
            ON CONFLICT (principal_id) DO UPDATE
               SET embedding = EXCLUDED.embedding, enrolled_at = now(), enrolled_by = EXCLUDED.enrolled_by
            """,
            principal_id,
            embedding,
            enrolled_by,
        )
