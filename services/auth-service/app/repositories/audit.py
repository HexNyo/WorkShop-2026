"""Journal d'audit de sécurité (append-only en base)."""

from __future__ import annotations

import ipaddress
from typing import Any
from uuid import UUID

import asyncpg

from ra_common.context import correlation_id_var, request_id_var
from ra_common.logging import redact


class AuditRepository:
    async def list_recent(self, conn: asyncpg.Connection, limit: int) -> list[asyncpg.Record]:
        return await conn.fetch(
            """
            SELECT a.occurred_at, a.event_type, a.outcome, p.username, actor.username AS actor, host(a.client_ip) AS client_ip, a.details
              FROM auth.audit_events a
              LEFT JOIN auth.principals p ON p.id = a.principal_id
              LEFT JOIN auth.principals actor ON actor.id = a.actor_principal_id
             ORDER BY a.id DESC
             LIMIT $1
            """,
            limit,
        )

    async def record(
        self,
        conn: asyncpg.Connection,
        *,
        event_type: str,
        outcome: str,
        principal_id: UUID | None = None,
        actor_principal_id: UUID | str | None = None,
        client_ip: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        ip = None
        if client_ip:
            try:
                ip = ipaddress.ip_address(client_ip)
            except ValueError:
                ip = None
        actor = UUID(str(actor_principal_id)) if actor_principal_id else None
        await conn.execute(
            """
            INSERT INTO auth.audit_events (event_type, outcome, principal_id, actor_principal_id, client_ip, correlation_id, details)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            """,
            event_type,
            outcome,
            principal_id,
            actor,
            ip,
            correlation_id_var.get() or request_id_var.get(),
            redact(details or {}),
        )
