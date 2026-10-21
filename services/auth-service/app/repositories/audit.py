"""Journal d'audit de sécurité (append-only en base)."""

from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Any
from uuid import UUID

from ra_common.context import correlation_id_var, request_id_var
from ra_common.db import Connection, Record, json_value
from ra_common.logging import redact


class AuditRepository:
    async def list_recent(
        self,
        conn: Connection,
        limit: int,
        *,
        username: str | None = None,
        event_type: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> list[Record]:
        rows = await conn.fetch(
            """
            SELECT a.occurred_at, a.event_type, a.outcome, p.username, actor.username AS actor, a.client_ip, a.details
              FROM ra_auth.audit_events a
              LEFT JOIN ra_auth.principals p ON p.id = a.principal_id
              LEFT JOIN ra_auth.principals actor ON actor.id = a.actor_principal_id
             WHERE ($2 IS NULL OR p.username = $2 OR actor.username = $2)
               AND ($3 IS NULL OR a.event_type = $3)
               AND ($4 IS NULL OR a.occurred_at >= $4)
               AND ($5 IS NULL OR a.occurred_at < $5)
             ORDER BY a.id DESC
             LIMIT $1
            """,
            limit,
            username,
            event_type,
            since,
            until,
        )
        return [{**row, "details": json_value(row["details"])} for row in rows]

    async def record(
        self,
        conn: Connection,
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
            INSERT INTO ra_auth.audit_events (event_type, outcome, principal_id, actor_principal_id, client_ip, correlation_id, details)
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
