"""Échantillons de santé, chronologie des phases et catalogue de playbooks."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

import asyncpg


class HealthRepository:
    async def add_sample(
        self,
        conn: asyncpg.Connection,
        *,
        service: str,
        status: str,
        latency_ms: int | None,
        http_status: int | None,
        details: dict[str, Any],
    ) -> None:
        await conn.execute(
            """
            INSERT INTO remediation.service_health_samples (service, status, latency_ms, http_status, details)
            VALUES ($1, $2::remediation.service_status, $3, $4, $5)
            """,
            service,
            status,
            latency_ms,
            http_status,
            details,
        )

    async def since(self, conn: asyncpg.Connection, window: timedelta, limit: int = 5000) -> list[asyncpg.Record]:
        return await conn.fetch(
            """
            SELECT service, status::text AS status, latency_ms, observed_at
              FROM remediation.service_health_samples
             WHERE observed_at > now() - $1::interval
             ORDER BY observed_at
             LIMIT $2
            """,
            window,
            limit,
        )

    async def purge(self, conn: asyncpg.Connection, older_than: timedelta) -> int:
        result = await conn.execute(
            "DELETE FROM remediation.service_health_samples WHERE observed_at < now() - $1::interval", older_than
        )
        return int(result.split()[-1])


class PhaseRepository:
    async def current(self, conn: asyncpg.Connection) -> asyncpg.Record | None:
        return await conn.fetchrow(
            "SELECT phase::text AS phase, entered_at, incident_id, reason FROM remediation.phase_history "
            "ORDER BY entered_at DESC, id DESC LIMIT 1"
        )

    async def add(self, conn: asyncpg.Connection, phase: str, incident_id: UUID | None, reason: str) -> datetime:
        return await conn.fetchval(
            """
            INSERT INTO remediation.phase_history (phase, incident_id, reason)
            VALUES ($1::remediation.system_phase, $2, $3) RETURNING entered_at
            """,
            phase,
            incident_id,
            reason[:256],
        )

    async def between(self, conn: asyncpg.Connection, start: datetime, end: datetime) -> list[asyncpg.Record]:
        """Segments chevauchant [start, end] : la phase en vigueur à `start` + les changements suivants."""
        return await conn.fetch(
            """
            (SELECT phase::text AS phase, entered_at, incident_id FROM remediation.phase_history
              WHERE entered_at <= $1 ORDER BY entered_at DESC, id DESC LIMIT 1)
            UNION ALL
            (SELECT phase::text AS phase, entered_at, incident_id FROM remediation.phase_history
              WHERE entered_at > $1 AND entered_at <= $2 ORDER BY entered_at, id LIMIT 2000)
            ORDER BY entered_at
            """,
            start,
            end,
        )


class PlaybookRepository:
    _COLUMNS = (
        "code, version, category::text AS category, title, description, steps, post_verification_steps, "
        "max_attempts, step_timeout_seconds, cooldown_seconds, enabled, updated_at"
    )

    async def list(self, conn: asyncpg.Connection) -> list[asyncpg.Record]:
        return await conn.fetch(f"SELECT {self._COLUMNS} FROM remediation.playbooks ORDER BY category, code")

    async def get(self, conn: asyncpg.Connection, code: str) -> asyncpg.Record | None:
        return await conn.fetchrow(f"SELECT {self._COLUMNS} FROM remediation.playbooks WHERE code = $1", code)

    async def active_for(self, conn: asyncpg.Connection, category: str) -> asyncpg.Record | None:
        return await conn.fetchrow(
            f"SELECT {self._COLUMNS} FROM remediation.playbooks "
            "WHERE category = $1::remediation.alert_category AND enabled",
            category,
        )

    async def set_enabled(self, conn: asyncpg.Connection, code: str, enabled: bool) -> asyncpg.Record | None:
        return await conn.fetchrow(
            f"UPDATE remediation.playbooks SET enabled = $2 WHERE code = $1 RETURNING {self._COLUMNS}", code, enabled
        )
