"""Échantillons de santé, chronologie des phases et catalogue de playbooks."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from ra_common.db import Connection, Record, json_value


class HealthRepository:
    async def add_sample(
        self,
        conn: Connection,
        *,
        service: str,
        status: str,
        latency_ms: int | None,
        http_status: int | None,
        details: dict[str, Any],
    ) -> None:
        await conn.execute(
            """
            INSERT INTO ra_remediation.service_health_samples (service, status, latency_ms, http_status, details)
            VALUES ($1, $2, $3, $4, $5)
            """,
            service,
            status,
            latency_ms,
            http_status,
            details,
        )

    async def since(self, conn: Connection, window: timedelta, limit: int = 5000) -> list[Record]:
        return await conn.fetch(
            """
            SELECT service, status, latency_ms, observed_at
              FROM ra_remediation.service_health_samples
             WHERE observed_at > CURRENT_TIMESTAMP(6) - INTERVAL $1 SECOND
             ORDER BY observed_at
             LIMIT $2
            """,
            int(window.total_seconds()),
            limit,
        )

    async def purge(self, conn: Connection, older_than: timedelta) -> int:
        result = await conn.execute(
            "DELETE FROM ra_remediation.service_health_samples WHERE observed_at < CURRENT_TIMESTAMP(6) - INTERVAL $1 SECOND",
            int(older_than.total_seconds()),
        )
        return int(result.split()[-1])


class PhaseRepository:
    async def current(self, conn: Connection) -> Record | None:
        return await conn.fetchrow(
            "SELECT phase, entered_at, incident_id, reason FROM ra_remediation.phase_history "
            "ORDER BY entered_at DESC, id DESC LIMIT 1"
        )

    async def add(self, conn: Connection, phase: str, incident_id: UUID | None, reason: str) -> datetime:
        return await conn.fetchval(
            """
            INSERT INTO ra_remediation.phase_history (phase, incident_id, reason)
            VALUES ($1, $2, $3) RETURNING entered_at
            """,
            phase,
            incident_id,
            reason[:256],
        )

    async def between(self, conn: Connection, start: datetime, end: datetime) -> list[Record]:
        """Segments chevauchant [start, end] : la phase en vigueur à `start` + les changements suivants."""
        return await conn.fetch(
            """
            (SELECT phase, entered_at, incident_id FROM ra_remediation.phase_history
              WHERE entered_at <= $1 ORDER BY entered_at DESC, id DESC LIMIT 1)
            UNION ALL
            (SELECT phase, entered_at, incident_id FROM ra_remediation.phase_history
              WHERE entered_at > $1 AND entered_at <= $2 ORDER BY entered_at, id LIMIT 2000)
            ORDER BY entered_at
            """,
            start,
            end,
        )


class PlaybookRepository:
    _COLUMNS = (
        "code, version, category, title, description, steps, post_verification_steps, "
        "max_attempts, step_timeout_seconds, cooldown_seconds, enabled, updated_at"
    )

    @staticmethod
    def _decode(row: Record | None) -> Record | None:
        if row is None:
            return None
        return {**row, "steps": json_value(row["steps"]), "post_verification_steps": json_value(row["post_verification_steps"])}

    async def list(self, conn: Connection) -> list[Record]:
        rows = await conn.fetch(f"SELECT {self._COLUMNS} FROM ra_remediation.playbooks ORDER BY category, code")
        return [self._decode(row) for row in rows]

    async def get(self, conn: Connection, code: str) -> Record | None:
        return self._decode(await conn.fetchrow(f"SELECT {self._COLUMNS} FROM ra_remediation.playbooks WHERE code = $1", code))

    async def active_for(self, conn: Connection, category: str) -> Record | None:
        return self._decode(
            await conn.fetchrow(f"SELECT {self._COLUMNS} FROM ra_remediation.playbooks WHERE category = $1 AND enabled", category)
        )

    async def set_enabled(self, conn: Connection, code: str, enabled: bool) -> Record | None:
        await conn.execute("UPDATE ra_remediation.playbooks SET enabled = $2 WHERE code = $1", code, enabled)
        return await self.get(conn, code)
