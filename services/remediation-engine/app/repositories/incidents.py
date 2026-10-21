"""Incidents, chronologie des transitions et alertes reçues."""

from __future__ import annotations

import statistics
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from ra_common.db import Connection, Record

from app.domain.models import AlertSubmission, Category, Incident, IncidentStatus, Severity

_COLUMNS = """
id, fingerprint, category, severity, status, status_reason,
title, target_service, target_principal_id, target_account_id, playbook_code, attempt_count, alert_count,
resolution, last_error, opened_at, remediation_started_at, verified_at, closed_at, updated_at
"""
_CLOSED = "('RESOLVED','SUPPRESSED')"
_SEVERITIES = "'INFO', 'WARNING', 'HIGH', 'CRITICAL'"  # ordre de l'ENUM severity


def _uuid(value: Any) -> UUID | None:
    return UUID(str(value)) if value is not None else None


def to_incident(row: Record) -> Incident:
    return Incident(
        id=UUID(str(row["id"])),
        fingerprint=row["fingerprint"],
        category=Category(row["category"]),
        severity=Severity(row["severity"]),
        status=IncidentStatus(row["status"]),
        status_reason=row["status_reason"],
        title=row["title"],
        target_service=row["target_service"],
        target_principal_id=_uuid(row["target_principal_id"]),
        target_account_id=_uuid(row["target_account_id"]),
        playbook_code=row["playbook_code"],
        attempt_count=row["attempt_count"],
        alert_count=row["alert_count"],
        resolution=row["resolution"],
        last_error=row["last_error"],
        opened_at=row["opened_at"],
        remediation_started_at=row["remediation_started_at"],
        verified_at=row["verified_at"],
        closed_at=row["closed_at"],
        updated_at=row["updated_at"],
    )


class IncidentRepository:
    async def get(self, conn: Connection, incident_id: UUID, *, for_update: bool = False) -> Incident | None:
        suffix = " FOR UPDATE" if for_update else ""
        row = await conn.fetchrow(f"SELECT {_COLUMNS} FROM ra_remediation.incidents WHERE id = $1{suffix}", incident_id)
        return to_incident(row) if row else None

    async def find_open(self, conn: Connection, fingerprint: str) -> Incident | None:
        row = await conn.fetchrow(
            f"SELECT {_COLUMNS} FROM ra_remediation.incidents WHERE fingerprint = $1 AND status NOT IN {_CLOSED} FOR UPDATE",
            fingerprint,
        )
        return to_incident(row) if row else None

    async def create(self, conn: Connection, alert: AlertSubmission, *, reason: str) -> UUID:
        incident_id = uuid4()
        await conn.execute(
            """
            INSERT INTO ra_remediation.incidents (id, fingerprint, category, severity, status_reason, title, target_service,
                                                  target_principal_id, target_account_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            """,
            incident_id,
            alert.fingerprint,
            alert.category.value,
            alert.severity.value,
            reason[:512],
            alert.title[:200],
            alert.target_service,
            alert.target_principal_id,
            alert.target_account_id,
        )
        return incident_id

    async def absorb_duplicate(self, conn: Connection, incident_id: UUID, severity: Severity) -> None:
        await conn.execute(
            f"""
            UPDATE ra_remediation.incidents
               SET alert_count = alert_count + 1,
                   severity = ELT(GREATEST(FIELD(severity, {_SEVERITIES}), FIELD($2, {_SEVERITIES})), {_SEVERITIES})
             WHERE id = $1
            """,
            incident_id,
            severity.value,
        )

    async def transition(
        self,
        conn: Connection,
        incident_id: UUID,
        to_status: IncidentStatus,
        reason: str,
        *,
        playbook_code: str | None = None,
        attempt_count: int | None = None,
        resolution: str | None = None,
        last_error: str | None = None,
    ) -> Incident:
        """La validité de la transition (et la garde RA203) est imposée par la base."""
        await conn.execute(
            """
            UPDATE ra_remediation.incidents
               SET status = $2,
                   status_reason = $3,
                   playbook_code = COALESCE($4, playbook_code),
                   attempt_count = COALESCE($5, attempt_count),
                   resolution = COALESCE($6, resolution),
                   last_error = COALESCE($7, last_error)
             WHERE id = $1
            """,
            incident_id,
            to_status.value,
            reason[:512],
            playbook_code,
            attempt_count,
            resolution,
            last_error[:1024] if last_error else None,
        )
        return await self.get(conn, incident_id)

    async def set_attempt(self, conn: Connection, incident_id: UUID, attempt: int, last_error: str | None) -> None:
        await conn.execute(
            "UPDATE ra_remediation.incidents SET attempt_count = $2, last_error = COALESCE($3, last_error) WHERE id = $1",
            incident_id,
            attempt,
            last_error[:1024] if last_error else None,
        )

    async def list(
        self,
        conn: Connection,
        *,
        status: IncidentStatus | None,
        before: tuple[datetime, UUID] | None,
        limit: int,
    ) -> list[Incident]:
        rows = await conn.fetch(
            f"""
            SELECT {_COLUMNS} FROM ra_remediation.incidents
             WHERE ($1 IS NULL OR status = $1)
               AND ($2 IS NULL OR (opened_at, id) < ($2, $3))
             ORDER BY opened_at DESC, id DESC
             LIMIT $4
            """,
            status.value if status else None,
            before[0] if before else None,
            before[1] if before else None,
            limit,
        )
        return [to_incident(row) for row in rows]

    async def list_open(self, conn: Connection) -> list[Incident]:
        rows = await conn.fetch(
            f"SELECT {_COLUMNS} FROM ra_remediation.incidents WHERE status NOT IN {_CLOSED} ORDER BY opened_at"
        )
        return [to_incident(row) for row in rows]

    async def last_resolved(self, conn: Connection) -> tuple[UUID, datetime] | None:
        row = await conn.fetchrow(
            "SELECT id, closed_at FROM ra_remediation.incidents WHERE status = 'RESOLVED' ORDER BY closed_at DESC LIMIT 1"
        )
        return (UUID(str(row["id"])), row["closed_at"]) if row else None

    async def counters(self, conn: Connection) -> Record:
        row = await conn.fetchrow(
            f"""
            SELECT COUNT(CASE WHEN status NOT IN {_CLOSED} THEN 1 END) AS open_incidents,
                   COUNT(CASE WHEN status = 'RESOLVED' AND closed_at > CURRENT_TIMESTAMP(6) - INTERVAL 24 HOUR THEN 1 END) AS resolved_24h,
                   COUNT(CASE WHEN status = 'ESCALATED' AND updated_at > CURRENT_TIMESTAMP(6) - INTERVAL 24 HOUR THEN 1 END) AS escalated_24h
              FROM ra_remediation.incidents
            """
        )
        durations = await conn.fetch(
            """
            SELECT TIMESTAMPDIFF(MICROSECOND, opened_at, closed_at) / 1000000 AS seconds
              FROM ra_remediation.incidents
             WHERE status = 'RESOLVED' AND closed_at > CURRENT_TIMESTAMP(6) - INTERVAL 24 HOUR
            """
        )
        # Médiane calculée ici : PERCENTILE_CONT n'existe qu'en fonction de fenêtre sous MariaDB.
        mttr = statistics.median(float(item["seconds"]) for item in durations) if durations else None
        return {**row, "mttr_p50": mttr}

    async def remediations_last_hour(self, conn: Connection, target_service: str) -> int:
        return await conn.fetchval(
            """
            SELECT COUNT(*) FROM ra_remediation.executions e
              JOIN ra_remediation.incidents i ON i.id = e.incident_id
             WHERE i.target_service = $1 AND e.started_at > CURRENT_TIMESTAMP(6) - INTERVAL 1 HOUR
            """,
            target_service,
        )

    async def last_execution_end(self, conn: Connection, target_service: str, playbook_code: str) -> datetime | None:
        return await conn.fetchval(
            """
            SELECT MAX(e.finished_at) FROM ra_remediation.executions e
              JOIN ra_remediation.incidents i ON i.id = e.incident_id
             WHERE i.target_service = $1 AND e.playbook_code = $2
            """,
            target_service,
            playbook_code,
        )

    async def transitions(self, conn: Connection, incident_id: UUID) -> list[Record]:
        return await conn.fetch(
            """
            SELECT from_status, to_status, reason, occurred_at
              FROM ra_remediation.incident_transitions WHERE incident_id = $1 ORDER BY id
            """,
            incident_id,
        )

    async def closed_between(self, conn: Connection, start: datetime, end: datetime) -> list[Record]:
        return await conn.fetch(
            """
            SELECT id, status, closed_at, TIMESTAMPDIFF(MICROSECOND, opened_at, closed_at) / 1000000 AS duration
              FROM ra_remediation.incidents
             WHERE closed_at BETWEEN $1 AND $2 AND status = 'RESOLVED'
             ORDER BY closed_at
            """,
            start,
            end,
        )


    async def set_reason(self, conn: Connection, incident_id: UUID, reason: str) -> None:
        await conn.execute("UPDATE ra_remediation.incidents SET status_reason = $2 WHERE id = $1", incident_id, reason[:512])

    async def audit(self, conn: Connection, limit: int) -> list[Record]:
        """Transitions + actions de playbook + prises en charge humaines, les plus récentes d'abord.
        shortcut: seul le dernier acquittement d'un incident est visible (status_reason) ; ajouter une
        table d'actions opérateur si l'historique complet des acquittements devient nécessaire."""
        return await conn.fetch(
            """
            SELECT * FROM (
                SELECT t.occurred_at AS at, t.incident_id, i.target_service, 'transition' AS kind,
                       CONCAT(COALESCE(t.from_status, '-'), ' -> ', t.to_status) AS action, t.reason AS detail
                  FROM ra_remediation.incident_transitions t JOIN ra_remediation.incidents i ON i.id = t.incident_id
                UNION ALL
                SELECT COALESCE(s.finished_at, s.started_at), e.incident_id, i.target_service, 'step',
                       CONCAT(s.action, ' ', s.status), COALESCE(s.error, s.target, '')
                  FROM ra_remediation.execution_steps s
                  JOIN ra_remediation.executions e ON e.id = s.execution_id
                  JOIN ra_remediation.incidents i ON i.id = e.incident_id
                 WHERE s.started_at IS NOT NULL OR s.finished_at IS NOT NULL
                UNION ALL
                SELECT i.updated_at, i.id, i.target_service, 'acknowledge', 'acknowledged', i.status_reason
                  FROM ra_remediation.incidents i WHERE i.status_reason LIKE 'operator %acknowledged%'
            ) audit
            ORDER BY at DESC
            LIMIT $1
            """,
            limit,
        )


class AlertRepository:
    async def find(self, conn: Connection, source: str, external_id: str) -> Record | None:
        return await conn.fetchrow(
            """
            SELECT a.id, a.incident_id, i.status AS incident_status,
                   a.id <> (SELECT a2.id FROM ra_remediation.alerts a2 WHERE a2.incident_id = a.incident_id
                             ORDER BY a2.received_at, a2.id LIMIT 1) AS deduplicated
              FROM ra_remediation.alerts a
              JOIN ra_remediation.incidents i ON i.id = a.incident_id
             WHERE a.source = $1 AND a.external_id = $2
            """,
            source,
            external_id,
        )

    async def insert(self, conn: Connection, alert: AlertSubmission, incident_id: UUID) -> UUID:
        alert_id = uuid4()
        await conn.execute(
            """
            INSERT INTO ra_remediation.alerts (id, source, external_id, fingerprint, category, severity, confidence, title,
                                               target_service, detected_at, payload, incident_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            """,
            alert_id,
            alert.source,
            alert.external_id,
            alert.fingerprint,
            alert.category.value,
            alert.severity.value,
            alert.confidence,
            alert.title[:200],
            alert.target_service,
            alert.detected_at,
            alert.payload,
            incident_id,
        )
        return alert_id

    async def list_for_incident(self, conn: Connection, incident_id: UUID) -> list[Record]:
        return await conn.fetch(
            """
            SELECT id, source, external_id, category, severity, confidence, title, detected_at, received_at
              FROM ra_remediation.alerts WHERE incident_id = $1 ORDER BY received_at
            """,
            incident_id,
        )

    async def between(self, conn: Connection, start: datetime, end: datetime) -> list[Record]:
        return await conn.fetch(
            """
            SELECT received_at, category, confidence, incident_id
              FROM ra_remediation.alerts WHERE received_at BETWEEN $1 AND $2 ORDER BY received_at LIMIT 500
            """,
            start,
            end,
        )
