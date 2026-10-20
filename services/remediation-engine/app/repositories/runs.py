"""Exécutions de playbooks (pas-à-pas) et vérifications synthétiques."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

import asyncpg


class ExecutionRepository:
    async def create(
        self, conn: asyncpg.Connection, *, incident_id: UUID, playbook_code: str, playbook_version: int, attempt: int
    ) -> UUID:
        value = await conn.fetchval(
            """
            INSERT INTO remediation.executions (incident_id, playbook_code, playbook_version, attempt)
            VALUES ($1, $2, $3, $4) RETURNING id
            """,
            incident_id,
            playbook_code,
            playbook_version,
            attempt,
        )
        return UUID(str(value))

    async def finish(self, conn: asyncpg.Connection, execution_id: UUID, status: str, error: str | None = None) -> None:
        await conn.execute(
            """
            UPDATE remediation.executions
               SET status = $2::remediation.execution_status, finished_at = clock_timestamp(), error = $3
             WHERE id = $1 AND status = 'RUNNING'
            """,
            execution_id,
            status,
            error[:1024] if error else None,
        )

    async def abort_running(self, conn: asyncpg.Connection) -> int:
        result = await conn.execute(
            """
            UPDATE remediation.executions
               SET status = 'ABORTED', finished_at = clock_timestamp(), error = 'engine restarted during execution'
             WHERE status = 'RUNNING'
            """
        )
        return int(result.split()[-1])

    async def add_step(
        self,
        conn: asyncpg.Connection,
        *,
        execution_id: UUID,
        phase: str,
        seq: int,
        action: str,
        target: str | None,
        params: dict[str, Any],
        status: str,
    ) -> int:
        return await conn.fetchval(
            """
            INSERT INTO remediation.execution_steps (execution_id, phase, seq, action, target, params, status, started_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7::remediation.step_status,
                    CASE WHEN $7 = 'RUNNING' THEN clock_timestamp() END)
            RETURNING id
            """,
            execution_id,
            phase,
            seq,
            action,
            target,
            params,
            status,
        )

    async def finish_step(
        self,
        conn: asyncpg.Connection,
        step_id: int,
        *,
        status: str,
        duration_ms: int | None,
        output: dict[str, Any] | None,
        error: str | None,
    ) -> None:
        await conn.execute(
            """
            UPDATE remediation.execution_steps
               SET status = $2::remediation.step_status, finished_at = clock_timestamp(), duration_ms = $3,
                   output = $4, error = $5
             WHERE id = $1
            """,
            step_id,
            status,
            duration_ms,
            output,
            error[:1024] if error else None,
        )

    async def for_incident(self, conn: asyncpg.Connection, incident_id: UUID) -> list[asyncpg.Record]:
        return await conn.fetch(
            """
            SELECT e.id, e.attempt, e.status::text AS status, e.playbook_code, e.playbook_version,
                   e.started_at, e.finished_at, e.error,
                   COALESCE(jsonb_agg(jsonb_build_object(
                       'phase', s.phase, 'seq', s.seq, 'action', s.action, 'target', s.target,
                       'status', s.status, 'duration_ms', s.duration_ms, 'output', s.output, 'error', s.error,
                       'started_at', s.started_at, 'finished_at', s.finished_at)
                     ORDER BY s.phase DESC, s.seq) FILTER (WHERE s.id IS NOT NULL), '[]') AS steps
              FROM remediation.executions e
              LEFT JOIN remediation.execution_steps s ON s.execution_id = e.id
             WHERE e.incident_id = $1
             GROUP BY e.id
             ORDER BY e.attempt
            """,
            incident_id,
        )


class VerificationRepository:
    async def create(
        self, conn: asyncpg.Connection, *, incident_id: UUID | None, execution_id: UUID | None, trigger_source: str
    ) -> UUID:
        value = await conn.fetchval(
            """
            INSERT INTO remediation.verification_runs (incident_id, execution_id, trigger_source)
            VALUES ($1, $2, $3) RETURNING id
            """,
            incident_id,
            execution_id,
            trigger_source,
        )
        return UUID(str(value))

    async def add_check(
        self,
        conn: asyncpg.Connection,
        *,
        run_id: UUID,
        seq: int,
        code: str,
        passed: bool,
        latency_ms: int | None,
        detail: dict[str, Any],
    ) -> None:
        await conn.execute(
            """
            INSERT INTO remediation.verification_checks (run_id, seq, check_code, passed, latency_ms, detail)
            VALUES ($1, $2, $3, $4, $5, $6)
            """,
            run_id,
            seq,
            code,
            passed,
            latency_ms,
            detail,
        )

    async def finish(
        self,
        conn: asyncpg.Connection,
        run_id: UUID,
        *,
        passed: bool,
        failed_check: str | None,
        transaction_ids: list[UUID],
    ) -> datetime:
        return await conn.fetchval(
            """
            UPDATE remediation.verification_runs
               SET status = $2::remediation.verification_status, finished_at = clock_timestamp(),
                   failed_check = $3, synthetic_transaction_ids = $4
             WHERE id = $1
         RETURNING finished_at
            """,
            run_id,
            "PASSED" if passed else "FAILED",
            None if passed else failed_check,
            transaction_ids,
        )

    async def fail_running(self, conn: asyncpg.Connection) -> int:
        result = await conn.execute(
            """
            UPDATE remediation.verification_runs
               SET status = 'FAILED', finished_at = clock_timestamp(), failed_check = 'ENGINE_RESTART'
             WHERE status = 'RUNNING'
            """
        )
        return int(result.split()[-1])

    async def latest(self, conn: asyncpg.Connection) -> asyncpg.Record | None:
        return await conn.fetchrow(
            """
            SELECT id, incident_id, trigger_source, status::text AS status, failed_check, started_at, finished_at
              FROM remediation.verification_runs WHERE status <> 'RUNNING'
             ORDER BY started_at DESC LIMIT 1
            """
        )

    async def for_incident(self, conn: asyncpg.Connection, incident_id: UUID) -> list[asyncpg.Record]:
        return await conn.fetch(
            """
            SELECT r.id, r.trigger_source, r.status::text AS status, r.failed_check, r.started_at, r.finished_at,
                   r.synthetic_transaction_ids,
                   COALESCE(jsonb_agg(jsonb_build_object(
                       'seq', c.seq, 'code', c.check_code, 'passed', c.passed,
                       'latency_ms', c.latency_ms, 'detail', c.detail) ORDER BY c.seq)
                     FILTER (WHERE c.id IS NOT NULL), '[]') AS checks
              FROM remediation.verification_runs r
              LEFT JOIN remediation.verification_checks c ON c.run_id = r.id
             WHERE r.incident_id = $1
             GROUP BY r.id
             ORDER BY r.started_at
            """,
            incident_id,
        )

    async def completed_between(self, conn: asyncpg.Connection, start: datetime, end: datetime) -> list[asyncpg.Record]:
        return await conn.fetch(
            """
            SELECT r.finished_at, r.status::text AS status, r.incident_id, r.trigger_source,
                   count(c.id) FILTER (WHERE c.passed) AS passed_checks, count(c.id) AS total_checks
              FROM remediation.verification_runs r
              LEFT JOIN remediation.verification_checks c ON c.run_id = r.id
             WHERE r.finished_at BETWEEN $1 AND $2 AND r.trigger_source <> 'SCHEDULED'
             GROUP BY r.id
             ORDER BY r.finished_at
            """,
            start,
            end,
        )
