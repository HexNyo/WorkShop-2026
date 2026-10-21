"""Exécutions de playbooks (pas-à-pas) et vérifications synthétiques."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from ra_common.db import Connection, Record, json_value


def _placeholders(count: int) -> str:
    return ", ".join(f"${index}" for index in range(1, count + 1))


class ExecutionRepository:
    async def create(
        self, conn: Connection, *, incident_id: UUID, playbook_code: str, playbook_version: int, attempt: int
    ) -> UUID:
        execution_id = uuid4()
        await conn.execute(
            """
            INSERT INTO ra_remediation.executions (id, incident_id, playbook_code, playbook_version, attempt)
            VALUES ($1, $2, $3, $4, $5)
            """,
            execution_id,
            incident_id,
            playbook_code,
            playbook_version,
            attempt,
        )
        return execution_id

    async def finish(self, conn: Connection, execution_id: UUID, status: str, error: str | None = None) -> None:
        await conn.execute(
            """
            UPDATE ra_remediation.executions
               SET status = $2, finished_at = SYSDATE(6), error = $3
             WHERE id = $1 AND status = 'RUNNING'
            """,
            execution_id,
            status,
            error[:1024] if error else None,
        )

    async def abort_running(self, conn: Connection) -> int:
        result = await conn.execute(
            """
            UPDATE ra_remediation.executions
               SET status = 'ABORTED', finished_at = SYSDATE(6), error = 'engine restarted during execution'
             WHERE status = 'RUNNING'
            """
        )
        return int(result.split()[-1])

    async def add_step(
        self,
        conn: Connection,
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
            INSERT INTO ra_remediation.execution_steps (execution_id, phase, seq, action, target, params, status, started_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, CASE WHEN $7 = 'RUNNING' THEN SYSDATE(6) END)
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
        conn: Connection,
        step_id: int,
        *,
        status: str,
        duration_ms: int | None,
        output: dict[str, Any] | None,
        error: str | None,
    ) -> None:
        await conn.execute(
            """
            UPDATE ra_remediation.execution_steps
               SET status = $2, finished_at = SYSDATE(6), duration_ms = $3, output = $4, error = $5
             WHERE id = $1
            """,
            step_id,
            status,
            duration_ms,
            output,
            error[:1024] if error else None,
        )

    async def for_incident(self, conn: Connection, incident_id: UUID) -> list[Record]:
        executions = await conn.fetch(
            """
            SELECT id, attempt, status, playbook_code, playbook_version, started_at, finished_at, error
              FROM ra_remediation.executions WHERE incident_id = $1 ORDER BY attempt
            """,
            incident_id,
        )
        if not executions:
            return []
        steps = await conn.fetch(
            f"""
            SELECT execution_id, phase, seq, action, target, status, duration_ms, output, error, started_at, finished_at
              FROM ra_remediation.execution_steps
             WHERE execution_id IN ({_placeholders(len(executions))})
             ORDER BY phase DESC, seq
            """,
            *(execution["id"] for execution in executions),
        )
        by_execution: dict[UUID, list[Record]] = {}
        for step in steps:
            execution_id = step.pop("execution_id")
            by_execution.setdefault(execution_id, []).append({**step, "output": json_value(step["output"])})
        return [{**execution, "steps": by_execution.get(execution["id"], [])} for execution in executions]


class VerificationRepository:
    async def create(
        self, conn: Connection, *, incident_id: UUID | None, execution_id: UUID | None, trigger_source: str
    ) -> UUID:
        run_id = uuid4()
        await conn.execute(
            """
            INSERT INTO ra_remediation.verification_runs (id, incident_id, execution_id, trigger_source)
            VALUES ($1, $2, $3, $4)
            """,
            run_id,
            incident_id,
            execution_id,
            trigger_source,
        )
        return run_id

    async def add_check(
        self,
        conn: Connection,
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
            INSERT INTO ra_remediation.verification_checks (run_id, seq, check_code, passed, latency_ms, detail)
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
        conn: Connection,
        run_id: UUID,
        *,
        passed: bool,
        failed_check: str | None,
        transaction_ids: list[UUID],
    ) -> datetime:
        await conn.execute(
            """
            UPDATE ra_remediation.verification_runs
               SET status = $2, finished_at = SYSDATE(6), failed_check = $3, synthetic_transaction_ids = $4
             WHERE id = $1
            """,
            run_id,
            "PASSED" if passed else "FAILED",
            None if passed else failed_check,
            list(transaction_ids),
        )
        return await conn.fetchval("SELECT finished_at FROM ra_remediation.verification_runs WHERE id = $1", run_id)

    async def fail_running(self, conn: Connection) -> int:
        result = await conn.execute(
            """
            UPDATE ra_remediation.verification_runs
               SET status = 'FAILED', finished_at = SYSDATE(6), failed_check = 'ENGINE_RESTART'
             WHERE status = 'RUNNING'
            """
        )
        return int(result.split()[-1])

    async def latest(self, conn: Connection) -> Record | None:
        return await conn.fetchrow(
            """
            SELECT id, incident_id, trigger_source, status, failed_check, started_at, finished_at
              FROM ra_remediation.verification_runs WHERE status <> 'RUNNING'
             ORDER BY started_at DESC LIMIT 1
            """
        )

    async def for_incident(self, conn: Connection, incident_id: UUID) -> list[Record]:
        runs = await conn.fetch(
            """
            SELECT id, trigger_source, status, failed_check, started_at, finished_at, synthetic_transaction_ids
              FROM ra_remediation.verification_runs WHERE incident_id = $1 ORDER BY started_at
            """,
            incident_id,
        )
        if not runs:
            return []
        checks = await conn.fetch(
            f"""
            SELECT run_id, seq, check_code AS code, passed, latency_ms, detail
              FROM ra_remediation.verification_checks
             WHERE run_id IN ({_placeholders(len(runs))})
             ORDER BY seq
            """,
            *(run["id"] for run in runs),
        )
        by_run: dict[UUID, list[Record]] = {}
        for check in checks:
            run_id = check.pop("run_id")
            by_run.setdefault(run_id, []).append({**check, "detail": json_value(check["detail"])})
        return [
            {**run, "synthetic_transaction_ids": json_value(run["synthetic_transaction_ids"]), "checks": by_run.get(run["id"], [])}
            for run in runs
        ]

    async def completed_between(self, conn: Connection, start: datetime, end: datetime) -> list[Record]:
        return await conn.fetch(
            """
            SELECT r.finished_at, r.status, r.incident_id, r.trigger_source,
                   COUNT(CASE WHEN c.passed THEN 1 END) AS passed_checks, COUNT(c.id) AS total_checks
              FROM ra_remediation.verification_runs r
              LEFT JOIN ra_remediation.verification_checks c ON c.run_id = r.id
             WHERE r.finished_at BETWEEN $1 AND $2 AND r.trigger_source <> 'SCHEDULED'
             GROUP BY r.id
             ORDER BY r.finished_at
            """,
            start,
            end,
        )
