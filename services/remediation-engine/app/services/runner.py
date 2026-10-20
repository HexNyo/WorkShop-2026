"""Exécution pas-à-pas des étapes d'un playbook, tracée en base et diffusée en temps réel."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Sequence
from dataclasses import dataclass
from uuid import UUID

from ra_common.db import Database
from ra_common.logging import log_event

from app.connectors.base import ActionError, StepContext
from app.connectors.registry import ActionRegistry
from app.domain.models import Incident
from app.domain.playbooks import PlaybookSpec, StepSpec, UnresolvedTemplate, render
from app.repositories.runs import ExecutionRepository
from app.services.events import SupervisionEvents

logger = logging.getLogger("remediation.runner")


@dataclass(frozen=True, slots=True)
class StepsOutcome:
    ok: bool
    error: str | None = None
    fatal: bool = False


class PlaybookRunner:
    def __init__(
        self, *, db: Database, executions: ExecutionRepository, registry: ActionRegistry, events: SupervisionEvents
    ) -> None:
        self._db = db
        self._executions = executions
        self._registry = registry
        self._events = events

    async def run_steps(
        self,
        *,
        incident: Incident,
        playbook: PlaybookSpec,
        execution_id: UUID,
        steps: Sequence[StepSpec],
        phase: str,
    ) -> StepsOutcome:
        context = incident.template_context()
        for seq, step in enumerate(steps, start=1):
            try:
                target = render(step.target, context)
                params = render(step.params, context)
            except UnresolvedTemplate as exc:
                status = "SKIPPED" if step.optional else "FAILED"
                error = f"unresolved template variable {exc.args[0]}"
                await self._record_instant(execution_id, phase, seq, step, status, error, incident.id)
                if step.optional:
                    continue
                return StepsOutcome(ok=False, error=f"step {seq} {step.action}: {error}", fatal=True)

            async with self._db.transaction() as conn:
                step_id = await self._executions.add_step(
                    conn,
                    execution_id=execution_id,
                    phase=phase,
                    seq=seq,
                    action=step.action,
                    target=target,
                    params=params,
                    status="RUNNING",
                )
            self._publish(execution_id, phase, seq, step.action, target, "RUNNING", incident.id)

            started = time.perf_counter()
            ctx = StepContext(incident=incident, playbook_code=playbook.code, seq=seq, phase=phase)
            output: dict | None = None
            error: str | None = None
            fatal = False
            try:
                output = await asyncio.wait_for(
                    self._registry.run(ctx, step.action, target, params), timeout=playbook.step_timeout_seconds
                )
                status = "SUCCEEDED"
            except ActionError as exc:
                status, error, fatal, output = "FAILED", str(exc), exc.fatal, exc.output
            except TimeoutError:
                status, error = "FAILED", f"timed out after {playbook.step_timeout_seconds}s"
            duration = int((time.perf_counter() - started) * 1000)

            async with self._db.transaction() as conn:
                await self._executions.finish_step(
                    conn, step_id, status=status, duration_ms=duration, output=output, error=error
                )
            self._publish(execution_id, phase, seq, step.action, target, status, incident.id, duration, output, error)
            log_event(
                logger,
                logging.INFO if status == "SUCCEEDED" else logging.WARNING,
                "remediation.step",
                f"{step.action} {status.lower()}",
                incident_id=str(incident.id),
                playbook=playbook.code,
                phase=phase,
                seq=seq,
                target=target,
                duration_ms=duration,
                error=error,
            )
            if status == "FAILED":
                return StepsOutcome(ok=False, error=f"step {seq} {step.action}: {error}", fatal=fatal)
        return StepsOutcome(ok=True)

    async def _record_instant(
        self, execution_id: UUID, phase: str, seq: int, step: StepSpec, status: str, error: str, incident_id: UUID
    ) -> None:
        async with self._db.transaction() as conn:
            step_id = await self._executions.add_step(
                conn,
                execution_id=execution_id,
                phase=phase,
                seq=seq,
                action=step.action,
                target=step.target,
                params=step.params,
                status="PENDING",
            )
            await self._executions.finish_step(conn, step_id, status=status, duration_ms=0, output=None, error=error)
        self._publish(execution_id, phase, seq, step.action, step.target, status, incident_id, 0, None, error)

    def _publish(
        self,
        execution_id: UUID,
        phase: str,
        seq: int,
        action: str,
        target: str | None,
        status: str,
        incident_id: UUID,
        duration_ms: int | None = None,
        output: dict | None = None,
        error: str | None = None,
    ) -> None:
        self._events.publish(
            "remediation.step",
            {
                "execution_id": str(execution_id),
                "phase": phase,
                "seq": seq,
                "action": action,
                "target": target,
                "status": status,
                "duration_ms": duration_ms,
                "output": output,
                "error": error,
            },
            incident_id,
        )
