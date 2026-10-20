"""Orchestrateur : machine à états d'incident, tentatives, vérification, escalade.

    OPEN ─► TRIAGED ─► REMEDIATING ─► VERIFYING ─► RESOLVED
                           ▲   │           │
                           └───┴── échec ──┴──► ESCALATED (humain) ─► retry / verify

* une remédiation à la fois par service cible (verrou) ;
* garde anti-boucle (N remédiations / heure / cible) et délai de refroidissement ;
* aucune clôture sans vérification synthétique PASSED (garanti aussi par la base, RA203) ;
* reprise après redémarrage : exécutions RUNNING -> ABORTED puis reprise des incidents.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from datetime import UTC, datetime
from typing import Literal
from uuid import UUID

from ra_common.db import UNAVAILABLE_ERRORS, Database
from ra_common.logging import log_event

from app.connectors.registry import ActionRegistry
from app.domain.models import Incident, IncidentStatus, IntakeResult
from app.domain.playbooks import InvalidPlaybook, PlaybookSpec, parse_playbook
from app.observability import INCIDENTS, MTTR, QUEUE_DEPTH, REMEDIATION_DURATION
from app.repositories.incidents import IncidentRepository
from app.repositories.observations import PlaybookRepository
from app.repositories.runs import ExecutionRepository, VerificationRepository
from app.services.events import SupervisionEvents
from app.services.phases import PhaseTracker
from app.services.runner import PlaybookRunner
from app.services.verifier import SyntheticVerifier

logger = logging.getLogger("remediation.orchestrator")

Mode = Literal["auto", "retry", "verify"]
_RETRY_BACKOFF_SECONDS = 2.0


class Orchestrator:
    def __init__(
        self,
        *,
        db: Database,
        incidents: IncidentRepository,
        executions: ExecutionRepository,
        verifications: VerificationRepository,
        playbooks: PlaybookRepository,
        registry: ActionRegistry,
        runner: PlaybookRunner,
        verifier: SyntheticVerifier,
        events: SupervisionEvents,
        phases: PhaseTracker,
        workers: int,
        max_per_target_per_hour: int,
    ) -> None:
        self._db = db
        self._incidents = incidents
        self._executions = executions
        self._verifications = verifications
        self._playbooks = playbooks
        self._registry = registry
        self._runner = runner
        self._verifier = verifier
        self._events = events
        self._phases = phases
        self._worker_count = workers
        self._max_per_hour = max_per_target_per_hour
        self._queue: asyncio.Queue[tuple[UUID, Mode]] = asyncio.Queue()
        self._inflight: set[UUID] = set()
        self._notes: dict[UUID, str] = {}  # raison saisie par l'opérateur (retry / verify)
        self._target_locks: dict[str, asyncio.Lock] = {}
        self._workers: list[asyncio.Task[None]] = []

    # ---------------------------------------------------------------- cycle de vie
    async def start(self) -> None:
        await self._recover()
        self._workers = [asyncio.create_task(self._worker(), name=f"orchestrator-{i}") for i in range(self._worker_count)]

    async def stop(self) -> None:
        for task in self._workers:
            task.cancel()
        for task in self._workers:
            with contextlib.suppress(asyncio.CancelledError):
                await task

    def dispatch(self, result: IntakeResult) -> None:
        if not result.deduplicated and not result.replayed and result.incident_status is IncidentStatus.OPEN:
            self.enqueue(result.incident_id)

    def enqueue(self, incident_id: UUID, mode: Mode = "auto", note: str | None = None) -> None:
        if note:
            self._notes[incident_id] = note
        self._queue.put_nowait((incident_id, mode))
        QUEUE_DEPTH.set(self._queue.qsize())

    async def validate_catalog(self) -> list[str]:
        """Vérifie au démarrage que chaque playbook n'utilise que des actions autorisées."""
        problems: list[str] = []
        async with self._db.connection() as conn:
            rows = await self._playbooks.list(conn)
        for row in rows:
            try:
                parse_playbook(dict(row), self._registry.actions)
            except InvalidPlaybook as exc:
                problems.append(str(exc))
                log_event(logger, logging.ERROR, "playbook.invalid", "invalid playbook in catalog", problem=str(exc))
        return problems

    async def _recover(self) -> None:
        async with self._db.transaction() as conn:
            aborted = await self._executions.abort_running(conn)
            failed = await self._verifications.fail_running(conn)
            resumable = [
                incident
                for incident in await self._incidents.list_open(conn)
                if incident.status in (IncidentStatus.OPEN, IncidentStatus.TRIAGED, IncidentStatus.REMEDIATING, IncidentStatus.VERIFYING)
            ]
        for incident in resumable:
            self.enqueue(incident.id)
        if aborted or failed or resumable:
            log_event(
                logger,
                logging.WARNING,
                "orchestrator.recovered",
                "resuming interrupted work after restart",
                aborted_executions=aborted,
                failed_verifications=failed,
                resumed_incidents=len(resumable),
            )

    async def _worker(self) -> None:
        while True:
            incident_id, mode = await self._queue.get()
            QUEUE_DEPTH.set(self._queue.qsize())
            if incident_id in self._inflight:
                continue
            self._inflight.add(incident_id)
            try:
                await self._process(incident_id, mode)
            except asyncio.CancelledError:
                raise
            except UNAVAILABLE_ERRORS as exc:
                logger.warning("database unavailable while processing %s: %s", incident_id, exc.__class__.__name__)
                await asyncio.sleep(5)
                self.enqueue(incident_id, mode)
            except Exception:  # noqa: BLE001 - un incident ne doit jamais tuer le worker
                logger.exception("unexpected error while processing incident", extra={"event": "orchestrator.error"})
                with contextlib.suppress(Exception):
                    await self._escalate_by_id(incident_id, "internal error in remediation engine (see logs)")
            finally:
                self._inflight.discard(incident_id)

    # ------------------------------------------------------------------ traitement
    async def _load(self, incident_id: UUID) -> Incident | None:
        async with self._db.connection() as conn:
            return await self._incidents.get(conn, incident_id)

    async def _process(self, incident_id: UUID, mode: Mode) -> None:
        incident = await self._load(incident_id)
        if incident is None or incident.status.is_closed:
            return
        lock = self._target_locks.setdefault(incident.target_service, asyncio.Lock())
        async with lock:
            incident = await self._load(incident_id)
            if incident is None or incident.status.is_closed:
                return
            if mode == "verify":
                await self._manual_verify(incident)
                return
            if incident.status is IncidentStatus.ESCALATED and mode != "retry":
                return
            if incident.status is IncidentStatus.OPEN:
                incident = await self._triage(incident)
                if incident is None:
                    return
            playbook = await self._load_playbook(incident)
            if playbook is None:
                return
            if mode == "auto":
                await self._cooldown(incident, playbook)
            await self._remediate(incident, playbook, manual=mode == "retry")

    async def _triage(self, incident: Incident) -> Incident | None:
        async with self._db.connection() as conn:
            recent = await self._incidents.remediations_last_hour(conn, incident.target_service)
            row = await self._playbooks.active_for(conn, incident.category.value)
        if recent >= self._max_per_hour:
            await self._escalate(incident, f"loop guard: {recent} remediations on {incident.target_service} in the last hour")
            return None
        if row is None:
            await self._escalate(incident, f"no active playbook for {incident.category.value}")
            return None
        try:
            spec = parse_playbook(dict(row), self._registry.actions)
        except InvalidPlaybook as exc:
            await self._escalate(incident, str(exc))
            return None
        return await self._transition(incident, IncidentStatus.TRIAGED, f"playbook {spec.code} v{spec.version} selected", playbook_code=spec.code)

    async def _load_playbook(self, incident: Incident) -> PlaybookSpec | None:
        if incident.playbook_code is None:
            await self._escalate(incident, "no playbook associated with the incident")
            return None
        async with self._db.connection() as conn:
            row = await self._playbooks.get(conn, incident.playbook_code)
        try:
            return parse_playbook(dict(row), self._registry.actions)
        except (InvalidPlaybook, TypeError) as exc:
            await self._escalate(incident, f"playbook unusable: {exc}")
            return None

    async def _cooldown(self, incident: Incident, playbook: PlaybookSpec) -> None:
        async with self._db.connection() as conn:
            last = await self._incidents.last_execution_end(conn, incident.target_service, playbook.code)
        if last is None or playbook.cooldown_seconds <= 0:
            return
        remaining = playbook.cooldown_seconds - (datetime.now(UTC) - last).total_seconds()
        if remaining > 0:
            log_event(
                logger,
                logging.INFO,
                "orchestrator.cooldown",
                f"waiting {remaining:.0f}s cooldown before {playbook.code}",
                incident_id=str(incident.id),
            )
            await asyncio.sleep(remaining)

    async def _remediate(self, incident: Incident, playbook: PlaybookSpec, *, manual: bool) -> None:
        attempt = incident.attempt_count
        limit = attempt + playbook.max_attempts if manual else playbook.max_attempts
        if attempt >= limit:
            await self._escalate(incident, f"remediation attempts exhausted ({attempt}/{limit})")
            return

        while attempt < limit:
            attempt += 1
            started = time.perf_counter()
            reason = f"attempt {attempt}/{limit} with {playbook.code}"
            if manual and attempt == incident.attempt_count + 1 and incident.id in self._notes:
                reason = f"{self._notes.pop(incident.id)} ({reason})"
            if incident.status is IncidentStatus.REMEDIATING:
                async with self._db.transaction() as conn:
                    await self._incidents.set_attempt(conn, incident.id, attempt, None)
            else:
                incident = await self._transition(incident, IncidentStatus.REMEDIATING, reason, attempt_count=attempt)

            async with self._db.transaction() as conn:
                execution_id = await self._executions.create(
                    conn,
                    incident_id=incident.id,
                    playbook_code=playbook.code,
                    playbook_version=playbook.version,
                    attempt=attempt,
                )
            outcome = await self._runner.run_steps(
                incident=incident, playbook=playbook, execution_id=execution_id, steps=playbook.steps, phase="REMEDIATION"
            )
            if not outcome.ok:
                await self._finish_execution(execution_id, "FAILED", outcome.error)
                REMEDIATION_DURATION.labels(playbook=playbook.code).observe(time.perf_counter() - started)
                if outcome.fatal or attempt >= limit:
                    await self._escalate(incident, f"remediation failed: {outcome.error}", last_error=outcome.error)
                    return
                async with self._db.transaction() as conn:
                    await self._incidents.set_attempt(conn, incident.id, attempt, outcome.error)
                await asyncio.sleep(_RETRY_BACKOFF_SECONDS)
                continue

            incident = await self._transition(
                incident, IncidentStatus.VERIFYING, "remediation steps completed; running end-to-end synthetic verification"
            )
            verification = await self._verifier.run(
                incident_id=incident.id, execution_id=execution_id, trigger_source="REMEDIATION"
            )
            if verification.passed:
                post = await self._runner.run_steps(
                    incident=incident,
                    playbook=playbook,
                    execution_id=execution_id,
                    steps=playbook.post_verification_steps,
                    phase="POST_VERIFICATION",
                )
                if not post.ok:
                    await self._finish_execution(execution_id, "FAILED", post.error)
                    await self._escalate(incident, f"post-verification step failed: {post.error}", last_error=post.error)
                    return
                await self._finish_execution(execution_id, "SUCCEEDED")
                REMEDIATION_DURATION.labels(playbook=playbook.code).observe(time.perf_counter() - started)
                await self._resolve(incident, "MANUAL" if manual else "AUTOMATIC")
                return

            error = f"synthetic verification failed at {verification.failed_check}"
            await self._finish_execution(execution_id, "FAILED", error)
            REMEDIATION_DURATION.labels(playbook=playbook.code).observe(time.perf_counter() - started)
            if attempt >= limit:
                await self._escalate(incident, error, last_error=error)
                return
            incident = await self._transition(
                incident, IncidentStatus.REMEDIATING, f"{error}; retrying", attempt_count=attempt, last_error=error
            )
            await asyncio.sleep(_RETRY_BACKOFF_SECONDS)

    async def _manual_verify(self, incident: Incident) -> None:
        if incident.status is not IncidentStatus.ESCALATED:
            return
        note = self._notes.pop(incident.id, "operator: manual verification requested")
        incident = await self._transition(incident, IncidentStatus.VERIFYING, note)
        verification = await self._verifier.run(incident_id=incident.id, execution_id=None, trigger_source="MANUAL")
        if not verification.passed:
            await self._escalate(incident, f"manual verification failed at {verification.failed_check}")
            return
        if incident.playbook_code:
            playbook = await self._load_playbook(incident)
            if playbook and playbook.post_verification_steps:
                attempt = incident.attempt_count + 1
                async with self._db.transaction() as conn:
                    await self._incidents.set_attempt(conn, incident.id, attempt, None)
                    execution_id = await self._executions.create(
                        conn,
                        incident_id=incident.id,
                        playbook_code=playbook.code,
                        playbook_version=playbook.version,
                        attempt=attempt,
                    )
                post = await self._runner.run_steps(
                    incident=incident,
                    playbook=playbook,
                    execution_id=execution_id,
                    steps=playbook.post_verification_steps,
                    phase="POST_VERIFICATION",
                )
                await self._finish_execution(execution_id, "SUCCEEDED" if post.ok else "FAILED", post.error)
                if not post.ok:
                    await self._escalate(incident, f"post-verification step failed: {post.error}")
                    return
        await self._resolve(incident, "MANUAL")

    # ------------------------------------------------------------------- helpers
    async def _finish_execution(self, execution_id: UUID, status: str, error: str | None = None) -> None:
        async with self._db.transaction() as conn:
            await self._executions.finish(conn, execution_id, status, error)

    async def _transition(self, incident: Incident, status: IncidentStatus, reason: str, **fields) -> Incident:
        async with self._db.transaction() as conn:
            updated = await self._incidents.transition(conn, incident.id, status, reason, **fields)
        self._events.publish(
            "incident.status_changed",
            {"from": incident.status.value, "to": status.value, "reason": reason, "attempt": updated.attempt_count},
            incident.id,
        )
        log_event(
            logger,
            logging.INFO,
            "incident.status_changed",
            f"incident {incident.status.value} -> {status.value}",
            incident_id=str(incident.id),
            reason=reason,
        )
        await self._phases.refresh()
        return updated

    async def _resolve(self, incident: Incident, resolution: str) -> None:
        resolved = await self._transition(
            incident, IncidentStatus.RESOLVED, "end-to-end synthetic verification passed", resolution=resolution
        )
        mttr = (resolved.closed_at - resolved.opened_at).total_seconds() if resolved.closed_at else None
        if mttr is not None:
            MTTR.observe(mttr)
        INCIDENTS.labels(category=incident.category.value, outcome="RESOLVED").inc()
        self._events.publish(
            "incident.closed",
            {"status": "RESOLVED", "resolution": resolution, "mttr_seconds": round(mttr, 1) if mttr else None},
            incident.id,
        )

    async def _escalate(self, incident: Incident, reason: str, *, last_error: str | None = None) -> None:
        current = await self._load(incident.id)
        if current is None or current.status in (IncidentStatus.ESCALATED, IncidentStatus.RESOLVED, IncidentStatus.SUPPRESSED):
            return
        await self._transition(current, IncidentStatus.ESCALATED, reason, last_error=last_error or reason)
        INCIDENTS.labels(category=incident.category.value, outcome="ESCALATED").inc()
        log_event(
            logger,
            logging.CRITICAL,
            "incident.escalated",
            "automatic remediation exhausted: human action required",
            incident_id=str(incident.id),
            reason=reason,
        )

    async def _escalate_by_id(self, incident_id: UUID, reason: str) -> None:
        incident = await self._load(incident_id)
        if incident is not None:
            await self._escalate(incident, reason)
