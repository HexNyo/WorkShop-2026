"""Suivi de la phase système (NOMINAL / DEGRADED / CRITICAL / RECOVERING / RESTORED)."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from uuid import UUID

from ra_common.db import Database
from ra_common.logging import log_event

from app.domain.models import Phase, ServiceStatus
from app.domain.phase import OpenIncident, compute_phase
from app.observability import PHASE
from app.repositories.incidents import IncidentRepository
from app.repositories.observations import PhaseRepository
from app.services.events import SupervisionEvents

logger = logging.getLogger("remediation.phases")


class PhaseTracker:
    def __init__(
        self,
        *,
        db: Database,
        incidents: IncidentRepository,
        phases: PhaseRepository,
        events: SupervisionEvents,
        restored_hold_seconds: int,
    ) -> None:
        self._db = db
        self._incidents = incidents
        self._phases = phases
        self._events = events
        self._hold = timedelta(seconds=restored_hold_seconds)
        self._health: Callable[[], Mapping[str, ServiceStatus]] = dict
        self._lock = asyncio.Lock()
        self.phase = Phase.NOMINAL
        self.since = datetime.now(UTC)
        self.incident_id: UUID | None = None

    def bind_health(self, provider: Callable[[], Mapping[str, ServiceStatus]]) -> None:
        self._health = provider

    async def load(self) -> None:
        async with self._db.connection() as conn:
            row = await self._phases.current(conn)
        if row:
            self.phase, self.since = Phase(row["phase"]), row["entered_at"]
            self.incident_id = UUID(str(row["incident_id"])) if row["incident_id"] else None
        self._gauge()

    async def refresh(self) -> None:
        async with self._lock:
            async with self._db.connection() as conn:
                open_incidents = await self._incidents.list_open(conn)
                last = await self._incidents.last_resolved(conn)
            decision = compute_phase(
                open_incidents=[
                    OpenIncident(item.id, item.status, item.severity, item.target_service, item.opened_at)
                    for item in open_incidents
                ],
                health=self._health(),
                last_resolved_at=last[1] if last else None,
                last_resolved_id=last[0] if last else None,
                now=datetime.now(UTC),
                restored_hold=self._hold,
            )
            if decision.phase is self.phase:
                return
            previous = self.phase
            async with self._db.transaction() as conn:
                self.since = await self._phases.add(conn, decision.phase.value, decision.incident_id, decision.reason)
            self.phase, self.incident_id = decision.phase, decision.incident_id
            self._gauge()
        self._events.publish(
            "system.phase_changed",
            {"phase": decision.phase.value, "previous": previous.value, "reason": decision.reason},
            decision.incident_id,
        )
        log_event(
            logger,
            logging.WARNING if decision.phase in (Phase.CRITICAL, Phase.DEGRADED) else logging.INFO,
            "system.phase_changed",
            f"system phase {previous.value} -> {decision.phase.value}",
            reason=decision.reason,
            incident_id=str(decision.incident_id) if decision.incident_id else None,
        )

    def _gauge(self) -> None:
        for phase in Phase:
            PHASE.labels(phase=phase.value).set(1 if phase is self.phase else 0)
