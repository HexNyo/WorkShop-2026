"""Réception des alertes : idempotence, déduplication par empreinte, ouverture d'incident."""

from __future__ import annotations

import logging
from collections.abc import Callable

import asyncpg
from ra_common.db import Database
from ra_common.logging import log_event

from app.domain.models import AlertSubmission, IncidentStatus, IntakeResult, Severity
from app.observability import ALERTS, INCIDENTS
from app.repositories.incidents import AlertRepository, IncidentRepository
from app.services.events import SupervisionEvents
from app.services.phases import PhaseTracker

logger = logging.getLogger("remediation.intake")


class AlertIntake:
    def __init__(
        self,
        *,
        db: Database,
        incidents: IncidentRepository,
        alerts: AlertRepository,
        events: SupervisionEvents,
        phases: PhaseTracker,
        min_confidence: float,
    ) -> None:
        self._db = db
        self._incidents = incidents
        self._alerts = alerts
        self._events = events
        self._phases = phases
        self._min_confidence = min_confidence
        self._dispatch: Callable[[IntakeResult], None] = lambda _: None

    def bind_dispatcher(self, dispatch: Callable[[IntakeResult], None]) -> None:
        self._dispatch = dispatch

    async def submit(self, alert: AlertSubmission) -> IntakeResult:
        try:
            result = await self._submit(alert)
        except asyncpg.UniqueViolationError:
            # Course entre deux livraisons simultanées : la seconde devient un rejeu / doublon.
            result = await self._submit(alert)
        if result.replayed:
            return result

        ALERTS.labels(source=alert.source, category=alert.category.value, deduplicated=str(result.deduplicated).lower()).inc()
        self._events.publish(
            "alert.received",
            {
                "alert_id": str(result.alert_id),
                "source": alert.source,
                "category": alert.category.value,
                "severity": alert.severity.value,
                "confidence": alert.confidence,
                "title": alert.title,
                "deduplicated": result.deduplicated,
            },
            result.incident_id,
        )
        if not result.deduplicated:
            self._events.publish(
                "incident.opened",
                {
                    "title": alert.title,
                    "category": alert.category.value,
                    "severity": alert.severity.value,
                    "target_service": alert.target_service,
                    "playbook_code": None,
                },
                result.incident_id,
            )
        if result.incident_status is IncidentStatus.SUPPRESSED:
            INCIDENTS.labels(category=alert.category.value, outcome="SUPPRESSED").inc()
            self._events.publish(
                "incident.closed", {"status": "SUPPRESSED", "resolution": "SUPPRESSED", "mttr_seconds": None}, result.incident_id
            )
        log_event(
            logger,
            logging.WARNING,
            "alert.received",
            "alert received",
            source=alert.source,
            external_id=alert.external_id,
            category=alert.category.value,
            severity=alert.severity.value,
            incident_id=str(result.incident_id),
            deduplicated=result.deduplicated,
        )
        await self._phases.refresh()
        self._dispatch(result)
        return result

    async def _submit(self, alert: AlertSubmission) -> IntakeResult:
        async with self._db.transaction() as conn:
            existing = await self._alerts.find(conn, alert.source, alert.external_id)
            if existing is not None:
                return IntakeResult(
                    alert_id=existing["id"],
                    incident_id=existing["incident_id"],
                    deduplicated=bool(existing["deduplicated"]),
                    incident_status=IncidentStatus(existing["incident_status"]),
                    replayed=True,
                )
            # Sérialise les alertes d'une même empreinte (déduplication sans course).
            await conn.execute("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", alert.fingerprint)
            incident = await self._incidents.find_open(conn, alert.fingerprint)
            if incident is not None:
                alert_id = await self._alerts.insert(conn, alert, incident.id)
                await self._incidents.absorb_duplicate(conn, incident.id, alert.severity)
                return IntakeResult(
                    alert_id=alert_id, incident_id=incident.id, deduplicated=True, incident_status=incident.status
                )

            incident_id = await self._incidents.create(conn, alert, reason=f"alert {alert.external_id} from {alert.source}")
            alert_id = await self._alerts.insert(conn, alert, incident_id)
            status = IncidentStatus.OPEN
            low_confidence = alert.confidence is not None and alert.confidence < self._min_confidence
            if alert.severity is Severity.INFO or low_confidence:
                reason = "informational alert" if alert.severity is Severity.INFO else (
                    f"confidence {alert.confidence:.2f} below threshold {self._min_confidence:.2f}"
                )
                await self._incidents.transition(conn, incident_id, IncidentStatus.SUPPRESSED, reason)
                status = IncidentStatus.SUPPRESSED
            return IntakeResult(alert_id=alert_id, incident_id=incident_id, deduplicated=False, incident_status=status)
