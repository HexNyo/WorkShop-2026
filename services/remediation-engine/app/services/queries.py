"""Modèles de lecture pour la console de supervision et le pilotage."""

from __future__ import annotations

from datetime import datetime, timedelta
from uuid import UUID

from ra_common.db import Database

from app.api.schemas import (
    AlertOut,
    CheckOut,
    Counters,
    ExecutionOut,
    HealthHistory,
    HealthPoint,
    HealthSeries,
    IncidentDetail,
    IncidentSummary,
    IncidentTarget,
    LastVerification,
    Marker,
    Overview,
    Segment,
    ServiceOut,
    StepOut,
    Timeline,
    TransitionOut,
    VerificationOut,
)
from app.domain.models import Incident, IncidentStatus
from app.repositories.incidents import AlertRepository, IncidentRepository
from app.repositories.observations import HealthRepository, PhaseRepository
from app.repositories.runs import ExecutionRepository, VerificationRepository
from app.services.events import SupervisionEvents
from app.services.monitor import HealthMonitor
from app.services.phases import PhaseTracker


def _mttr(incident: Incident) -> float | None:
    if incident.closed_at is None:
        return None
    return round((incident.closed_at - incident.opened_at).total_seconds(), 1)


def summary(incident: Incident) -> IncidentSummary:
    return IncidentSummary(
        id=incident.id,
        title=incident.title,
        category=incident.category.value,
        severity=incident.severity.value,
        status=incident.status.value,
        status_reason=incident.status_reason,
        target_service=incident.target_service,
        playbook_code=incident.playbook_code,
        attempt=incident.attempt_count,
        alert_count=incident.alert_count,
        resolution=incident.resolution,
        opened_at=incident.opened_at,
        closed_at=incident.closed_at,
        mttr_seconds=_mttr(incident),
    )


class SupervisionQueries:
    def __init__(
        self,
        *,
        db: Database,
        incidents: IncidentRepository,
        alerts: AlertRepository,
        executions: ExecutionRepository,
        verifications: VerificationRepository,
        health: HealthRepository,
        phases_repository: PhaseRepository,
        phases: PhaseTracker,
        monitor: HealthMonitor,
        events: SupervisionEvents,
    ) -> None:
        self._db = db
        self._incidents = incidents
        self._alerts = alerts
        self._executions = executions
        self._verifications = verifications
        self._health = health
        self._phase_repository = phases_repository
        self._phases = phases
        self._monitor = monitor
        self._events = events

    async def overview(self) -> Overview:
        async with self._db.connection() as conn:
            open_incidents = await self._incidents.list_open(conn)
            counters = await self._incidents.counters(conn)
            latest = await self._verifications.latest(conn)
        active = max(open_incidents, key=lambda item: (item.severity.rank, item.opened_at), default=None)
        services = [
            ServiceOut(name=item.service, status=item.status.value, latency_ms=item.latency_ms, checked_at=item.checked_at, detail=item.detail)
            for item in sorted(self._monitor.health.values(), key=lambda item: item.service)
        ]
        return Overview(
            phase=self._phases.phase.value,
            phase_since=self._phases.since,
            phase_incident_id=self._phases.incident_id,
            active_incident=summary(active) if active else None,
            services=services,
            counters=Counters(
                open_incidents=counters["open_incidents"],
                resolved_24h=counters["resolved_24h"],
                escalated_24h=counters["escalated_24h"],
                mttr_p50_seconds=round(counters["mttr_p50"], 1) if counters["mttr_p50"] is not None else None,
            ),
            last_verification=LastVerification(
                run_id=latest["id"],
                status=latest["status"],
                trigger_source=latest["trigger_source"],
                failed_check=latest["failed_check"],
                finished_at=latest["finished_at"],
            )
            if latest
            else None,
            stream_seq=self._events.last_seq,
        )

    async def incidents(
        self, *, status: IncidentStatus | None, before: tuple[datetime, UUID] | None, limit: int
    ) -> list[Incident]:
        async with self._db.connection() as conn:
            return await self._incidents.list(conn, status=status, before=before, limit=limit)

    async def incident(self, incident_id: UUID) -> IncidentDetail | None:
        async with self._db.connection() as conn:
            incident = await self._incidents.get(conn, incident_id)
            if incident is None:
                return None
            alerts = await self._alerts.list_for_incident(conn, incident_id)
            transitions = await self._incidents.transitions(conn, incident_id)
            executions = await self._executions.for_incident(conn, incident_id)
            verifications = await self._verifications.for_incident(conn, incident_id)
        return IncidentDetail(
            id=incident.id,
            title=incident.title,
            category=incident.category.value,
            severity=incident.severity.value,
            status=incident.status.value,
            status_reason=incident.status_reason,
            resolution=incident.resolution,
            last_error=incident.last_error,
            target=IncidentTarget(
                service=incident.target_service,
                principal_id=incident.target_principal_id,
                account_id=incident.target_account_id,
            ),
            playbook_code=incident.playbook_code,
            attempt=incident.attempt_count,
            opened_at=incident.opened_at,
            remediation_started_at=incident.remediation_started_at,
            verified_at=incident.verified_at,
            closed_at=incident.closed_at,
            mttr_seconds=_mttr(incident),
            alerts=[AlertOut(**dict(row)) for row in alerts],
            transitions=[
                TransitionOut(from_status=row["from_status"], to=row["to_status"], reason=row["reason"], at=row["occurred_at"])
                for row in transitions
            ],
            executions=[
                ExecutionOut(
                    id=row["id"],
                    attempt=row["attempt"],
                    status=row["status"],
                    playbook_code=row["playbook_code"],
                    playbook_version=row["playbook_version"],
                    started_at=row["started_at"],
                    finished_at=row["finished_at"],
                    error=row["error"],
                    steps=[StepOut(**step) for step in row["steps"]],
                )
                for row in executions
            ],
            verifications=[
                VerificationOut(
                    id=row["id"],
                    trigger_source=row["trigger_source"],
                    status=row["status"],
                    failed_check=row["failed_check"],
                    started_at=row["started_at"],
                    finished_at=row["finished_at"],
                    synthetic_transaction_ids=list(row["synthetic_transaction_ids"]),
                    checks=[CheckOut(**check) for check in row["checks"]],
                )
                for row in verifications
            ],
        )

    async def timeline(self, start: datetime, end: datetime) -> Timeline:
        async with self._db.connection() as conn:
            phases = await self._phase_repository.between(conn, start, end)
            alerts = await self._alerts.between(conn, start, end)
            verifications = await self._verifications.completed_between(conn, start, end)
            closed = await self._incidents.closed_between(conn, start, end)
        segments = []
        for index, row in enumerate(phases):
            following = phases[index + 1]["entered_at"] if index + 1 < len(phases) else None
            segments.append(
                Segment(
                    phase=row["phase"],
                    start=max(row["entered_at"], start),
                    end=min(following, end) if following else None,
                    incident_id=row["incident_id"],
                )
            )
        markers = [
            Marker(
                at=row["received_at"],
                kind="alert.received",
                label=f"{row['category']}" + (f" ({row['confidence']:.2f})" if row["confidence"] is not None else ""),
                incident_id=row["incident_id"],
            )
            for row in alerts
        ]
        markers += [
            Marker(
                at=row["finished_at"],
                kind="verification.completed",
                label=f"STM {row['status']} ({row['passed_checks']}/{row['total_checks']})",
                incident_id=row["incident_id"],
            )
            for row in verifications
        ]
        markers += [
            Marker(
                at=row["closed_at"],
                kind="incident.closed",
                label=f"RESOLVED in {row['duration']:.0f} s",
                incident_id=row["id"],
            )
            for row in closed
        ]
        return Timeline(segments=segments, markers=sorted(markers, key=lambda marker: marker.at))

    async def health_history(self, window: timedelta) -> HealthHistory:
        async with self._db.connection() as conn:
            rows = await self._health.since(conn, window)
        series: dict[str, list[HealthPoint]] = {}
        for row in rows:
            series.setdefault(row["service"], []).append(
                HealthPoint(t=row["observed_at"], status=row["status"], latency_ms=row["latency_ms"])
            )
        return HealthHistory(series=[HealthSeries(service=name, points=points) for name, points in sorted(series.items())])
