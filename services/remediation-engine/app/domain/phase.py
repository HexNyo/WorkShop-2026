"""Calcul de la phase système affichée par la console (Avant / Pendant / Après).

Règles par priorité décroissante (cf. docs/04 § 5).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID

from app.domain.models import IncidentStatus, Phase, ServiceStatus, Severity


@dataclass(frozen=True, slots=True)
class OpenIncident:
    id: UUID
    status: IncidentStatus
    severity: Severity
    target_service: str
    opened_at: datetime


@dataclass(frozen=True, slots=True)
class PhaseDecision:
    phase: Phase
    incident_id: UUID | None
    reason: str


def compute_phase(
    *,
    open_incidents: Iterable[OpenIncident],
    health: Mapping[str, ServiceStatus],
    last_resolved_at: datetime | None,
    last_resolved_id: UUID | None,
    now: datetime,
    restored_hold: timedelta,
) -> PhaseDecision:
    incidents = sorted(open_incidents, key=lambda item: (-item.severity.rank, item.opened_at))
    remediating_services = {item.target_service for item in incidents if item.status.is_in_remediation}

    escalated = [item for item in incidents if item.status is IncidentStatus.ESCALATED]
    if escalated:
        return PhaseDecision(Phase.CRITICAL, escalated[0].id, "incident escalated: human action required")
    untreated_critical = [
        item for item in incidents
        if item.status in (IncidentStatus.OPEN, IncidentStatus.TRIAGED) and item.severity is Severity.CRITICAL
    ]
    if untreated_critical:
        return PhaseDecision(Phase.CRITICAL, untreated_critical[0].id, "critical incident detected")
    down = sorted(name for name, status in health.items() if status is ServiceStatus.DOWN and name not in remediating_services)
    if down:
        return PhaseDecision(Phase.CRITICAL, None, f"service down: {', '.join(down)}")

    in_remediation = [item for item in incidents if item.status.is_in_remediation]
    if in_remediation:
        return PhaseDecision(Phase.RECOVERING, in_remediation[0].id, f"automatic remediation {in_remediation[0].status.value.lower()}")

    pending = [item for item in incidents if item.status in (IncidentStatus.OPEN, IncidentStatus.TRIAGED)]
    if pending:
        return PhaseDecision(Phase.DEGRADED, pending[0].id, "incident detected")
    degraded = sorted(name for name, status in health.items() if status is ServiceStatus.DEGRADED)
    if degraded:
        return PhaseDecision(Phase.DEGRADED, None, f"service degraded: {', '.join(degraded)}")

    all_up = all(status is ServiceStatus.UP for status in health.values())
    if last_resolved_at is not None and now - last_resolved_at < restored_hold and all_up:
        return PhaseDecision(Phase.RESTORED, last_resolved_id, "service restored and verified")
    return PhaseDecision(Phase.NOMINAL, None, "all services nominal")
