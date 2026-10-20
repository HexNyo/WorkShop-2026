"""Entités du domaine de remédiation."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

ROLE_DETECTOR = "svc.detector"
ROLE_ADMIN = "remediation.admin"
ROLE_VIEWER = "noc.viewer"
ROLE_CHAOS = "chaos.operator"

SERVICES = ("auth-service", "payment-api", "database", "remediation-engine", "frontend-dashboard")


class Severity(StrEnum):
    INFO = "INFO"
    WARNING = "WARNING"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)


class Category(StrEnum):
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
    PERFORMANCE_DEGRADATION = "PERFORMANCE_DEGRADATION"
    RESOURCE_EXHAUSTION = "RESOURCE_EXHAUSTION"
    DATA_INTEGRITY_VIOLATION = "DATA_INTEGRITY_VIOLATION"
    CREDENTIAL_COMPROMISE = "CREDENTIAL_COMPROMISE"
    ANOMALOUS_TRAFFIC = "ANOMALOUS_TRAFFIC"
    FRAUD_PATTERN = "FRAUD_PATTERN"


class IncidentStatus(StrEnum):
    OPEN = "OPEN"
    TRIAGED = "TRIAGED"
    REMEDIATING = "REMEDIATING"
    VERIFYING = "VERIFYING"
    RESOLVED = "RESOLVED"
    ESCALATED = "ESCALATED"
    SUPPRESSED = "SUPPRESSED"

    @property
    def is_closed(self) -> bool:
        return self in (IncidentStatus.RESOLVED, IncidentStatus.SUPPRESSED)

    @property
    def is_in_remediation(self) -> bool:
        return self in (IncidentStatus.REMEDIATING, IncidentStatus.VERIFYING)


class ServiceStatus(StrEnum):
    UP = "UP"
    DEGRADED = "DEGRADED"
    DOWN = "DOWN"
    UNKNOWN = "UNKNOWN"


class Phase(StrEnum):
    NOMINAL = "NOMINAL"
    DEGRADED = "DEGRADED"
    CRITICAL = "CRITICAL"
    RECOVERING = "RECOVERING"
    RESTORED = "RESTORED"


# Transitions autorisées : miroir applicatif de remediation.fn_incidents_before_update.
ALLOWED_TRANSITIONS: dict[IncidentStatus, frozenset[IncidentStatus]] = {
    IncidentStatus.OPEN: frozenset({IncidentStatus.TRIAGED, IncidentStatus.SUPPRESSED, IncidentStatus.ESCALATED}),
    IncidentStatus.TRIAGED: frozenset({IncidentStatus.REMEDIATING, IncidentStatus.SUPPRESSED, IncidentStatus.ESCALATED}),
    IncidentStatus.REMEDIATING: frozenset({IncidentStatus.VERIFYING, IncidentStatus.ESCALATED}),
    IncidentStatus.VERIFYING: frozenset({IncidentStatus.RESOLVED, IncidentStatus.REMEDIATING, IncidentStatus.ESCALATED}),
    IncidentStatus.ESCALATED: frozenset({IncidentStatus.REMEDIATING, IncidentStatus.VERIFYING}),
    IncidentStatus.RESOLVED: frozenset(),
    IncidentStatus.SUPPRESSED: frozenset(),
}


def can_transition(current: IncidentStatus, target: IncidentStatus) -> bool:
    return target in ALLOWED_TRANSITIONS[current]


@dataclass(frozen=True, slots=True)
class Incident:
    id: UUID
    fingerprint: str
    category: Category
    severity: Severity
    status: IncidentStatus
    status_reason: str
    title: str
    target_service: str
    target_principal_id: UUID | None
    target_account_id: UUID | None
    playbook_code: str | None
    attempt_count: int
    alert_count: int
    resolution: str | None
    last_error: str | None
    opened_at: datetime
    remediation_started_at: datetime | None
    verified_at: datetime | None
    closed_at: datetime | None
    updated_at: datetime

    def template_context(self) -> dict[str, str | None]:
        return {
            "incident.id": str(self.id),
            "incident.target_service": self.target_service,
            "incident.target_principal_id": str(self.target_principal_id) if self.target_principal_id else None,
            "incident.target_account_id": str(self.target_account_id) if self.target_account_id else None,
            "incident.category": self.category.value,
        }


@dataclass(frozen=True, slots=True)
class AlertSubmission:
    """Alerte normalisée (issue du webhook ou de la surveillance intégrée)."""

    source: str
    external_id: str
    detected_at: datetime
    category: Category
    severity: Severity
    confidence: float | None
    title: str
    description: str | None
    target_service: str
    target_principal_id: UUID | None
    target_account_id: UUID | None
    fingerprint: str
    payload: dict[str, Any]


@dataclass(frozen=True, slots=True)
class IntakeResult:
    alert_id: UUID
    incident_id: UUID
    deduplicated: bool
    incident_status: IncidentStatus
    replayed: bool = False


@dataclass(frozen=True, slots=True)
class ServiceHealth:
    service: str
    status: ServiceStatus
    latency_ms: int | None
    checked_at: datetime
    detail: str | None = None
    consecutive_failures: int = 0


@dataclass(slots=True)
class CheckRecord:
    code: str
    passed: bool
    latency_ms: int | None
    detail: dict[str, Any] = field(default_factory=dict)
