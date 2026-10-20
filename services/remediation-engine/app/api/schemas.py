"""DTO d'entrée/sortie du moteur (validation stricte des alertes entrantes)."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.domain.models import Category, Severity


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


# ======================================================== contrat du webhook (1.0)
class AlertTarget(StrictModel):
    service: Literal["auth-service", "payment-api", "database", "remediation-engine", "frontend-dashboard"]
    principal_id: UUID | None = None
    account_id: UUID | None = None


class AlertIn(StrictModel):
    """Miroir de contracts/alert-webhook.schema.json."""

    schema_version: Literal["1.0"]
    source: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,63}$")
    external_id: str = Field(min_length=1, max_length=128)
    detected_at: datetime
    category: Category
    severity: Severity
    confidence: float | None = Field(None, ge=0, le=1)
    title: str = Field(min_length=3, max_length=200)
    description: str | None = Field(None, max_length=2000)
    target: AlertTarget
    fingerprint: str | None = Field(None, min_length=1, max_length=256)
    evidence: dict[str, Any] = Field(default_factory=dict)
    labels: dict[str, str] = Field(default_factory=dict, max_length=32)

    @field_validator("detected_at")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("detected_at must include a timezone")
        return value

    @field_validator("labels")
    @classmethod
    def _labels(cls, value: dict[str, str]) -> dict[str, str]:
        for key, item in value.items():
            if not re.match(r"^[a-z][a-z0-9_]{0,62}$", key) or len(item) > 256:
                raise ValueError(f"invalid label {key!r}")
        return value

    @model_validator(mode="after")
    def _category_targets(self) -> AlertIn:
        if self.category is Category.CREDENTIAL_COMPROMISE and self.target.principal_id is None:
            raise ValueError("CREDENTIAL_COMPROMISE alerts require target.principal_id")
        if self.category is Category.FRAUD_PATTERN and self.target.account_id is None:
            raise ValueError("FRAUD_PATTERN alerts require target.account_id")
        return self


class AlertAccepted(BaseModel):
    alert_id: UUID
    incident_id: UUID
    deduplicated: bool
    incident_status: str


# ================================================================ pilotage
class OperatorAction(StrictModel):
    reason: str = Field(min_length=5, max_length=256)


class SimulatedAlert(StrictModel):
    service: Literal["auth-service", "payment-api", "database", "remediation-engine", "frontend-dashboard"]
    category: Category
    severity: Severity = Severity.CRITICAL


class PlaybookPatch(StrictModel):
    enabled: bool


# ============================================================== lecture
class IncidentSummary(BaseModel):
    id: UUID
    title: str
    category: str
    severity: str
    status: str
    status_reason: str
    target_service: str
    playbook_code: str | None
    attempt: int
    alert_count: int
    resolution: str | None
    opened_at: datetime
    closed_at: datetime | None
    mttr_seconds: float | None


class IncidentPage(BaseModel):
    items: list[IncidentSummary]
    next_cursor: str | None


class AlertOut(BaseModel):
    id: UUID
    source: str
    external_id: str
    category: str
    severity: str
    confidence: float | None
    title: str
    detected_at: datetime
    received_at: datetime


class TransitionOut(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    from_status: str | None = Field(serialization_alias="from")
    to: str
    reason: str
    at: datetime


class StepOut(BaseModel):
    phase: str
    seq: int
    action: str
    target: str | None
    status: str
    duration_ms: int | None
    output: dict[str, Any] | None
    error: str | None
    started_at: datetime | None
    finished_at: datetime | None


class ExecutionOut(BaseModel):
    id: UUID
    attempt: int
    status: str
    playbook_code: str
    playbook_version: int
    started_at: datetime
    finished_at: datetime | None
    error: str | None
    steps: list[StepOut]


class CheckOut(BaseModel):
    seq: int
    code: str
    passed: bool
    latency_ms: int | None
    detail: dict[str, Any]


class VerificationOut(BaseModel):
    id: UUID
    trigger_source: str
    status: str
    failed_check: str | None
    started_at: datetime
    finished_at: datetime | None
    synthetic_transaction_ids: list[UUID]
    checks: list[CheckOut]


class IncidentTarget(BaseModel):
    service: str
    principal_id: UUID | None
    account_id: UUID | None


class IncidentDetail(BaseModel):
    id: UUID
    title: str
    category: str
    severity: str
    status: str
    status_reason: str
    resolution: str | None
    last_error: str | None
    target: IncidentTarget
    playbook_code: str | None
    attempt: int
    opened_at: datetime
    remediation_started_at: datetime | None
    verified_at: datetime | None
    closed_at: datetime | None
    mttr_seconds: float | None
    alerts: list[AlertOut]
    transitions: list[TransitionOut]
    executions: list[ExecutionOut]
    verifications: list[VerificationOut]


class ServiceOut(BaseModel):
    name: str
    status: str
    latency_ms: int | None
    checked_at: datetime | None
    detail: str | None = None


class Counters(BaseModel):
    open_incidents: int
    resolved_24h: int
    escalated_24h: int
    mttr_p50_seconds: float | None


class LastVerification(BaseModel):
    run_id: UUID
    status: str
    trigger_source: str
    failed_check: str | None
    finished_at: datetime | None


class Overview(BaseModel):
    phase: str
    phase_since: datetime
    phase_incident_id: UUID | None
    active_incident: IncidentSummary | None
    services: list[ServiceOut]
    counters: Counters
    last_verification: LastVerification | None
    stream_seq: int


class Segment(BaseModel):
    phase: str
    start: datetime = Field(serialization_alias="from")
    end: datetime | None = Field(serialization_alias="to")
    incident_id: UUID | None


class Marker(BaseModel):
    at: datetime
    kind: str
    label: str
    incident_id: UUID | None = None


class Timeline(BaseModel):
    segments: list[Segment]
    markers: list[Marker]


class HealthPoint(BaseModel):
    t: datetime
    status: str
    latency_ms: int | None


class HealthSeries(BaseModel):
    service: str
    points: list[HealthPoint]


class HealthHistory(BaseModel):
    series: list[HealthSeries]


class PlaybookOut(BaseModel):
    code: str
    version: int
    category: str
    title: str
    description: str
    steps: list[dict[str, Any]]
    post_verification_steps: list[dict[str, Any]]
    max_attempts: int
    step_timeout_seconds: int
    cooldown_seconds: int
    enabled: bool
    updated_at: datetime


class StreamTicketOut(BaseModel):
    ticket: str
    expires_in: int


class Queued(BaseModel):
    incident_id: UUID
    queued: Literal[True] = True
    mode: str
