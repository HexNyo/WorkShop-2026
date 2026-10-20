from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from app.domain.models import ALLOWED_TRANSITIONS, IncidentStatus, Phase, ServiceStatus, Severity, can_transition
from app.domain.phase import OpenIncident, compute_phase
from app.domain.playbooks import InvalidPlaybook, UnresolvedTemplate, parse_playbook, render
from app.domain.security import SignatureError, fingerprint, sign, verify_signature
from app.services.monitor import classify

SECRET = b"k" * 48


# ----------------------------------------------------------------- signature
def test_signature_round_trip() -> None:
    body = b'{"a":1}'
    header = sign(SECRET, body, int(time.time()))
    assert verify_signature(SECRET, header, body, tolerance_seconds=300)


@pytest.mark.parametrize(
    ("header", "body", "reason"),
    [
        (None, b"{}", "missing_signature"),
        ("garbage", b"{}", "malformed_signature"),
        (sign(SECRET, b"{}", int(time.time()) - 3600), b"{}", "timestamp_out_of_tolerance"),
        (sign(SECRET, b'{"a":1}', int(time.time())), b'{"a":2}', "bad_signature"),
        (sign(b"x" * 48, b"{}", int(time.time())), b"{}", "bad_signature"),
    ],
)
def test_signature_rejections(header, body, reason) -> None:
    with pytest.raises(SignatureError) as excinfo:
        verify_signature(SECRET, header, body, tolerance_seconds=300)
    assert excinfo.value.reason == reason


def test_fingerprint_is_stable_and_target_scoped() -> None:
    base = dict(explicit=None, category="SERVICE_UNAVAILABLE", service="payment-api", principal_id=None, account_id=None)
    assert fingerprint(**base) == fingerprint(**base)
    assert fingerprint(**base) != fingerprint(**{**base, "service": "auth-service"})
    assert fingerprint(**{**base, "explicit": "custom"}) == fingerprint(**{**base, "explicit": "custom", "service": "x"})
    assert len(fingerprint(**base)) == 64


# -------------------------------------------------------------- transitions
def test_transition_table_mirrors_database_guard() -> None:
    assert can_transition(IncidentStatus.VERIFYING, IncidentStatus.RESOLVED)
    assert not can_transition(IncidentStatus.REMEDIATING, IncidentStatus.RESOLVED), "no closure without verification"
    assert not can_transition(IncidentStatus.OPEN, IncidentStatus.RESOLVED)
    assert ALLOWED_TRANSITIONS[IncidentStatus.RESOLVED] == frozenset()
    assert can_transition(IncidentStatus.ESCALATED, IncidentStatus.VERIFYING)


# ---------------------------------------------------------------- playbooks
ROW = {
    "code": "PB-TEST",
    "version": 1,
    "category": "SERVICE_UNAVAILABLE",
    "title": "t",
    "steps": [{"action": "docker.restart_container", "target": "{{incident.target_service}}", "params": {}}],
    "post_verification_steps": [],
    "max_attempts": 2,
    "step_timeout_seconds": 30,
    "cooldown_seconds": 0,
    "enabled": True,
}


def test_playbook_parsing_enforces_action_allowlist() -> None:
    spec = parse_playbook(ROW, frozenset({"docker.restart_container"}))
    assert spec.steps[0].target == "{{incident.target_service}}"
    with pytest.raises(InvalidPlaybook, match="unknown action"):
        parse_playbook(ROW, frozenset({"probe.wait_ready"}))
    with pytest.raises(InvalidPlaybook):
        parse_playbook({**ROW, "steps": [{"action": "rm -rf", "params": {}}]}, frozenset({"rm -rf"}))


def test_template_rendering() -> None:
    context = {"incident.target_service": "payment-api", "incident.target_principal_id": None}
    assert render("{{incident.target_service}}", context) == "payment-api"
    assert render({"a": ["x-{{ incident.target_service }}"]}, context) == {"a": ["x-payment-api"]}
    assert render(42, context) == 42
    with pytest.raises(UnresolvedTemplate):
        render("{{incident.target_principal_id}}", context)


# -------------------------------------------------------------------- phases
NOW = datetime(2026, 10, 19, 8, 0, tzinfo=UTC)
HOLD = timedelta(minutes=5)
UP = {"payment-api": ServiceStatus.UP, "auth-service": ServiceStatus.UP}


def incident(status: IncidentStatus, severity: Severity = Severity.CRITICAL, service: str = "payment-api") -> OpenIncident:
    return OpenIncident(uuid4(), status, severity, service, NOW - timedelta(minutes=1))


def phase(incidents=(), health=UP, resolved=None) -> Phase:
    return compute_phase(
        open_incidents=incidents, health=health, last_resolved_at=resolved, last_resolved_id=None, now=NOW, restored_hold=HOLD
    ).phase


def test_phase_rules() -> None:
    assert phase() is Phase.NOMINAL
    assert phase([incident(IncidentStatus.OPEN)]) is Phase.CRITICAL
    assert phase([incident(IncidentStatus.OPEN, Severity.HIGH)]) is Phase.DEGRADED
    assert phase([incident(IncidentStatus.REMEDIATING)]) is Phase.RECOVERING
    assert phase([incident(IncidentStatus.ESCALATED)]) is Phase.CRITICAL
    assert phase(resolved=NOW - timedelta(minutes=1)) is Phase.RESTORED
    assert phase(resolved=NOW - timedelta(minutes=10)) is Phase.NOMINAL
    assert phase(health={**UP, "auth-service": ServiceStatus.DOWN}) is Phase.CRITICAL
    assert phase(health={**UP, "auth-service": ServiceStatus.DEGRADED}) is Phase.DEGRADED
    # Un service DOWN parce qu'il est en cours de redémarrage par la remédiation n'est pas « critique ».
    assert phase([incident(IncidentStatus.REMEDIATING)], health={**UP, "payment-api": ServiceStatus.DOWN}) is Phase.RECOVERING


def test_health_classification() -> None:
    assert classify(200, "pass", 10, 0) is ServiceStatus.UP
    assert classify(200, "warn", 10, 0) is ServiceStatus.DEGRADED
    assert classify(200, "pass", 900, 0) is ServiceStatus.DEGRADED
    assert classify(503, "fail", 10, 1) is ServiceStatus.DEGRADED
    assert classify(None, None, None, 2) is ServiceStatus.DOWN
