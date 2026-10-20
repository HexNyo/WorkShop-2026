from __future__ import annotations

import json
import threading
import time
import uuid

import httpx
import pytest

from tests.e2e.conftest import (
    BOB,
    CLOSED,
    SUPERVISION_URL,
    SYNTHETIC_ACCOUNT_A,
    alert_body,
    lab,
    send_alert,
    wait_incident,
)


class EventCollector:
    """Abonné SSE en tâche de fond (vue « console NOC/SOC »)."""

    def __init__(self, ticket: str) -> None:
        self.events: list[dict] = []
        self._ticket = ticket
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def __enter__(self) -> EventCollector:
        self._thread.start()
        time.sleep(0.5)
        return self

    def __exit__(self, *_exc) -> None:
        self._stop.set()

    def _run(self) -> None:
        with httpx.Client(base_url=SUPERVISION_URL, timeout=httpx.Timeout(5.0, read=20.0)) as client:
            with client.stream("GET", "/v1/stream", params={"ticket": self._ticket}) as stream:
                for line in stream.iter_lines():
                    if self._stop.is_set():
                        return
                    if line.startswith("data: "):
                        self.events.append(json.loads(line[6:]))

    def types_for(self, incident_id: str) -> list[str]:
        return [event["type"] for event in self.events if event.get("incident_id") == incident_id]


def ticket(supervision: httpx.Client, as_) -> str:
    response = supervision.post("/v1/stream-tickets", headers=as_("noc-operator"))
    assert response.status_code == 201, response.text
    return response.json()["ticket"]


# =========================================================== isolation & sécurité
def test_listeners_are_segregated(control: httpx.Client, supervision: httpx.Client, as_) -> None:
    assert control.get("/health/readiness").json()["checks"]["docker:proxy"][0]["status"] == "pass"
    assert supervision.post("/v1/alerts", json={}).status_code in (404, 405), "webhook absent from SUPERVISION"
    assert control.get("/v1/overview", headers=as_("noc-operator")).status_code == 404, "console absent from CONTROL"
    assert supervision.get("/v1/playbooks", headers=as_("admin")).status_code == 404, "pilotage absent from SUPERVISION"


def test_webhook_requires_jwt_and_hmac(control: httpx.Client, as_) -> None:
    body = alert_body("SERVICE_UNAVAILABLE", severity="INFO")
    raw = json.dumps(body).encode()
    assert control.post("/v1/alerts", content=raw).status_code == 401

    for signature, reason in [(None, "missing_signature"), ("t=1,v1=00", "timestamp_out_of_tolerance"),
                              (f"t={int(time.time())},v1={'0' * 64}", "bad_signature")]:
        response = send_alert(control, as_, body, signature=signature)
        assert response.status_code == 401 and response.json()["code"] == "INVALID_SIGNATURE", response.text
        assert reason in response.json()["detail"]

    # Un humain, même administrateur, ne peut pas émettre d'alerte.
    assert send_alert(control, as_, body, principal="admin").status_code == 403
    # Un jeton de service d'une autre audience est refusé.
    assert send_alert(control, as_, body, principal="svc-synthetic").status_code == 401

    invalid = send_alert(control, as_, {**body, "category": "NOT_A_CATEGORY"})
    assert invalid.status_code == 422
    missing_target = send_alert(control, as_, alert_body("CREDENTIAL_COMPROMISE"))
    assert missing_target.status_code == 422 and "principal_id" in missing_target.text


def test_supervision_rbac_and_stream(supervision: httpx.Client, as_) -> None:
    assert supervision.get("/v1/overview").status_code == 401
    assert supervision.get("/v1/overview", headers=as_("alice")).status_code == 403
    overview = supervision.get("/v1/overview", headers=as_("noc-operator"))
    assert overview.status_code == 200
    names = {service["name"] for service in overview.json()["services"]}
    assert {"auth-service", "payment-api", "database", "remediation-engine"} <= names
    with EventCollector(ticket(supervision, as_)) as collector:
        time.sleep(16)  # au moins un battement service.health
    assert any(event["type"] == "service.health" for event in collector.events)
    assert supervision.get("/v1/stream", params={"ticket": "st_forged.ticket"}).status_code == 401


def test_low_confidence_alert_is_suppressed_and_replays_are_idempotent(control: httpx.Client, supervision, as_) -> None:
    body = alert_body("PERFORMANCE_DEGRADATION", confidence=0.2, fingerprint=f"e2e-{uuid.uuid4()}")
    first = send_alert(control, as_, body)
    assert first.status_code == 202 and first.json()["incident_status"] == "SUPPRESSED"
    replay = send_alert(control, as_, body)
    assert replay.status_code == 200 and replay.headers["idempotent-replayed"] == "true"
    assert replay.json()["incident_id"] == first.json()["incident_id"]
    detail = wait_incident(supervision, as_, first.json()["incident_id"], CLOSED, timeout=5)
    assert detail["resolution"] == "SUPPRESSED" and detail["executions"] == []


# ===================================================== boucle complète de reprise
def test_data_integrity_attack_is_detected_remediated_and_verified(
    control: httpx.Client, supervision: httpx.Client, payment: httpx.Client, as_, lab_enabled
) -> None:
    with EventCollector(ticket(supervision, as_)) as collector:
        tampered = lab(payment, as_, {"type": "BALANCE_TAMPER", "params": {"account_number": "RA-1000-0003", "delta": "500.00"}})
        assert tampered.status_code == 201, tampered.text

        accepted = send_alert(control, as_, alert_body("DATA_INTEGRITY_VIOLATION"))
        assert accepted.status_code == 202, accepted.text
        incident_id = accepted.json()["incident_id"]
        duplicate = send_alert(control, as_, alert_body("DATA_INTEGRITY_VIOLATION"))
        assert duplicate.json()["incident_id"] == incident_id and duplicate.json()["deduplicated"] is True

        detail = wait_incident(supervision, as_, incident_id, CLOSED | {"ESCALATED"})
        # RESTORED est atteint au sondage de santé suivant la réouverture (≤ 1 intervalle).
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if supervision.get("/v1/overview", headers=as_("noc-operator")).json()["phase"] == "RESTORED":
                break
            time.sleep(1)
        time.sleep(0.5)

    assert detail["status"] == "RESOLVED", detail["last_error"]
    assert detail["resolution"] == "AUTOMATIC" and detail["verified_at"] and detail["mttr_seconds"] > 0
    assert [t["to"] for t in detail["transitions"]][-4:] == ["TRIAGED", "REMEDIATING", "VERIFYING", "RESOLVED"]
    steps = [(s["phase"], s["action"], s["status"]) for s in detail["executions"][-1]["steps"]]
    assert ("REMEDIATION", "payment.repair_balances", "SUCCEEDED") in steps
    assert ("POST_VERIFICATION", "payment.set_write_mode", "SUCCEEDED") in steps
    verification = detail["verifications"][-1]
    assert verification["status"] == "PASSED" and len(verification["checks"]) == 9
    assert len(detail["alerts"]) >= 2, "duplicate alert attached to the same incident"

    # La plateforme est réellement rétablie : intégrité OK et trafic réel rouvert.
    integrity = payment.get("/health/integrity", params={"refresh": "true"}, headers=as_("svc-synthetic", "payment-api"))
    assert integrity.status_code == 200 and integrity.json()["status"] == "pass"
    readiness = payment.get("/health/readiness").json()
    assert readiness["checks"]["runtime:write-mode"][0]["observedValue"] == "READ_WRITE"

    seen = collector.types_for(incident_id)
    for event_type in ("alert.received", "incident.status_changed", "remediation.step", "verification.check",
                       "verification.completed", "incident.closed"):
        assert event_type in seen, f"{event_type} missing from the SSE stream"
    phases = [e["payload"]["phase"] for e in collector.events if e["type"] == "system.phase_changed"]
    assert "RECOVERING" in phases and "RESTORED" in phases


def test_unavailable_service_is_restarted_then_verified(
    control: httpx.Client, supervision: httpx.Client, payment: httpx.Client, as_, lab_enabled
) -> None:
    assert lab(payment, as_, {"type": "READINESS_FAILURE"}).status_code == 201
    assert payment.get("/health/readiness").status_code == 503
    accepted = send_alert(control, as_, alert_body("SERVICE_UNAVAILABLE"))
    assert accepted.status_code in (200, 202), accepted.text
    detail = wait_incident(supervision, as_, accepted.json()["incident_id"], CLOSED | {"ESCALATED"})
    assert detail["status"] == "RESOLVED", detail["last_error"]
    actions = [(s["action"], s["status"]) for s in detail["executions"][-1]["steps"]]
    assert actions[:2] == [("docker.restart_container", "SUCCEEDED"), ("probe.wait_ready", "SUCCEEDED")]
    assert payment.get("/health/readiness").status_code == 200
    assert payment.get("/lab/v1/faults", headers=as_("admin")).json()["items"] == [], "restart cleared the fault"


def test_compromised_credentials_are_contained(
    control: httpx.Client, supervision: httpx.Client, auth: httpx.Client, as_
) -> None:
    from tests.e2e.conftest import secret

    bob_token = auth.post("/v1/auth/login", json={"username": "bob", "password": secret("bob")}).json()["access_token"]
    accepted = send_alert(control, as_, alert_body("CREDENTIAL_COMPROMISE", principal_id=BOB))
    detail = wait_incident(supervision, as_, accepted.json()["incident_id"], CLOSED | {"ESCALATED"})
    try:
        assert detail["status"] == "RESOLVED", detail["last_error"]
        assert [s["action"] for s in detail["executions"][-1]["steps"]] == [
            "auth.revoke_principal_tokens", "auth.disable_principal",
        ]
        assert auth.get("/v1/me", headers={"Authorization": f"Bearer {bob_token}"}).status_code == 401
        assert auth.post("/v1/auth/login", json={"username": "bob", "password": secret("bob")}).status_code == 401
    finally:
        enabled = auth.post(f"/internal/v1/principals/{BOB}/enable", json={"reason": "TEST_CLEANUP"}, headers=as_("admin"))
        assert enabled.status_code == 200


def test_unremediable_incident_escalates_then_manual_verification_closes_it(
    control: httpx.Client, supervision: httpx.Client, as_
) -> None:
    accepted = send_alert(control, as_, alert_body("FRAUD_PATTERN", account_id=SYNTHETIC_ACCOUNT_A))
    incident_id = accepted.json()["incident_id"]
    escalated = wait_incident(supervision, as_, incident_id, {"ESCALATED", "RESOLVED"})
    assert escalated["status"] == "ESCALATED", "freezing a synthetic account must be refused"
    assert "freeze" in (escalated["last_error"] or "") or "synthetic" in (escalated["last_error"] or "").lower()
    assert supervision.get("/v1/overview", headers=as_("noc-operator")).json()["phase"] == "CRITICAL"

    # Pilotage humain réservé au réseau control et au rôle remediation.admin.
    assert control.post(f"/v1/incidents/{incident_id}/verify", json={"reason": "operator check"},
                        headers=as_("noc-operator")).status_code == 403
    queued = control.post(f"/v1/incidents/{incident_id}/verify", json={"reason": "false positive confirmed"},
                          headers=as_("admin"))
    assert queued.status_code == 202, queued.text
    resolved = wait_incident(supervision, as_, incident_id, CLOSED, timeout=90)
    assert resolved["resolution"] == "MANUAL" and resolved["verifications"][-1]["status"] == "PASSED"
    again = control.post(f"/v1/incidents/{incident_id}/retry", json={"reason": "too late"}, headers=as_("admin"))
    assert again.status_code == 409


def test_zero_touch_watchdog_detects_and_repairs_without_external_alert(
    supervision: httpx.Client, payment: httpx.Client, as_, lab_enabled
) -> None:
    """Aucune alerte externe : la STM planifiée détecte l'altération, le moteur répare seul."""
    started = time.time()
    tampered = lab(payment, as_, {"type": "BALANCE_TAMPER", "params": {"account_number": "RA-1000-0001", "delta": "-10.00"}})
    assert tampered.status_code == 201, tampered.text

    deadline = time.monotonic() + 200
    incident_id = None
    while time.monotonic() < deadline and incident_id is None:
        page = supervision.get("/v1/incidents", params={"limit": 5}, headers=as_("noc-operator")).json()["items"]
        for item in page:
            opened = item["opened_at"].replace("Z", "+00:00")
            from datetime import datetime

            if item["category"] == "DATA_INTEGRITY_VIOLATION" and datetime.fromisoformat(opened).timestamp() >= started - 1:
                incident_id = item["id"]
                break
        time.sleep(2)
    assert incident_id, "the built-in watchdog did not raise an incident"

    detail = wait_incident(supervision, as_, incident_id, CLOSED | {"ESCALATED"}, timeout=200)
    assert detail["status"] == "RESOLVED", detail["last_error"]
    assert detail["alerts"][0]["source"] == "watchdog"
    integrity = payment.get("/health/integrity", params={"refresh": "true"}, headers=as_("svc-synthetic", "payment-api"))
    assert integrity.json()["status"] == "pass"


def test_timeline_health_history_and_catalog(control: httpx.Client, supervision: httpx.Client, as_) -> None:
    timeline = supervision.get("/v1/timeline", headers=as_("noc-operator"))
    assert timeline.status_code == 200
    body = timeline.json()
    assert {segment["phase"] for segment in body["segments"]} >= {"RECOVERING"}
    assert all("from" in segment and "to" in segment for segment in body["segments"])
    assert any(marker["kind"] == "incident.closed" for marker in body["markers"])

    history = supervision.get("/v1/services/health", params={"window": "15m"}, headers=as_("noc-operator")).json()
    assert {series["service"] for series in history["series"]} >= {"payment-api", "auth-service"}

    incidents = control.get("/v1/incidents", params={"limit": 2}, headers=as_("admin")).json()
    assert len(incidents["items"]) == 2 and incidents["next_cursor"]
    playbooks = control.get("/v1/playbooks", headers=as_("admin")).json()
    assert {pb["code"] for pb in playbooks} >= {"PB-INTEGRITY-RESTORE", "PB-SERVICE-RESTART"}
    try:
        disabled = control.patch("/v1/playbooks/PB-PERF-RECOVERY", json={"enabled": False}, headers=as_("admin"))
        assert disabled.status_code == 200 and disabled.json()["enabled"] is False
    finally:
        assert control.patch("/v1/playbooks/PB-PERF-RECOVERY", json={"enabled": True}, headers=as_("admin")).status_code == 200


@pytest.mark.parametrize("path", ["/v1/overview", "/v1/incidents"])
def test_supervision_is_read_only(supervision: httpx.Client, as_, path: str) -> None:
    assert supervision.delete(path, headers=as_("admin")).status_code == 405
