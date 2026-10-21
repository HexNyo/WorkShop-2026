"""Listener CONTROL (réseau `control` uniquement) : webhook d'alertes et pilotage humain."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Query, Request, status
from pydantic import ValidationError
from ra_common.db import UniqueViolationError
from ra_common.problem import ProblemException, not_found
from ra_common.security import AccessTokenClaims, require_roles
from starlette.responses import JSONResponse

from app.api.common import decode_cursor, encode_cursor, get_container
from app.api.schemas import (
    AlertAccepted,
    AlertIn,
    IncidentDetail,
    IncidentPage,
    OperatorAction,
    PlaybookOut,
    PlaybookPatch,
    Queued,
    SimulatedAlert,
)
from app.container import Container
from app.domain.models import (
    ROLE_ADMIN,
    ROLE_CHAOS,
    ROLE_DETECTOR,
    AlertSubmission,
    IncidentStatus,
)
from app.domain.security import SignatureError, fingerprint, verify_signature
from app.services.queries import summary

router = APIRouter(prefix="/v1")


def _invalid_signature(reason: str) -> ProblemException:
    return ProblemException(
        401, "INVALID_SIGNATURE", "Invalid signature", f"Webhook signature rejected ({reason})",
        headers={"WWW-Authenticate": 'RA-HMAC realm="remediation-control"'},
    )


def to_submission(alert: AlertIn) -> AlertSubmission:
    return AlertSubmission(
        source=alert.source,
        external_id=alert.external_id,
        detected_at=alert.detected_at,
        category=alert.category,
        severity=alert.severity,
        confidence=alert.confidence,
        title=alert.title,
        description=alert.description,
        target_service=alert.target.service,
        target_principal_id=alert.target.principal_id,
        target_account_id=alert.target.account_id,
        fingerprint=fingerprint(
            explicit=alert.fingerprint,
            category=alert.category.value,
            service=alert.target.service,
            principal_id=str(alert.target.principal_id) if alert.target.principal_id else None,
            account_id=str(alert.target.account_id) if alert.target.account_id else None,
        ),
        payload=alert.model_dump(mode="json"),
    )


@router.post("/alerts", status_code=202, response_model=AlertAccepted, tags=["webhook"])
async def receive_alert(
    request: Request,
    container: Container = Depends(get_container),
    claims: AccessTokenClaims = Depends(require_roles(ROLE_DETECTOR)),
) -> JSONResponse:
    settings = container.settings
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > settings.webhook_max_bytes:
        raise ProblemException(413, "PAYLOAD_TOO_LARGE", "Payload too large", f"Alerts are limited to {settings.webhook_max_bytes} bytes")
    body = await request.body()
    if len(body) > settings.webhook_max_bytes:
        raise ProblemException(413, "PAYLOAD_TOO_LARGE", "Payload too large", f"Alerts are limited to {settings.webhook_max_bytes} bytes")
    try:
        verify_signature(
            settings.webhook_hmac_secret.get_secret_value().encode(),
            request.headers.get("x-ra-signature"),
            body,
            tolerance_seconds=settings.webhook_tolerance_seconds,
        )
    except SignatureError as exc:
        raise _invalid_signature(exc.reason) from exc

    try:
        alert = AlertIn.model_validate_json(body)
    except ValidationError as exc:
        raise ProblemException(
            422,
            "VALIDATION_ERROR",
            "Validation error",
            "Alert does not match contract alert-webhook 1.0",
            errors=[
                {"location": ".".join(str(part) for part in error.get("loc", ())) or "body", "message": error.get("msg", "invalid")}
                for error in exc.errors()
            ],
        ) from exc

    delay = container.webhook_limiter.check(f"{claims.sub}:{alert.source}", settings.webhook_rate_per_minute)
    if delay is not None:
        raise ProblemException(429, "RATE_LIMITED", "Too many requests", "Alert rate limit exceeded for this source",
                               headers={"Retry-After": str(max(int(delay), 1))})

    result = await container.intake.submit(to_submission(alert))
    accepted = AlertAccepted(
        alert_id=result.alert_id,
        incident_id=result.incident_id,
        deduplicated=result.deduplicated,
        incident_status=result.incident_status.value,
    ).model_dump(mode="json")
    if result.replayed:
        return JSONResponse(accepted, status_code=200, headers={"Idempotent-Replayed": "true"})
    return JSONResponse(accepted, status_code=202)


# ------------------------------------------------------------------- pilotage
# Monté sur CONTROL (/v1) et sur SUPERVISION (/v1/admin, via la passerelle) : mêmes
# actions, toujours réservées à remediation.admin.
pilot = APIRouter()
admin = require_roles(ROLE_ADMIN)


@pilot.get("/incidents", response_model=IncidentPage, tags=["incidents"])
async def list_incidents(
    status_filter: IncidentStatus | None = Query(None, alias="status"),
    limit: int = Query(50, ge=1, le=200),
    cursor: str | None = Query(None, max_length=200),
    container: Container = Depends(get_container),
    _: AccessTokenClaims = Depends(admin),
) -> IncidentPage:
    items = await container.queries.incidents(status=status_filter, before=decode_cursor(cursor), limit=limit + 1)
    page = items[:limit]
    return IncidentPage(
        items=[summary(item) for item in page],
        next_cursor=encode_cursor(page[-1].opened_at, page[-1].id) if len(items) > limit else None,
    )


@pilot.get("/incidents/{incident_id}", response_model=IncidentDetail, tags=["incidents"])
async def get_incident(
    incident_id: UUID, container: Container = Depends(get_container), _: AccessTokenClaims = Depends(admin)
) -> IncidentDetail:
    detail = await container.queries.incident(incident_id)
    if detail is None:
        raise not_found("Incident not found")
    return detail


async def _require_escalated(container: Container, incident_id: UUID) -> None:
    detail = await container.queries.incident(incident_id)
    if detail is None:
        raise not_found("Incident not found")
    if detail.status != IncidentStatus.ESCALATED.value:
        raise ProblemException(409, "INVALID_STATE", "Conflict", f"Incident is {detail.status}; only ESCALATED incidents accept this action")


@pilot.post("/incidents/{incident_id}/retry", status_code=status.HTTP_202_ACCEPTED, response_model=Queued, tags=["incidents"])
async def retry_incident(
    incident_id: UUID,
    body: OperatorAction,
    container: Container = Depends(get_container),
    claims: AccessTokenClaims = Depends(admin),
) -> Queued:
    await _require_escalated(container, incident_id)
    container.orchestrator.enqueue(incident_id, "retry", note=f"operator {claims.name}: {body.reason}")
    return Queued(incident_id=incident_id, mode="retry")


@pilot.post("/incidents/{incident_id}/verify", status_code=status.HTTP_202_ACCEPTED, response_model=Queued, tags=["incidents"])
async def verify_incident(
    incident_id: UUID,
    body: OperatorAction,
    container: Container = Depends(get_container),
    claims: AccessTokenClaims = Depends(admin),
) -> Queued:
    await _require_escalated(container, incident_id)
    container.orchestrator.enqueue(incident_id, "verify", note=f"operator {claims.name}: {body.reason}")
    return Queued(incident_id=incident_id, mode="verify")


def _playbook(row) -> PlaybookOut:
    return PlaybookOut(**dict(row))


@pilot.get("/playbooks", response_model=list[PlaybookOut], tags=["playbooks"])
async def list_playbooks(container: Container = Depends(get_container), _: AccessTokenClaims = Depends(admin)) -> list[PlaybookOut]:
    async with container.db.connection() as conn:
        return [_playbook(row) for row in await container.playbooks.list(conn)]


@pilot.patch("/playbooks/{code}", response_model=PlaybookOut, tags=["playbooks"])
async def patch_playbook(
    code: str,
    body: PlaybookPatch,
    container: Container = Depends(get_container),
    _: AccessTokenClaims = Depends(admin),
) -> PlaybookOut:
    try:
        async with container.db.transaction() as conn:
            row = await container.playbooks.set_enabled(conn, code, body.enabled)
    except UniqueViolationError as exc:
        raise ProblemException(409, "INVALID_STATE", "Conflict", "Another playbook is already enabled for this category") from exc
    if row is None:
        raise not_found("Playbook not found")
    return _playbook(row)


@pilot.post("/verifications", tags=["verifications"], summary="STM à la demande, hors incident")
async def run_verification(
    body: OperatorAction, container: Container = Depends(get_container), _: AccessTokenClaims = Depends(admin)
) -> JSONResponse:
    # Hors incident, la base impose trigger_source = SCHEDULED (contrainte ck_verification_incident).
    outcome = await container.verifier.run(incident_id=None, execution_id=None, trigger_source="SCHEDULED")
    return JSONResponse(
        {"run_id": str(outcome.run_id), "status": "PASSED" if outcome.passed else "FAILED", "failed_check": outcome.failed_check},
        status_code=200,
    )

@pilot.post("/incidents/{incident_id}/acknowledge", tags=["incidents"], summary="Prise en charge humaine d'un incident escaladé")
async def acknowledge_incident(
    incident_id: UUID,
    body: OperatorAction,
    container: Container = Depends(get_container),
    claims: AccessTokenClaims = Depends(admin),
) -> JSONResponse:
    await _require_escalated(container, incident_id)
    reason = f"operator {claims.name}: acknowledged - {body.reason}"
    async with container.db.transaction() as conn:
        await container.incidents.set_reason(conn, incident_id, reason)
    container.events.publish("incident.acknowledged", {"by": claims.name, "reason": body.reason}, incident_id)
    return JSONResponse({"incident_id": str(incident_id), "acknowledged_by": claims.name})


@pilot.get("/audit", tags=["audit"], summary="Journal des actions automatiques et humaines")
async def audit(
    limit: int = Query(100, ge=1, le=500),
    container: Container = Depends(get_container),
    _: AccessTokenClaims = Depends(admin),
) -> JSONResponse:
    async with container.db.connection() as conn:
        rows = await container.incidents.audit(conn, limit)
    return JSONResponse({"items": [
        {**{k: (v.isoformat() if hasattr(v, "isoformat") else str(v) if k == "incident_id" else v) for k, v in dict(row).items()},
         "actor": "human" if (row["detail"] or "").startswith("operator ") else "automated"}
        for row in rows
    ]})


@pilot.get("/settings", tags=["settings"], summary="Réglages effectifs du moteur (lecture seule)")
async def engine_settings(container: Container = Depends(get_container), _: AccessTokenClaims = Depends(admin)) -> JSONResponse:
    s = container.settings
    return JSONResponse({
        "health_poll_seconds": s.health_poll_seconds,
        "watchdog_enabled": s.watchdog_enabled,
        "watchdog_down_polls": s.watchdog_down_polls,
        "scheduled_stm_seconds": s.scheduled_stm_seconds,
        "max_per_target_per_hour": s.max_per_target_per_hour,
        "min_confidence": s.min_confidence,
        "restored_hold_seconds": s.restored_hold_seconds,
    })


@pilot.post("/simulate-alert", status_code=202, tags=["lab"], summary="Laboratoire : alerte simulée sur n'importe quel service")
async def simulate_alert(
    body: SimulatedAlert,
    container: Container = Depends(get_container),
    claims: AccessTokenClaims = Depends(require_roles(ROLE_CHAOS)),
) -> JSONResponse:
    if not container.settings.chaos_lab_enabled:
        raise not_found("Chaos lab disabled")
    alert = AlertIn(
        schema_version="1.0",
        source="operator-simulator",
        external_id=f"sim-{uuid4().hex}",
        detected_at=datetime.now(UTC),
        category=body.category,
        severity=body.severity,
        confidence=1.0,
        title=f"Simulated {body.category.value} on {body.service} by {claims.name}",
        target={"service": body.service},
    )
    result = await container.intake.submit(to_submission(alert))
    return JSONResponse({"incident_id": str(result.incident_id), "deduplicated": result.deduplicated}, status_code=202)
