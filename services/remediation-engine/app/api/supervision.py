"""Listener SUPERVISION (réseau `app`, via la passerelle) : lecture seule + flux SSE."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query
from ra_common.metrics import AUTH_REJECTIONS
from ra_common.problem import ProblemException, not_found, unauthenticated
from ra_common.security import AccessTokenClaims, require_roles
from ra_common.sse import TicketError, event_stream, parse_last_event_id
from starlette.responses import StreamingResponse

from app.api.common import decode_cursor, encode_cursor, get_container
from app.api.schemas import HealthHistory, IncidentDetail, IncidentPage, Overview, StreamTicketOut, Timeline
from app.container import Container
from app.domain.models import ROLE_ADMIN, ROLE_VIEWER, IncidentStatus
from app.services.queries import summary

router = APIRouter(prefix="/v1", tags=["supervision"])
viewer = require_roles(ROLE_VIEWER, ROLE_ADMIN)
_WINDOW = re.compile(r"^([1-9][0-9]{0,3})([mh])$")


@router.get("/overview", response_model=Overview, summary="État courant : phase, incident actif, santé, compteurs")
async def overview(container: Container = Depends(get_container), _: AccessTokenClaims = Depends(viewer)) -> Overview:
    return await container.queries.overview()


@router.get("/timeline", response_model=Timeline, summary="Chronologie Avant / Pendant / Après")
async def timeline(
    start: datetime | None = Query(None, alias="from"),
    end: datetime | None = Query(None, alias="to"),
    container: Container = Depends(get_container),
    _: AccessTokenClaims = Depends(viewer),
) -> Timeline:
    end = end or datetime.now(UTC)
    start = start or end - timedelta(hours=1)
    if start.tzinfo is None or end.tzinfo is None:
        raise ProblemException(422, "VALIDATION_ERROR", "Validation error", "from/to must include a timezone")
    if not start < end or end - start > timedelta(days=7):
        raise ProblemException(422, "VALIDATION_ERROR", "Validation error", "from must precede to, within 7 days")
    return await container.queries.timeline(start, end)


@router.get("/incidents", response_model=IncidentPage)
async def incidents(
    status_filter: IncidentStatus | None = Query(None, alias="status"),
    limit: int = Query(50, ge=1, le=200),
    cursor: str | None = Query(None, max_length=200),
    container: Container = Depends(get_container),
    _: AccessTokenClaims = Depends(viewer),
) -> IncidentPage:
    items = await container.queries.incidents(status=status_filter, before=decode_cursor(cursor), limit=limit + 1)
    page = items[:limit]
    return IncidentPage(
        items=[summary(item) for item in page],
        next_cursor=encode_cursor(page[-1].opened_at, page[-1].id) if len(items) > limit else None,
    )


@router.get("/incidents/{incident_id}", response_model=IncidentDetail)
async def incident(
    incident_id: UUID, container: Container = Depends(get_container), _: AccessTokenClaims = Depends(viewer)
) -> IncidentDetail:
    detail = await container.queries.incident(incident_id)
    if detail is None:
        raise not_found("Incident not found")
    return detail


@router.get("/services/health", response_model=HealthHistory, summary="Historique de santé des services")
async def services_health(
    window: str = Query("15m", max_length=6),
    container: Container = Depends(get_container),
    _: AccessTokenClaims = Depends(viewer),
) -> HealthHistory:
    match = _WINDOW.match(window)
    if not match:
        raise ProblemException(422, "VALIDATION_ERROR", "Validation error", "window must look like 15m or 2h")
    amount, unit = int(match.group(1)), match.group(2)
    duration = timedelta(minutes=amount) if unit == "m" else timedelta(hours=amount)
    if duration > timedelta(hours=24):
        raise ProblemException(422, "VALIDATION_ERROR", "Validation error", "window must not exceed 24h")
    return await container.queries.health_history(duration)


@router.post("/stream-tickets", response_model=StreamTicketOut, status_code=201, summary="Ticket d'abonnement SSE (30 s)")
async def stream_ticket(
    container: Container = Depends(get_container), claims: AccessTokenClaims = Depends(viewer)
) -> StreamTicketOut:
    return StreamTicketOut(ticket=container.tickets.issue(claims), expires_in=container.tickets.ttl_seconds)


@router.get("/stream", response_class=StreamingResponse, summary="Flux temps réel de supervision")
async def stream(
    ticket: str = Query(min_length=10, max_length=4096),
    last_event_id: str | None = Header(None, alias="Last-Event-ID"),
    container: Container = Depends(get_container),
) -> StreamingResponse:
    try:
        claims = container.tickets.redeem(ticket)
    except TicketError as exc:
        AUTH_REJECTIONS.labels(reason=f"ticket_{exc.reason}").inc()
        raise unauthenticated("The stream ticket is invalid, expired or already used") from exc
    if not claims.has_any_role(ROLE_VIEWER, ROLE_ADMIN):
        raise unauthenticated("The stream ticket does not grant supervision access")

    revocations = container.security.revocations

    async def still_authorized() -> bool:
        return not revocations.is_revoked_ids(jti=claims.jti, sub=claims.sub, iat=claims.iat)

    async def body():
        with container.events.broadcaster.subscribe(lambda _event: True, parse_last_event_id(last_event_id)) as subscription:
            async for chunk in event_stream(subscription, not_after=claims.token_exp, still_authorized=still_authorized):
                yield chunk

    return StreamingResponse(
        body(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )
