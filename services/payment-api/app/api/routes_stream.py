"""Flux temps réel des transactions (Server-Sent Events)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Header, Query, Request
from ra_common.metrics import AUTH_REJECTIONS
from ra_common.problem import unauthenticated
from ra_common.security import AccessTokenClaims, require_roles
from ra_common.sse import TicketError, event_stream, parse_last_event_id
from starlette.responses import StreamingResponse

from app.api.deps import get_container
from app.api.schemas import StreamTicketOut
from app.container import Container
from app.domain.models import ROLE_CUSTOMER, ROLE_OPERATOR, ROLE_SYNTHETIC
from app.observability import SSE_SUBSCRIBERS
from app.services.events import visibility_filter

router = APIRouter(prefix="/v1", tags=["stream"])


@router.post("/stream-tickets", response_model=StreamTicketOut, status_code=201, summary="Ticket d'abonnement SSE (30 s)")
async def stream_ticket(
    container: Container = Depends(get_container),
    claims: AccessTokenClaims = Depends(require_roles(ROLE_CUSTOMER, ROLE_OPERATOR, ROLE_SYNTHETIC)),
) -> StreamTicketOut:
    return StreamTicketOut(ticket=container.tickets.issue(claims), expires_in=container.tickets.ttl_seconds)


@router.get(
    "/transactions/events",
    summary="Flux SSE transaction.created / transaction.updated",
    response_class=StreamingResponse,
)
async def transaction_events(
    request: Request,
    ticket: str = Query(min_length=10, max_length=4096),
    last_event_id: str | None = Header(None, alias="Last-Event-ID"),
    container: Container = Depends(get_container),
) -> StreamingResponse:
    try:
        claims = container.tickets.redeem(ticket)
    except TicketError as exc:
        AUTH_REJECTIONS.labels(reason=f"ticket_{exc.reason}").inc()
        raise unauthenticated("The stream ticket is invalid, expired or already used") from exc

    revocations = container.security.revocations

    async def still_authorized() -> bool:
        return not revocations.is_revoked_ids(jti=claims.jti, sub=claims.sub, iat=claims.iat)

    async def body():
        with container.broadcaster.subscribe(visibility_filter(claims), parse_last_event_id(last_event_id)) as sub:
            SSE_SUBSCRIBERS.set(container.broadcaster.subscriber_count)
            try:
                async for chunk in event_stream(sub, not_after=claims.token_exp, still_authorized=still_authorized):
                    yield chunk
            finally:
                SSE_SUBSCRIBERS.set(container.broadcaster.subscriber_count - 1)

    return StreamingResponse(
        body(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )
