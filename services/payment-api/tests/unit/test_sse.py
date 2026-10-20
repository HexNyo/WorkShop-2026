"""Tickets SSE, diffusion avec reprise et filtrage par visibilité."""

from __future__ import annotations

import asyncio
import time

import pytest
from ra_common.security.tokens import AccessTokenClaims
from ra_common.sse import EventBroadcaster, StreamTicketSigner, TicketError, event_stream, format_event

from app.services.events import visibility_filter

SECRET = b"s" * 48


def claims(sub: str, roles: tuple[str, ...], exp_offset: int = 300) -> AccessTokenClaims:
    now = int(time.time())
    return AccessTokenClaims(
        iss="i", sub=sub, aud=["payment-api"], iat=now, nbf=now, exp=now + exp_offset, jti=f"jti-{sub}",
        typ="access", pkind="USER", name="n", roles=roles,
    )


def test_ticket_round_trip_single_use_and_tamper() -> None:
    signer = StreamTicketSigner(SECRET, ttl_seconds=30)
    ticket = signer.issue(claims("alice", ("payment.customer",)))
    redeemed = signer.redeem(ticket)
    assert redeemed.sub == "alice" and redeemed.roles == ("payment.customer",)
    with pytest.raises(TicketError, match="already_used"):
        signer.redeem(ticket)

    other = signer.issue(claims("alice", ("payment.customer",)))
    body, signature = other.split(".")
    with pytest.raises(TicketError, match="bad_signature"):
        signer.redeem(body[:-2] + "AA." + signature)
    with pytest.raises(TicketError, match="bad_signature"):
        StreamTicketSigner(b"x" * 48).redeem(other)
    with pytest.raises(TicketError, match="malformed"):
        signer.redeem("garbage")


def test_ticket_expires_with_token_or_ttl() -> None:
    signer = StreamTicketSigner(SECRET, ttl_seconds=30)
    with pytest.raises(TicketError, match="expired"):
        signer.redeem(signer.issue(claims("alice", (), exp_offset=-1)))
    with pytest.raises(ValueError):
        StreamTicketSigner(b"short")


def _publish(broadcaster: EventBroadcaster, initiator: str, credit_owner: str, synthetic: bool = False) -> None:
    broadcaster.publish(
        "transaction.updated",
        {"id": initiator},
        meta={"initiator": initiator, "debit_owner": initiator, "credit_owner": credit_owner, "synthetic": synthetic},
    )


async def test_visibility_filter_and_replay() -> None:
    signer = StreamTicketSigner(SECRET)
    broadcaster = EventBroadcaster(buffer_size=10)
    alice = signer.redeem(signer.issue(claims("alice", ("payment.customer",))))
    operator = signer.redeem(signer.issue(claims("op", ("payment.operator",))))

    _publish(broadcaster, "bob", "alice")      # seq 1 : alice bénéficiaire -> visible
    _publish(broadcaster, "bob", "carol")      # seq 2 : invisible pour alice
    _publish(broadcaster, "svc", "svc", True)  # seq 3 : synthétique

    with broadcaster.subscribe(visibility_filter(alice), last_event_id=0) as subscription:
        assert subscription.queue.qsize() == 1
        assert subscription.queue.get_nowait().seq == 1
        _publish(broadcaster, "alice", "bob")
        assert subscription.queue.get_nowait().seq == 4

    with broadcaster.subscribe(visibility_filter(operator), last_event_id=1) as subscription:
        assert [subscription.queue.get_nowait().seq for _ in range(subscription.queue.qsize())] == [2, 3, 4]
    assert broadcaster.subscriber_count == 0


async def test_replay_window_exceeded_sends_reset() -> None:
    broadcaster = EventBroadcaster(buffer_size=2)
    for _ in range(5):
        _publish(broadcaster, "a", "a")
    with broadcaster.subscribe(lambda _: True, last_event_id=1) as subscription:
        assert subscription.queue.get_nowait().type == "stream.reset"


async def test_event_stream_formats_and_stops_on_revocation() -> None:
    broadcaster = EventBroadcaster()
    revoked = asyncio.Event()

    async def still_authorized() -> bool:
        return not revoked.is_set()

    with broadcaster.subscribe(lambda _: True) as subscription:
        _publish(broadcaster, "a", "b")
        stream = event_stream(subscription, not_after=time.time() + 60, still_authorized=still_authorized, heartbeat_seconds=0.05)
        assert (await anext(stream)).startswith("retry:")
        chunk = await anext(stream)
        assert chunk.startswith("id: 1\nevent: transaction.updated\ndata: {")
        assert await anext(stream) == ": heartbeat\n\n"
        revoked.set()
        assert (await anext(stream)).startswith("event: stream.revoked")
        with pytest.raises(StopAsyncIteration):
            await anext(stream)


def test_format_event_is_single_data_line() -> None:
    broadcaster = EventBroadcaster()
    event = broadcaster.publish("x", {"text": "multi\nline"})
    rendered = format_event(event)
    assert rendered.count("\ndata: ") == 1 and rendered.endswith("\n\n")
