"""Server-Sent Events : tickets d'abonnement signés, diffusion avec reprise, formatage.

`EventSource` ne permet pas d'envoyer d'en-tête Authorization : le client échange
son jeton contre un ticket court (30 s), signé HMAC et à usage unique, qu'il passe
en paramètre d'URL. Le ticket est vérifiable sans état partagé (multi-instances) ;
l'usage unique est garanti par instance.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import hmac
import json
import secrets
import time
from collections import deque
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from ra_common.security.tokens import AccessTokenClaims

HEARTBEAT_SECONDS = 15.0


# ----------------------------------------------------------------------- tickets
class TicketError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class TicketClaims:
    sub: str
    jti: str
    iat: int
    token_exp: int
    roles: tuple[str, ...]
    pkind: str

    def has_any_role(self, *roles: str) -> bool:
        return any(role in self.roles for role in roles)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


class StreamTicketSigner:
    def __init__(self, secret: bytes, *, ttl_seconds: int = 30, purpose: str = "sse") -> None:
        if len(secret) < 32:
            raise ValueError("stream ticket secret must contain at least 32 bytes")
        self._key = hashlib.sha256(purpose.encode() + b"|" + secret).digest()
        self._ttl = ttl_seconds
        self._used: dict[str, float] = {}

    @property
    def ttl_seconds(self) -> int:
        return self._ttl

    def issue(self, claims: AccessTokenClaims) -> str:
        body = {
            "sub": claims.sub,
            "jti": claims.jti,
            "iat": claims.iat,
            "texp": claims.exp,
            "roles": list(claims.roles),
            "pkind": claims.pkind,
            "exp": int(time.time()) + self._ttl,
            "nonce": secrets.token_urlsafe(12),
        }
        encoded = _b64(json.dumps(body, separators=(",", ":")).encode())
        return f"st_{encoded}.{_b64(hmac.new(self._key, encoded.encode(), hashlib.sha256).digest())}"

    def redeem(self, ticket: str) -> TicketClaims:
        if not ticket.startswith("st_") or ticket.count(".") != 1:
            raise TicketError("malformed")
        encoded, signature = ticket[3:].split(".")
        expected = _b64(hmac.new(self._key, encoded.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(expected, signature):
            raise TicketError("bad_signature")
        try:
            body = json.loads(_unb64(encoded))
        except (ValueError, json.JSONDecodeError) as exc:
            raise TicketError("malformed") from exc
        now = time.time()
        if body.get("exp", 0) < now or body.get("texp", 0) < now:
            raise TicketError("expired")
        self._used = {nonce: exp for nonce, exp in self._used.items() if exp >= now}
        if body["nonce"] in self._used:
            raise TicketError("already_used")
        self._used[body["nonce"]] = body["exp"]
        return TicketClaims(
            sub=body["sub"],
            jti=body["jti"],
            iat=int(body["iat"]),
            token_exp=int(body["texp"]),
            roles=tuple(body.get("roles", ())),
            pkind=body.get("pkind", "USER"),
        )


# --------------------------------------------------------------------- diffusion
@dataclass(frozen=True, slots=True)
class StreamEvent:
    seq: int
    type: str
    envelope: dict[str, Any]
    meta: dict[str, Any]


EventFilter = Callable[[StreamEvent], bool]


@dataclass(eq=False)
class Subscription:
    filter: EventFilter
    queue: asyncio.Queue[StreamEvent] = field(default_factory=lambda: asyncio.Queue(maxsize=512))
    overflowed: bool = False


class EventBroadcaster:
    """Diffusion en mémoire vers les abonnés SSE avec tampon circulaire de reprise."""

    def __init__(self, buffer_size: int = 1000) -> None:
        self._buffer: deque[StreamEvent] = deque(maxlen=buffer_size)
        self._subscribers: set[Subscription] = set()
        self._seq = 0

    @property
    def last_seq(self) -> int:
        return self._seq

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)

    def publish(
        self,
        event_type: str,
        payload: dict[str, Any],
        *,
        incident_id: str | None = None,
        meta: dict[str, Any] | None = None,
        occurred_at: str | None = None,
    ) -> StreamEvent:
        self._seq += 1
        envelope: dict[str, Any] = {
            "type": event_type,
            "seq": self._seq,
            "occurred_at": occurred_at
            or datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "payload": payload,
        }
        if incident_id is not None:
            envelope["incident_id"] = incident_id
        event = StreamEvent(seq=self._seq, type=event_type, envelope=envelope, meta=meta or {})
        self._buffer.append(event)
        for subscription in list(self._subscribers):
            if not subscription.filter(event):
                continue
            try:
                subscription.queue.put_nowait(event)
            except asyncio.QueueFull:
                # Client trop lent : il est déconnecté et devra recharger l'état.
                subscription.overflowed = True
        return event

    @contextlib.contextmanager
    def subscribe(self, event_filter: EventFilter, last_event_id: int | None = None):
        subscription = Subscription(filter=event_filter)
        if last_event_id is not None:
            oldest = self._buffer[0].seq if self._buffer else self._seq + 1
            if last_event_id < oldest - 1:
                subscription.queue.put_nowait(
                    StreamEvent(
                        seq=self._seq,
                        type="stream.reset",
                        envelope={
                            "type": "stream.reset",
                            "seq": self._seq,
                            "occurred_at": datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                            "payload": {"reason": "replay window exceeded"},
                        },
                        meta={},
                    )
                )
            else:
                for event in self._buffer:
                    if event.seq > last_event_id and event_filter(event):
                        subscription.queue.put_nowait(event)
        self._subscribers.add(subscription)
        try:
            yield subscription
        finally:
            self._subscribers.discard(subscription)


def format_event(event: StreamEvent) -> str:
    data = json.dumps(event.envelope, separators=(",", ":"), ensure_ascii=False, default=str)
    return f"id: {event.seq}\nevent: {event.type}\ndata: {data}\n\n"


def parse_last_event_id(value: str | None) -> int | None:
    if value and value.isdigit():
        return int(value)
    return None


async def event_stream(
    subscription: Subscription,
    *,
    not_after: float,
    still_authorized: Callable[[], Awaitable[bool]],
    heartbeat_seconds: float = HEARTBEAT_SECONDS,
) -> AsyncIterator[str]:
    """Générateur SSE : événements, battements de cœur, fermeture à l'expiration du jeton
    ou dès que le principal est révoqué."""
    yield "retry: 3000\n\n"
    while True:
        remaining = not_after - time.time()
        if remaining <= 0:
            yield 'event: stream.expired\ndata: {"reason":"token expired"}\n\n'
            return
        try:
            event = await asyncio.wait_for(subscription.queue.get(), timeout=min(heartbeat_seconds, remaining))
        except TimeoutError:
            if not await still_authorized():
                yield 'event: stream.revoked\ndata: {"reason":"access revoked"}\n\n'
                return
            yield ": heartbeat\n\n"
            continue
        if subscription.overflowed:
            yield 'event: stream.reset\ndata: {"reason":"client too slow"}\n\n'
            return
        yield format_event(event)
