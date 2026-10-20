"""Événements temps réel des transactions.

Publication : `pg_notify` DANS la transaction SQL métier — PostgreSQL ne délivre la
notification qu'au COMMIT, donc jamais d'événement pour une écriture annulée.
Réception : une connexion LISTEN dédiée par instance alimente le diffuseur SSE ;
toutes les instances voient ainsi tous les événements.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from typing import Any

import asyncpg
from ra_common.db import Database
from ra_common.sse import EventBroadcaster, StreamEvent, TicketClaims

from app.domain.models import ROLE_OPERATOR, ROLE_SYNTHETIC, Transaction
from app.domain.money import format_minor
from app.repositories.transactions import TransactionRepository

logger = logging.getLogger("payment.events")
CHANNEL = "payment_events"


def transaction_payload(transaction: Transaction, minor_units: int) -> dict[str, Any]:
    return {
        "id": str(transaction.id),
        "status": transaction.status.value,
        "debit_account_number": transaction.debit_account_number,
        "credit_account_number": transaction.credit_account_number,
        "amount": {
            "value": format_minor(transaction.amount_minor, minor_units),
            "currency": transaction.currency,
            "minor": transaction.amount_minor,
        },
        "failure": (
            {"code": transaction.failure_code, "reason": transaction.failure_reason} if transaction.failure_code else None
        ),
        "is_synthetic": transaction.is_synthetic,
        "updated_at": transaction.updated_at.isoformat(),
    }


class TransactionEventPublisher:
    def __init__(self, repository: TransactionRepository, currencies: dict[str, int]) -> None:
        self._repository = repository
        self._currencies = currencies

    async def publish(self, conn: asyncpg.Connection, event_type: str, transaction: Transaction) -> None:
        message = {
            "type": event_type,
            "payload": transaction_payload(transaction, self._currencies[transaction.currency]),
            "meta": {
                "initiator": str(transaction.initiator_principal_id),
                "debit_owner": str(transaction.debit_owner_id),
                "credit_owner": str(transaction.credit_owner_id),
                "synthetic": transaction.is_synthetic,
            },
        }
        await self._repository.notify(conn, CHANNEL, json.dumps(message, separators=(",", ":")))


def visibility_filter(ticket: TicketClaims):
    """Un abonné ne reçoit que les transactions qu'il a le droit de lire (mêmes règles que l'API)."""
    synthetic = ROLE_SYNTHETIC in ticket.roles
    operator = ROLE_OPERATOR in ticket.roles

    def accept(event: StreamEvent) -> bool:
        meta = event.meta
        if synthetic:
            return bool(meta.get("synthetic")) and meta.get("initiator") == ticket.sub
        if operator:
            return True
        return ticket.sub in (meta.get("initiator"), meta.get("debit_owner"), meta.get("credit_owner"))

    return accept


class TransactionEventListener:
    def __init__(self, db: Database, broadcaster: EventBroadcaster) -> None:
        self._db = db
        self._broadcaster = broadcaster
        self._task: asyncio.Task[None] | None = None
        self._connected = False

    @property
    def connected(self) -> bool:
        return self._connected

    def start(self) -> None:
        self._task = asyncio.create_task(self._run(), name="payment-events-listener")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task

    def _on_notification(self, _conn: Any, _pid: int, _channel: str, payload: str) -> None:
        try:
            message = json.loads(payload)
            self._broadcaster.publish(message["type"], message["payload"], meta=message.get("meta", {}))
        except (ValueError, KeyError, TypeError):
            logger.exception("invalid event notification", extra={"event": "events.invalid_notification"})

    async def _run(self) -> None:
        delay = 0.5
        while True:
            terminated = asyncio.Event()
            connection: asyncpg.Connection | None = None
            try:
                connection = await asyncpg.connect(**self._db.connect_kwargs, timeout=5)
                connection.add_termination_listener(lambda _conn: terminated.set())
                await connection.add_listener(CHANNEL, self._on_notification)
                self._connected = True
                delay = 0.5
                logger.info("listening for transaction events", extra={"event": "events.listening"})
                while not terminated.is_set():
                    # Sonde périodique : détecte une connexion à moitié ouverte.
                    with contextlib.suppress(TimeoutError):
                        await asyncio.wait_for(terminated.wait(), timeout=15)
                    if not terminated.is_set():
                        await connection.fetchval("SELECT 1", timeout=5)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - le superviseur doit survivre à toute panne
                logger.warning(
                    "event listener disconnected (%s), reconnecting in %.1fs",
                    exc.__class__.__name__,
                    delay,
                    extra={"event": "events.listener_down"},
                )
            finally:
                self._connected = False
                if connection is not None and not connection.is_closed():
                    with contextlib.suppress(Exception):
                        await connection.close(timeout=2)
            await asyncio.sleep(delay)
            delay = min(delay * 2, 10.0)
