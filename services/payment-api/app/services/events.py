"""Événements temps réel des transactions.

Publication : ligne d'outbox écrite DANS la transaction SQL métier — elle n'est
visible qu'après COMMIT, donc jamais d'événement pour une écriture annulée.
Réception : chaque instance relit l'outbox récente (MariaDB n'a pas de LISTEN/NOTIFY)
et alimente son diffuseur SSE ; toutes les instances voient ainsi tous les événements.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
from typing import Any

from ra_common.db import Connection, Database
from ra_common.sse import EventBroadcaster, StreamEvent, TicketClaims

from app.domain.models import ROLE_OPERATOR, ROLE_SYNTHETIC, Transaction
from app.domain.money import format_minor
from app.repositories.transactions import TransactionRepository

logger = logging.getLogger("payment.events")


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

    async def publish(self, conn: Connection, event_type: str, transaction: Transaction) -> None:
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
        await self._repository.add_event(conn, json.dumps(message, separators=(",", ":")))


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
    """Relit l'outbox toutes les POLL_SECONDS ; chaque id n'est diffusé qu'une fois.

    shortcut: un COMMIT survenant plus de WINDOW_SECONDS après l'écriture de l'événement est
    manqué (les requêtes sont bornées à quelques secondes) ; passer à un curseur par id + délai
    de garde si des transactions longues apparaissent.
    """

    POLL_SECONDS = 0.5
    WINDOW_SECONDS = 30
    RETENTION_SECONDS = 300

    def __init__(self, db: Database, broadcaster: EventBroadcaster) -> None:
        self._db = db
        self._broadcaster = broadcaster
        self._repository = TransactionRepository()
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

    def _publish(self, payload: str) -> None:
        try:
            message = json.loads(payload)
            self._broadcaster.publish(message["type"], message["payload"], meta=message.get("meta", {}))
        except (ValueError, KeyError, TypeError):
            logger.exception("invalid event notification", extra={"event": "events.invalid_notification"})

    async def _run(self) -> None:
        seen: set[int] | None = None  # None : premier passage, l'historique n'est pas rediffusé
        purged_at = 0.0
        while True:
            try:
                async with self._db.connection() as conn:
                    rows = await self._repository.events_since(conn, self.WINDOW_SECONDS)
                    if time.monotonic() - purged_at > 60:
                        await self._repository.purge_events(conn, self.RETENTION_SECONDS)
                        purged_at = time.monotonic()
                if seen is not None:
                    for row in rows:
                        if row["id"] not in seen:
                            self._publish(row["payload"])
                seen = {row["id"] for row in rows}
                if not self._connected:
                    logger.info("listening for transaction events", extra={"event": "events.listening"})
                self._connected = True
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - le superviseur doit survivre à toute panne
                if self._connected:
                    logger.warning(
                        "event listener disconnected (%s)", exc.__class__.__name__, extra={"event": "events.listener_down"}
                    )
                self._connected = False
            await asyncio.sleep(self.POLL_SECONDS)
