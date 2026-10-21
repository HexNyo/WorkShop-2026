"""Transactions : création, transitions, exécution atomique (procédure SQL), lecture paginée."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from ra_common.db import Connection, Record

from app.domain.models import LedgerEntry, StatusChange, Transaction, TransactionStatus

_SELECT = """
SELECT t.id, t.initiator_principal_id, t.idempotency_key, t.request_fingerprint,
       t.debit_account_id, d.account_number AS debit_account_number, d.owner_principal_id AS debit_owner_id,
       t.credit_account_id, c.account_number AS credit_account_number, c.owner_principal_id AS credit_owner_id,
       t.amount_minor, t.currency, t.description, t.status, t.failure_code, t.failure_reason,
       t.is_synthetic, t.correlation_id, t.created_at, t.validated_at, t.executed_at, t.updated_at
  FROM ra_payment.transactions t
  JOIN ra_payment.accounts d ON d.id = t.debit_account_id
  JOIN ra_payment.accounts c ON c.id = t.credit_account_id
"""


def _to_transaction(row: Record) -> Transaction:
    return Transaction(
        id=UUID(str(row["id"])),
        initiator_principal_id=UUID(str(row["initiator_principal_id"])),
        idempotency_key=row["idempotency_key"],
        request_fingerprint=bytes(row["request_fingerprint"]),
        debit_account_id=UUID(str(row["debit_account_id"])),
        debit_account_number=row["debit_account_number"],
        debit_owner_id=UUID(str(row["debit_owner_id"])),
        credit_account_id=UUID(str(row["credit_account_id"])),
        credit_account_number=row["credit_account_number"],
        credit_owner_id=UUID(str(row["credit_owner_id"])),
        amount_minor=row["amount_minor"],
        currency=row["currency"],
        description=row["description"],
        status=TransactionStatus(row["status"]),
        failure_code=row["failure_code"],
        failure_reason=row["failure_reason"],
        is_synthetic=row["is_synthetic"],
        correlation_id=row["correlation_id"],
        created_at=row["created_at"],
        validated_at=row["validated_at"],
        executed_at=row["executed_at"],
        updated_at=row["updated_at"],
    )


class TransactionRepository:
    async def get(self, conn: Connection, transaction_id: UUID) -> Transaction | None:
        row = await conn.fetchrow(_SELECT + " WHERE t.id = $1", transaction_id)
        return _to_transaction(row) if row else None

    async def get_by_idempotency_key(self, conn: Connection, initiator: UUID, key: str) -> Transaction | None:
        row = await conn.fetchrow(_SELECT + " WHERE t.initiator_principal_id = $1 AND t.idempotency_key = $2", initiator, key)
        return _to_transaction(row) if row else None

    async def insert(
        self,
        conn: Connection,
        *,
        initiator: UUID,
        idempotency_key: str,
        fingerprint: bytes,
        debit_account_id: UUID,
        credit_account_id: UUID,
        amount_minor: int,
        currency: str,
        description: str | None,
        is_synthetic: bool,
        correlation_id: str | None,
    ) -> UUID:
        transaction_id = uuid4()
        await conn.execute(
            """
            INSERT INTO ra_payment.transactions (id, initiator_principal_id, idempotency_key, request_fingerprint,
                                                 debit_account_id, credit_account_id, amount_minor, currency,
                                                 description, is_synthetic, correlation_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            """,
            transaction_id,
            initiator,
            idempotency_key,
            fingerprint,
            debit_account_id,
            credit_account_id,
            amount_minor,
            currency,
            description,
            is_synthetic,
            correlation_id,
        )
        return transaction_id

    async def transition(
        self,
        conn: Connection,
        transaction_id: UUID,
        *,
        to_status: TransactionStatus,
        from_statuses: tuple[TransactionStatus, ...],
        failure_code: str | None = None,
        failure_reason: str | None = None,
    ) -> bool:
        """Transition conditionnelle : False si l'état courant ne fait pas partie de `from_statuses`."""
        allowed = ", ".join(f"${index}" for index in range(5, 5 + len(from_statuses)))
        result = await conn.execute(
            f"""
            UPDATE ra_payment.transactions
               SET status = $2, failure_code = $3, failure_reason = $4
             WHERE id = $1 AND status IN ({allowed})
            """,
            transaction_id,
            to_status.value,
            failure_code,
            failure_reason,
            *(status.value for status in from_statuses),
        )
        return result.endswith(" 1")

    async def execute(self, conn: Connection, transaction_id: UUID) -> TransactionStatus:
        """Primitive atomique en base (verrouillage ordonné, partie double, chaîne de hachage)."""
        row = await conn.fetchrow("CALL ra_payment.sp_execute_transaction($1)", transaction_id)
        return TransactionStatus(row["status"])

    async def history(self, conn: Connection, transaction_id: UUID) -> list[StatusChange]:
        rows = await conn.fetch(
            """
            SELECT to_status AS status, changed_at
              FROM ra_payment.transaction_status_history
             WHERE transaction_id = $1
             ORDER BY id
            """,
            transaction_id,
        )
        return [StatusChange(status=TransactionStatus(row["status"]), at=row["changed_at"]) for row in rows]

    async def list(
        self,
        conn: Connection,
        *,
        visible_to: UUID | None,
        initiator: UUID | None,
        synthetic: bool | None,
        status: TransactionStatus | None,
        account_id: UUID | None,
        before: tuple[datetime, UUID] | None,
        limit: int,
    ) -> list[Transaction]:
        rows = await conn.fetch(
            _SELECT
            + """
             WHERE ($1 IS NULL OR t.initiator_principal_id = $1
                               OR d.owner_principal_id = $1 OR c.owner_principal_id = $1)
               AND ($2 IS NULL OR t.initiator_principal_id = $2)
               AND ($3 IS NULL OR t.is_synthetic = $3)
               AND ($4 IS NULL OR t.status = $4)
               AND ($5 IS NULL OR t.debit_account_id = $5 OR t.credit_account_id = $5)
               AND ($6 IS NULL OR (t.created_at, t.id) < ($6, $7))
             ORDER BY t.created_at DESC, t.id DESC
             LIMIT $8
            """,
            visible_to,
            initiator,
            synthetic,
            status.value if status else None,
            account_id,
            before[0] if before else None,
            before[1] if before else None,
            limit,
        )
        return [_to_transaction(row) for row in rows]

    async def ledger(
        self, conn: Connection, account_id: UUID, *, before_seq: int | None, limit: int
    ) -> list[LedgerEntry]:
        rows = await conn.fetch(
            """
            SELECT account_seq, transaction_id, direction, amount_minor, currency,
                   balance_after_minor, entry_hash, created_at
              FROM ra_payment.ledger_entries
             WHERE account_id = $1 AND ($2 IS NULL OR account_seq < $2)
             ORDER BY account_seq DESC
             LIMIT $3
            """,
            account_id,
            before_seq,
            limit,
        )
        return [
            LedgerEntry(
                seq=row["account_seq"],
                transaction_id=UUID(str(row["transaction_id"])),
                direction=row["direction"],
                amount_minor=row["amount_minor"],
                currency=row["currency"],
                balance_after_minor=row["balance_after_minor"],
                entry_hash=bytes(row["entry_hash"]),
                created_at=row["created_at"],
            )
            for row in rows
        ]

    async def add_event(self, conn: Connection, payload: str) -> None:
        """Événement en outbox : visible des lecteurs uniquement si la transaction SQL est validée."""
        await conn.execute("INSERT INTO ra_payment.event_outbox (payload) VALUES ($1)", payload)

    async def events_since(self, conn: Connection, seconds: int) -> list[Record]:
        return await conn.fetch(
            "SELECT id, payload FROM ra_payment.event_outbox WHERE created_at >= CURRENT_TIMESTAMP(6) - INTERVAL $1 SECOND ORDER BY id",
            seconds,
        )

    async def purge_events(self, conn: Connection, older_than_seconds: int) -> None:
        await conn.execute(
            "DELETE FROM ra_payment.event_outbox WHERE created_at < CURRENT_TIMESTAMP(6) - INTERVAL $1 SECOND",
            older_than_seconds,
        )
