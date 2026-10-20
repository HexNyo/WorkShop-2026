"""Transactions : création, transitions, exécution atomique (fonction SQL), lecture paginée."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

import asyncpg

from app.domain.models import LedgerEntry, StatusChange, Transaction, TransactionStatus

_SELECT = """
SELECT t.id, t.initiator_principal_id, t.idempotency_key, t.request_fingerprint,
       t.debit_account_id, d.account_number AS debit_account_number, d.owner_principal_id AS debit_owner_id,
       t.credit_account_id, c.account_number AS credit_account_number, c.owner_principal_id AS credit_owner_id,
       t.amount_minor, t.currency, t.description, t.status::text AS status, t.failure_code, t.failure_reason,
       t.is_synthetic, t.correlation_id, t.created_at, t.validated_at, t.executed_at, t.updated_at
  FROM payment.transactions t
  JOIN payment.accounts d ON d.id = t.debit_account_id
  JOIN payment.accounts c ON c.id = t.credit_account_id
"""


def _to_transaction(row: asyncpg.Record) -> Transaction:
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
    async def get(self, conn: asyncpg.Connection, transaction_id: UUID) -> Transaction | None:
        row = await conn.fetchrow(_SELECT + " WHERE t.id = $1", transaction_id)
        return _to_transaction(row) if row else None

    async def get_by_idempotency_key(self, conn: asyncpg.Connection, initiator: UUID, key: str) -> Transaction | None:
        row = await conn.fetchrow(_SELECT + " WHERE t.initiator_principal_id = $1 AND t.idempotency_key = $2", initiator, key)
        return _to_transaction(row) if row else None

    async def insert(
        self,
        conn: asyncpg.Connection,
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
        value = await conn.fetchval(
            """
            INSERT INTO payment.transactions (initiator_principal_id, idempotency_key, request_fingerprint,
                                              debit_account_id, credit_account_id, amount_minor, currency,
                                              description, is_synthetic, correlation_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING id
            """,
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
        return UUID(str(value))

    async def transition(
        self,
        conn: asyncpg.Connection,
        transaction_id: UUID,
        *,
        to_status: TransactionStatus,
        from_statuses: tuple[TransactionStatus, ...],
        failure_code: str | None = None,
        failure_reason: str | None = None,
    ) -> bool:
        """Transition conditionnelle : False si l'état courant ne fait pas partie de `from_statuses`."""
        result = await conn.execute(
            """
            UPDATE payment.transactions
               SET status = $2::payment.transaction_status, failure_code = $3, failure_reason = $4
             WHERE id = $1 AND status = ANY($5::payment.transaction_status[])
            """,
            transaction_id,
            to_status.value,
            failure_code,
            failure_reason,
            [status.value for status in from_statuses],
        )
        return result.endswith(" 1")

    async def execute(self, conn: asyncpg.Connection, transaction_id: UUID) -> TransactionStatus:
        """Primitive atomique en base (verrouillage ordonné, partie double, chaîne de hachage)."""
        status = await conn.fetchval("SELECT status::text FROM payment.fn_execute_transaction($1)", transaction_id)
        return TransactionStatus(status)

    async def history(self, conn: asyncpg.Connection, transaction_id: UUID) -> list[StatusChange]:
        rows = await conn.fetch(
            """
            SELECT to_status::text AS status, changed_at
              FROM payment.transaction_status_history
             WHERE transaction_id = $1
             ORDER BY id
            """,
            transaction_id,
        )
        return [StatusChange(status=TransactionStatus(row["status"]), at=row["changed_at"]) for row in rows]

    async def list(
        self,
        conn: asyncpg.Connection,
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
             WHERE ($1::uuid IS NULL OR t.initiator_principal_id = $1
                                     OR d.owner_principal_id = $1 OR c.owner_principal_id = $1)
               AND ($2::uuid IS NULL OR t.initiator_principal_id = $2)
               AND ($3::boolean IS NULL OR t.is_synthetic = $3)
               AND ($4::text IS NULL OR t.status = $4::payment.transaction_status)
               AND ($5::uuid IS NULL OR t.debit_account_id = $5 OR t.credit_account_id = $5)
               AND ($6::timestamptz IS NULL OR (t.created_at, t.id) < ($6, $7::uuid))
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
        self, conn: asyncpg.Connection, account_id: UUID, *, before_seq: int | None, limit: int
    ) -> list[LedgerEntry]:
        rows = await conn.fetch(
            """
            SELECT account_seq, transaction_id, direction::text AS direction, amount_minor, currency,
                   balance_after_minor, entry_hash, created_at
              FROM payment.ledger_entries
             WHERE account_id = $1 AND ($2::bigint IS NULL OR account_seq < $2)
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

    async def notify(self, conn: asyncpg.Connection, channel: str, payload: str) -> None:
        """Notification délivrée par PostgreSQL uniquement si la transaction SQL est validée."""
        await conn.execute("SELECT pg_notify($1, $2)", channel, payload)
