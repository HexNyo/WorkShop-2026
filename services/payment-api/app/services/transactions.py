"""Cas d'usage transactionnels : initiation, validation, exécution, annulation, lecture."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from ra_common.context import correlation_id_var
from ra_common.db import Connection, Database, DatabaseError, UniqueViolationError, sqlstate
from ra_common.logging import log_event

from app.domain.errors import (
    AmountLimitExceeded,
    CurrencyMismatch,
    Forbidden,
    IdempotencyConflict,
    InvalidState,
    ResourceNotFound,
    SyntheticSegregation,
    ValidationFailure,
)
from app.domain.models import (
    Account,
    Caller,
    CreateTransactionCommand,
    LedgerEntry,
    StatusChange,
    Transaction,
    TransactionStatus,
)
from app.domain.money import InvalidAmount, to_minor
from app.domain.policies import can_read, can_read_account, ensure_writable, owns_account, request_fingerprint
from app.observability import AMOUNT, DIVERGENCE, PROCESSING, REPLAYS, TRANSACTIONS
from app.repositories.accounts import AccountRepository
from app.repositories.transactions import TransactionRepository
from app.services.events import TransactionEventPublisher
from app.services.runtime_flags import RuntimeFlagsProvider

logger = logging.getLogger("payment.transactions")

SQLSTATE_LEDGER_DIVERGENCE = "RA009"
SQLSTATE_INVALID_STATE = "RA002"
OPEN_STATUSES = (TransactionStatus.PENDING, TransactionStatus.VALIDATED)


@dataclass(frozen=True, slots=True)
class CreateOutcome:
    transaction: Transaction
    created: bool


class TransactionService:
    def __init__(
        self,
        *,
        db: Database,
        accounts: AccountRepository,
        transactions: TransactionRepository,
        flags: RuntimeFlagsProvider,
        events: TransactionEventPublisher,
        currencies: dict[str, int],
    ) -> None:
        self._db = db
        self._accounts = accounts
        self._transactions = transactions
        self._flags = flags
        self._events = events
        self._currencies = currencies

    # ---------------------------------------------------------------- création
    async def create(self, caller: Caller, cmd: CreateTransactionCommand) -> CreateOutcome:
        started = time.perf_counter()
        if not caller.can_initiate:
            raise Forbidden("This principal may not initiate transactions")
        flags = await self._flags.get()
        ensure_writable(flags, caller)

        minor_units = self._currencies.get(cmd.currency)
        if minor_units is None:
            raise ValidationFailure("body.amount.currency", "unsupported currency")
        try:
            amount_minor = to_minor(cmd.amount_value, minor_units)
        except InvalidAmount as exc:
            raise ValidationFailure("body.amount.value", str(exc)) from exc
        if amount_minor > flags.max_transaction_amount_minor:
            raise AmountLimitExceeded(
                f"Amount exceeds the current per-transaction limit ({flags.max_transaction_amount_minor} minor units)"
            )
        fingerprint = request_fingerprint(cmd, amount_minor)

        async with self._db.transaction() as conn:
            existing = await self._transactions.get_by_idempotency_key(conn, caller.id, cmd.idempotency_key)
            if existing is not None:
                return self._replay(existing, fingerprint)

            debit = await self._accounts.get(conn, cmd.debit_account_id)
            if debit is None or not owns_account(caller, debit):
                raise ResourceNotFound("Debit account not found")
            credit = await self._accounts.get_by_number(conn, cmd.credit_account_number)
            if credit is None:
                raise ValidationFailure("body.credit_account_number", "unknown account")
            if credit.id == debit.id:
                raise ValidationFailure("body.credit_account_number", "must differ from the debit account")
            if debit.currency != cmd.currency or credit.currency != cmd.currency:
                raise CurrencyMismatch(
                    f"Transaction currency {cmd.currency} does not match accounts ({debit.currency} -> {credit.currency})"
                )
            if credit.is_synthetic != caller.is_synthetic:
                raise SyntheticSegregation("Synthetic and real accounts cannot exchange funds")

            try:
                async with conn.transaction():  # savepoint : course sur la clé d'idempotence
                    transaction_id = await self._transactions.insert(
                        conn,
                        initiator=caller.id,
                        idempotency_key=cmd.idempotency_key,
                        fingerprint=fingerprint,
                        debit_account_id=debit.id,
                        credit_account_id=credit.id,
                        amount_minor=amount_minor,
                        currency=cmd.currency,
                        description=cmd.description,
                        is_synthetic=caller.is_synthetic,
                        correlation_id=correlation_id_var.get(),
                    )
            except UniqueViolationError as exc:
                if exc.constraint_name != "uq_transactions_idempotency":
                    raise
                concurrent = await self._transactions.get_by_idempotency_key(conn, caller.id, cmd.idempotency_key)
                return self._replay(concurrent, fingerprint)

            await self._events.publish(conn, "transaction.created", await self._transactions.get(conn, transaction_id))
            validated = await self._validate(conn, transaction_id, debit, credit)
            if validated and cmd.auto_execute:
                await self._execute(conn, transaction_id)
            transaction = await self._transactions.get(conn, transaction_id)
            await self._events.publish(conn, "transaction.updated", transaction)

        self._record(transaction, started)
        return CreateOutcome(transaction=transaction, created=True)

    def _replay(self, existing: Transaction, fingerprint: bytes) -> CreateOutcome:
        if existing.request_fingerprint != fingerprint:
            raise IdempotencyConflict("This Idempotency-Key was already used with a different request payload")
        REPLAYS.inc()
        return CreateOutcome(transaction=existing, created=False)

    async def _validate(self, conn: Connection, transaction_id: UUID, debit: Account, credit: Account) -> bool:
        """Contrôles métier ; renvoie True si la transaction est VALIDATED (exécutable)."""
        if debit.status != "ACTIVE" or credit.status != "ACTIVE":
            await self._transactions.transition(
                conn,
                transaction_id,
                to_status=TransactionStatus.REJECTED,
                from_statuses=(TransactionStatus.PENDING,),
                failure_code="ACCOUNT_NOT_ACTIVE",
                failure_reason=f"debit account {debit.status}, credit account {credit.status}",
            )
            return False
        return await self._transactions.transition(
            conn, transaction_id, to_status=TransactionStatus.VALIDATED, from_statuses=(TransactionStatus.PENDING,)
        )

    async def _execute(self, conn: Connection, transaction_id: UUID) -> None:
        """Exécution dans un savepoint : une divergence détectée en base (RA009) est
        historisée en FAILED au lieu d'annuler toute la demande."""
        try:
            async with conn.transaction():
                await self._transactions.execute(conn, transaction_id)
        except DatabaseError as exc:
            if sqlstate(exc) != SQLSTATE_LEDGER_DIVERGENCE:
                raise
            DIVERGENCE.inc()
            log_event(
                logger,
                logging.ERROR,
                "integrity.divergence_detected",
                "balance/ledger divergence detected: transaction refused",
                transaction_id=str(transaction_id),
                detail=getattr(exc, "detail", None),
            )
            await self._transactions.transition(
                conn,
                transaction_id,
                to_status=TransactionStatus.FAILED,
                from_statuses=(TransactionStatus.VALIDATED,),
                failure_code="LEDGER_INTEGRITY_FAULT",
                failure_reason="balance/ledger divergence detected; transaction refused for safety",
            )

    def _record(self, transaction: Transaction, started: float) -> None:
        status = transaction.status.value
        TRANSACTIONS.labels(status=status, synthetic=str(transaction.is_synthetic).lower()).inc()
        PROCESSING.labels(outcome=status).observe(time.perf_counter() - started)
        if transaction.status is TransactionStatus.EXECUTED:
            AMOUNT.labels(currency=transaction.currency).inc(transaction.amount_minor)
        log_event(
            logger,
            logging.INFO if status in ("EXECUTED", "VALIDATED") else logging.WARNING,
            f"transaction.{status.lower()}",
            f"transaction {status.lower()}",
            transaction_id=str(transaction.id),
            amount_minor=transaction.amount_minor,
            currency=transaction.currency,
            synthetic=transaction.is_synthetic,
            failure_code=transaction.failure_code,
        )

    # ------------------------------------------------- exécution / annulation
    async def execute(self, caller: Caller, transaction_id: UUID) -> Transaction:
        started = time.perf_counter()
        ensure_writable(await self._flags.get(), caller)
        async with self._db.transaction() as conn:
            transaction = await self._owned(conn, caller, transaction_id)
            if transaction.status is TransactionStatus.EXECUTED:
                return transaction
            if transaction.status is not TransactionStatus.VALIDATED:
                raise InvalidState(f"Transaction is {transaction.status.value}; only VALIDATED transactions can be executed")
            try:
                await self._execute(conn, transaction_id)
            except DatabaseError as exc:
                if sqlstate(exc) == SQLSTATE_INVALID_STATE:
                    raise InvalidState("Transaction state changed concurrently") from exc
                raise
            transaction = await self._transactions.get(conn, transaction_id)
            await self._events.publish(conn, "transaction.updated", transaction)
        self._record(transaction, started)
        return transaction

    async def cancel(self, caller: Caller, transaction_id: UUID) -> Transaction:
        ensure_writable(await self._flags.get(), caller)
        async with self._db.transaction() as conn:
            transaction = await self._owned(conn, caller, transaction_id)
            changed = await self._transactions.transition(
                conn, transaction_id, to_status=TransactionStatus.CANCELLED, from_statuses=OPEN_STATUSES
            )
            if not changed:
                raise InvalidState(f"Transaction is {transaction.status.value}; it can no longer be cancelled")
            transaction = await self._transactions.get(conn, transaction_id)
            await self._events.publish(conn, "transaction.updated", transaction)
        TRANSACTIONS.labels(status="CANCELLED", synthetic=str(transaction.is_synthetic).lower()).inc()
        return transaction

    async def _owned(self, conn: Connection, caller: Caller, transaction_id: UUID) -> Transaction:
        transaction = await self._transactions.get(conn, transaction_id)
        if transaction is None or transaction.initiator_principal_id != caller.id:
            raise ResourceNotFound("Transaction not found")
        return transaction

    # ----------------------------------------------------------------- lecture
    async def get(self, caller: Caller, transaction_id: UUID) -> tuple[Transaction, list[StatusChange]]:
        async with self._db.connection() as conn:
            transaction = await self._transactions.get(conn, transaction_id)
            if transaction is None or not can_read(caller, transaction):
                raise ResourceNotFound("Transaction not found")
            return transaction, await self._transactions.history(conn, transaction_id)

    async def list(
        self,
        caller: Caller,
        *,
        status: TransactionStatus | None,
        account_id: UUID | None,
        synthetic: bool | None,
        before: tuple[datetime, UUID] | None,
        limit: int,
    ) -> list[Transaction]:
        if caller.is_synthetic:
            visible_to, initiator, synthetic = None, caller.id, True
        elif caller.is_operator:
            visible_to, initiator, synthetic = None, None, (False if synthetic is None else synthetic)
        else:
            visible_to, initiator, synthetic = caller.id, None, False
        async with self._db.connection() as conn:
            return await self._transactions.list(
                conn,
                visible_to=visible_to,
                initiator=initiator,
                synthetic=synthetic,
                status=status,
                account_id=account_id,
                before=before,
                limit=limit,
            )

    async def list_accounts(self, caller: Caller, *, include_synthetic: bool) -> list[Account]:
        async with self._db.connection() as conn:
            if caller.is_synthetic:
                return await self._accounts.list(conn, owner_id=None, synthetic=True)
            if caller.is_operator:
                return await self._accounts.list(conn, owner_id=None, synthetic=None if include_synthetic else False)
            return await self._accounts.list(conn, owner_id=caller.id, synthetic=False)

    async def get_account(self, caller: Caller, account_id: UUID) -> Account:
        async with self._db.connection() as conn:
            account = await self._accounts.get(conn, account_id)
        if account is None or not can_read_account(caller, account):
            raise ResourceNotFound("Account not found")
        return account

    async def ledger(
        self, caller: Caller, account_id: UUID, *, before_seq: int | None, limit: int
    ) -> tuple[Account, list[LedgerEntry]]:
        account = await self.get_account(caller, account_id)
        async with self._db.connection() as conn:
            return account, await self._transactions.ledger(conn, account_id, before_seq=before_seq, limit=limit)
