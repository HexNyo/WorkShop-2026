"""DTO d'entrée/sortie (validation stricte, aucun champ inconnu accepté)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.core.config import ACCOUNT_NUMBER_PATTERN
from app.domain.models import Account, LedgerEntry, StatusChange, Transaction
from app.domain.money import AMOUNT_PATTERN, format_minor

IDEMPOTENCY_KEY_PATTERN = r"^[A-Za-z0-9_:.-]{8,64}$"
FAULT_TYPES = Literal["LATENCY", "ERROR_RATE", "READINESS_FAILURE", "POOL_EXHAUSTION", "CRASH", "BALANCE_TAMPER"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


# =================================================================== entrées
class MoneyIn(StrictModel):
    value: str = Field(pattern=AMOUNT_PATTERN, examples=["125.50"])
    currency: str = Field(pattern=r"^[A-Z]{3}$", examples=["EUR"])


class CreateTransactionRequest(StrictModel):
    debit_account_id: UUID
    credit_account_number: str = Field(pattern=ACCOUNT_NUMBER_PATTERN)
    amount: MoneyIn
    description: str | None = Field(None, max_length=140)
    auto_execute: bool = True


class BatchItem(CreateTransactionRequest):
    idempotency_key: str = Field(pattern=IDEMPOTENCY_KEY_PATTERN)


class BatchRequest(StrictModel):
    items: list[BatchItem] = Field(min_length=1, max_length=50)


class Reasoned(StrictModel):
    reason: str = Field(min_length=5, max_length=256)
    incident_id: UUID | None = None


class FlagUpdateRequest(Reasoned):
    value: Any


class IntegrityReportRequest(StrictModel):
    incident_id: UUID | None = None


class RepairRequest(Reasoned):
    dry_run: bool = False


class PurgeRequest(Reasoned):
    older_than_seconds: int = Field(ge=60, le=86400)


class FaultRequest(StrictModel):
    type: FAULT_TYPES
    params: dict[str, Any] = Field(default_factory=dict)
    duration_seconds: int | None = Field(None, ge=1, le=3600)


# =================================================================== sorties
class MoneyOut(BaseModel):
    value: str
    currency: str
    minor: int

    @classmethod
    def of(cls, minor: int, currency: str, minor_units: int) -> MoneyOut:
        return cls(value=format_minor(minor, minor_units), currency=currency, minor=minor)


class AccountRef(BaseModel):
    id: UUID
    account_number: str


class FailureOut(BaseModel):
    code: str
    reason: str | None


class HistoryItem(BaseModel):
    status: str
    at: datetime


class TransactionOut(BaseModel):
    id: UUID
    status: str
    debit_account: AccountRef
    credit_account: AccountRef
    amount: MoneyOut
    description: str | None
    is_synthetic: bool
    failure: FailureOut | None
    idempotency_key: str
    created_at: datetime
    validated_at: datetime | None
    executed_at: datetime | None

    @classmethod
    def of(cls, tx: Transaction, minor_units: int) -> TransactionOut:
        return cls(
            id=tx.id,
            status=tx.status.value,
            debit_account=AccountRef(id=tx.debit_account_id, account_number=tx.debit_account_number),
            credit_account=AccountRef(id=tx.credit_account_id, account_number=tx.credit_account_number),
            amount=MoneyOut.of(tx.amount_minor, tx.currency, minor_units),
            description=tx.description,
            is_synthetic=tx.is_synthetic,
            failure=FailureOut(code=tx.failure_code, reason=tx.failure_reason) if tx.failure_code else None,
            idempotency_key=tx.idempotency_key,
            created_at=tx.created_at,
            validated_at=tx.validated_at,
            executed_at=tx.executed_at,
        )


class TransactionDetailOut(TransactionOut):
    history: list[HistoryItem]

    @classmethod
    def with_history(cls, tx: Transaction, minor_units: int, history: list[StatusChange]) -> TransactionDetailOut:
        return cls(
            **TransactionOut.of(tx, minor_units).model_dump(),
            history=[HistoryItem(status=item.status.value, at=item.at) for item in history],
        )


class TransactionPage(BaseModel):
    items: list[TransactionOut]
    next_cursor: str | None


class BatchResultItem(BaseModel):
    index: int
    status: int
    transaction: TransactionOut | None = None
    error: dict[str, Any] | None = None


class BatchResponse(BaseModel):
    results: list[BatchResultItem]


class AccountOut(BaseModel):
    id: UUID
    account_number: str
    holder_name: str
    currency: str
    status: str
    is_synthetic: bool
    balance: MoneyOut
    updated_at: datetime

    @classmethod
    def of(cls, account: Account, minor_units: int) -> AccountOut:
        return cls(
            id=account.id,
            account_number=account.account_number,
            holder_name=account.holder_name,
            currency=account.currency,
            status=account.status,
            is_synthetic=account.is_synthetic,
            balance=MoneyOut.of(account.available_minor, account.currency, minor_units),
            updated_at=account.balance_updated_at,
        )


class AccountList(BaseModel):
    items: list[AccountOut]


class LedgerEntryOut(BaseModel):
    seq: int
    transaction_id: UUID
    direction: Literal["DEBIT", "CREDIT"]
    amount: MoneyOut
    balance_after: MoneyOut
    entry_hash: str
    created_at: datetime

    @classmethod
    def of(cls, entry: LedgerEntry, minor_units: int) -> LedgerEntryOut:
        return cls(
            seq=entry.seq,
            transaction_id=entry.transaction_id,
            direction=entry.direction,
            amount=MoneyOut.of(entry.amount_minor, entry.currency, minor_units),
            balance_after=MoneyOut.of(entry.balance_after_minor, entry.currency, minor_units),
            entry_hash=entry.entry_hash.hex(),
            created_at=entry.created_at,
        )


class LedgerPage(BaseModel):
    items: list[LedgerEntryOut]
    next_cursor: str | None


class StreamTicketOut(BaseModel):
    ticket: str
    expires_in: int


class FlagOut(BaseModel):
    key: str
    value: Any
    reason: str
    updated_by: UUID | None
    incident_id: UUID | None
    updated_at: datetime


class FlagList(BaseModel):
    items: list[FlagOut]


class FlagUpdateOut(BaseModel):
    key: str
    previous_value: Any
    value: Any
    updated_at: datetime


class RepairedField(BaseModel):
    account_id: UUID
    field: str
    previous: str
    corrected: str


class IntegritySummary(BaseModel):
    status: Literal["pass", "warn", "fail"]
    report_id: UUID | None


class RepairOut(BaseModel):
    dry_run: bool
    repaired: list[RepairedField]
    integrity_after: IntegritySummary | None


class PurgeOut(BaseModel):
    purged: int


class AccountStatusOut(BaseModel):
    id: UUID
    status: str


class FaultOut(BaseModel):
    fault_id: UUID
    type: str
    params: dict[str, Any]
    activated_at: datetime
    active_until: datetime | None


class FaultList(BaseModel):
    items: list[FaultOut]


class ClearedOut(BaseModel):
    cleared: int
