"""Entités du domaine de paiement."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from uuid import UUID

from ra_common.security.tokens import AccessTokenClaims

ROLE_CUSTOMER = "payment.customer"
ROLE_OPERATOR = "payment.operator"
ROLE_SYNTHETIC = "svc.synthetic"
ROLE_REMEDIATION = "svc.remediation"
ROLE_CHAOS = "chaos.operator"


class TransactionStatus(StrEnum):
    PENDING = "PENDING"
    VALIDATED = "VALIDATED"
    EXECUTED = "EXECUTED"
    REJECTED = "REJECTED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class WriteMode(StrEnum):
    READ_WRITE = "READ_WRITE"
    SYNTHETIC_ONLY = "SYNTHETIC_ONLY"
    READ_ONLY = "READ_ONLY"


@dataclass(frozen=True, slots=True)
class Caller:
    """Principal authentifié, vu par le domaine de paiement."""

    id: UUID
    roles: tuple[str, ...]
    is_service: bool

    @classmethod
    def from_claims(cls, claims: AccessTokenClaims) -> Caller:
        return cls(id=UUID(claims.sub), roles=claims.roles, is_service=claims.pkind == "SERVICE")

    @property
    def is_synthetic(self) -> bool:
        return ROLE_SYNTHETIC in self.roles

    @property
    def is_operator(self) -> bool:
        return ROLE_OPERATOR in self.roles

    @property
    def can_initiate(self) -> bool:
        return ROLE_CUSTOMER in self.roles or self.is_synthetic


@dataclass(frozen=True, slots=True)
class Account:
    id: UUID
    account_number: str
    owner_principal_id: UUID
    holder_name: str
    currency: str
    status: str
    is_synthetic: bool
    available_minor: int
    balance_updated_at: datetime


@dataclass(frozen=True, slots=True)
class Transaction:
    id: UUID
    initiator_principal_id: UUID
    idempotency_key: str
    request_fingerprint: bytes
    debit_account_id: UUID
    debit_account_number: str
    debit_owner_id: UUID
    credit_account_id: UUID
    credit_account_number: str
    credit_owner_id: UUID
    amount_minor: int
    currency: str
    description: str | None
    status: TransactionStatus
    failure_code: str | None
    failure_reason: str | None
    is_synthetic: bool
    correlation_id: str | None
    created_at: datetime
    validated_at: datetime | None
    executed_at: datetime | None
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class StatusChange:
    status: TransactionStatus
    at: datetime


@dataclass(frozen=True, slots=True)
class LedgerEntry:
    seq: int
    transaction_id: UUID
    direction: str
    amount_minor: int
    currency: str
    balance_after_minor: int
    entry_hash: bytes
    created_at: datetime


@dataclass(frozen=True, slots=True)
class RuntimeFlags:
    write_mode: WriteMode
    max_transaction_amount_minor: int
    max_requests_per_minute_per_principal: int


@dataclass(frozen=True, slots=True)
class CreateTransactionCommand:
    idempotency_key: str
    debit_account_id: UUID
    credit_account_number: str
    amount_value: str
    currency: str
    description: str | None
    auto_execute: bool
