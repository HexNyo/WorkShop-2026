"""Règles métier pures (sans E/S) : écriture, visibilité, idempotence, valeurs de flags."""

from __future__ import annotations

import hashlib
import json
from typing import Any
from uuid import UUID

from app.domain.errors import ValidationFailure, WriteModeRestricted
from app.domain.models import Account, Caller, CreateTransactionCommand, RuntimeFlags, Transaction, WriteMode

FLAG_KEYS = ("write_mode", "max_transaction_amount_minor", "max_requests_per_minute_per_principal")


def ensure_writable(flags: RuntimeFlags, caller: Caller) -> None:
    """READ_WRITE : tout passe ; SYNTHETIC_ONLY (quarantaine) : seul le trafic synthétique ;
    READ_ONLY : aucune écriture."""
    if flags.write_mode is WriteMode.READ_WRITE:
        return
    if flags.write_mode is WriteMode.SYNTHETIC_ONLY and caller.is_synthetic:
        return
    raise WriteModeRestricted(flags.write_mode.value)


def request_fingerprint(cmd: CreateTransactionCommand, amount_minor: int) -> bytes:
    canonical = {
        "debit_account_id": str(cmd.debit_account_id),
        "credit_account_number": cmd.credit_account_number,
        "amount_minor": amount_minor,
        "currency": cmd.currency,
        "description": cmd.description,
        "auto_execute": cmd.auto_execute,
    }
    return hashlib.sha256(json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()).digest()


# ------------------------------------------------------------------- visibilité
def can_read_account(caller: Caller, account: Account) -> bool:
    if caller.is_synthetic:
        return account.is_synthetic
    if caller.is_operator:
        return True
    return account.owner_principal_id == caller.id


def owns_account(caller: Caller, account: Account) -> bool:
    return account.owner_principal_id == caller.id and account.is_synthetic == caller.is_synthetic


def can_read_transaction(caller: Caller, initiator: UUID, debit_owner: UUID, credit_owner: UUID, synthetic: bool) -> bool:
    if caller.is_synthetic:
        return synthetic and initiator == caller.id
    if caller.is_operator:
        return True
    return caller.id in (initiator, debit_owner, credit_owner)


def can_read(caller: Caller, transaction: Transaction) -> bool:
    return can_read_transaction(
        caller,
        transaction.initiator_principal_id,
        transaction.debit_owner_id,
        transaction.credit_owner_id,
        transaction.is_synthetic,
    )


# ----------------------------------------------------------------------- flags
def validate_flag_value(key: str, value: Any) -> Any:
    if key not in FLAG_KEYS:
        raise ValidationFailure("path.key", f"unknown flag; expected one of {', '.join(FLAG_KEYS)}")
    if key == "write_mode":
        if value not in {mode.value for mode in WriteMode}:
            raise ValidationFailure("body.value", "write_mode must be READ_WRITE, SYNTHETIC_ONLY or READ_ONLY")
        return value
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValidationFailure("body.value", f"{key} must be a strictly positive integer")
    upper = 100_000_000_000 if key == "max_transaction_amount_minor" else 1_000_000
    if value > upper:
        raise ValidationFailure("body.value", f"{key} must be <= {upper}")
    return value
