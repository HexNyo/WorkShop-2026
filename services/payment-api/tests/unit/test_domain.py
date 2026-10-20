from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest

from app.api.deps import decode_seq_cursor, decode_time_cursor, encode_time_cursor
from app.domain.errors import MalformedRequest, ValidationFailure, WriteModeRestricted
from app.domain.models import Account, Caller, CreateTransactionCommand, RuntimeFlags, WriteMode
from app.domain.money import InvalidAmount, format_minor, to_minor
from app.domain.policies import (
    can_read_account,
    can_read_transaction,
    ensure_writable,
    owns_account,
    request_fingerprint,
    validate_flag_value,
)
from app.services.rate_limit import SlidingWindowLimiter

ALICE = UUID("00000000-0000-4000-8000-000000000002")
BOB = UUID("00000000-0000-4000-8000-000000000003")
SYNTH = UUID("00000000-0000-4000-8000-000000000102")

customer = Caller(id=ALICE, roles=("payment.customer",), is_service=False)
operator = Caller(id=BOB, roles=("payment.operator",), is_service=False)
synthetic = Caller(id=SYNTH, roles=("svc.synthetic",), is_service=True)


def account(owner: UUID, *, synthetic_flag: bool = False) -> Account:
    return Account(
        id=UUID(int=1),
        account_number="RA-9000-0001" if synthetic_flag else "RA-1000-0001",
        owner_principal_id=owner,
        holder_name="x",
        currency="EUR",
        status="ACTIVE",
        is_synthetic=synthetic_flag,
        available_minor=0,
        balance_updated_at=datetime.now(UTC),
    )


# ------------------------------------------------------------------- montants
@pytest.mark.parametrize(
    ("value", "units", "expected"),
    [("125.50", 2, 12550), ("0.01", 2, 1), ("10", 2, 1000), ("7", 0, 7), ("1.2345", 4, 12345)],
)
def test_to_minor(value: str, units: int, expected: int) -> None:
    assert to_minor(value, units) == expected


@pytest.mark.parametrize(("value", "units"), [("1.234", 2), ("0", 2), ("0.00", 2), ("1.5", 0), ("abc", 2), ("-1", 2)])
def test_to_minor_rejects(value: str, units: int) -> None:
    with pytest.raises(InvalidAmount):
        to_minor(value, units)


def test_signed_amounts_for_lab_and_formatting() -> None:
    assert to_minor("-500.00", 2, allow_negative=True) == -50000
    assert format_minor(12550, 2) == "125.50"
    assert format_minor(1, 2) == "0.01"
    assert format_minor(-50000, 2) == "-500.00"
    assert format_minor(7, 0) == "7"


# ---------------------------------------------------------------- écriture
@pytest.mark.parametrize(
    ("mode", "caller", "allowed"),
    [
        (WriteMode.READ_WRITE, customer, True),
        (WriteMode.SYNTHETIC_ONLY, customer, False),
        (WriteMode.SYNTHETIC_ONLY, synthetic, True),
        (WriteMode.READ_ONLY, synthetic, False),
    ],
)
def test_write_modes(mode: WriteMode, caller: Caller, allowed: bool) -> None:
    flags = RuntimeFlags(write_mode=mode, max_transaction_amount_minor=1, max_requests_per_minute_per_principal=1)
    if allowed:
        ensure_writable(flags, caller)
    else:
        with pytest.raises(WriteModeRestricted):
            ensure_writable(flags, caller)


def test_fingerprint_is_canonical() -> None:
    base = dict(
        idempotency_key="k" * 8,
        debit_account_id=UUID(int=1),
        credit_account_number="RA-1000-0003",
        amount_value="1.00",
        currency="EUR",
        description=None,
        auto_execute=True,
    )
    first = request_fingerprint(CreateTransactionCommand(**base), 100)
    assert first == request_fingerprint(CreateTransactionCommand(**{**base, "idempotency_key": "other-key"}), 100)
    assert first != request_fingerprint(CreateTransactionCommand(**{**base, "auto_execute": False}), 100)
    assert first != request_fingerprint(CreateTransactionCommand(**base), 101)
    assert len(first) == 32


# --------------------------------------------------------------- visibilité
def test_account_visibility_and_ownership() -> None:
    mine, theirs, probe = account(ALICE), account(BOB), account(SYNTH, synthetic_flag=True)
    assert can_read_account(customer, mine) and not can_read_account(customer, theirs)
    assert can_read_account(operator, theirs)
    assert can_read_account(synthetic, probe) and not can_read_account(synthetic, mine)
    assert owns_account(customer, mine) and not owns_account(customer, theirs)
    assert owns_account(synthetic, probe)


def test_transaction_visibility() -> None:
    assert can_read_transaction(customer, BOB, BOB, ALICE, False), "beneficiary sees incoming payment"
    assert not can_read_transaction(customer, BOB, BOB, BOB, False)
    assert can_read_transaction(operator, ALICE, ALICE, ALICE, False)
    assert can_read_transaction(synthetic, SYNTH, SYNTH, SYNTH, True)
    assert not can_read_transaction(synthetic, ALICE, ALICE, BOB, False)


# --------------------------------------------------------------------- flags
def test_flag_validation() -> None:
    assert validate_flag_value("write_mode", "SYNTHETIC_ONLY") == "SYNTHETIC_ONLY"
    assert validate_flag_value("max_requests_per_minute_per_principal", 30) == 30
    for key, value in [
        ("write_mode", "OPEN_BAR"),
        ("max_transaction_amount_minor", 0),
        ("max_transaction_amount_minor", True),
        ("max_transaction_amount_minor", "100"),
        ("unknown_flag", 1),
    ]:
        with pytest.raises(ValidationFailure):
            validate_flag_value(key, value)


# ------------------------------------------------------------------- quota
def test_sliding_window_limiter() -> None:
    limiter = SlidingWindowLimiter(window_seconds=60)
    assert all(limiter.check("alice", 3, now=100.0 + i) is None for i in range(3))
    delay = limiter.check("alice", 3, now=103.0)
    assert delay == pytest.approx(57.0)
    assert SlidingWindowLimiter.retry_after(delay) == 57
    assert limiter.check("bob", 3, now=103.0) is None
    assert limiter.check("alice", 3, now=160.5) is None, "oldest hit left the window"


# ---------------------------------------------------------------- curseurs
def test_cursors_round_trip_and_reject_garbage() -> None:
    moment, identifier = datetime(2026, 10, 19, 8, 15, 30, 123456, tzinfo=UTC), UUID(int=42)
    assert decode_time_cursor(encode_time_cursor(moment, identifier)) == (moment, identifier)
    assert decode_seq_cursor("17") == 17
    with pytest.raises(MalformedRequest):
        decode_time_cursor("@@not-a-cursor@@")
    with pytest.raises(MalformedRequest):
        decode_seq_cursor("-1")
