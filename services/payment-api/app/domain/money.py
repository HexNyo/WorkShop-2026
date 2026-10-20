"""Montants : chaînes décimales à l'API, entiers d'unités mineures partout ailleurs."""

from __future__ import annotations

from decimal import Decimal, InvalidOperation

AMOUNT_PATTERN = r"^(0|[1-9][0-9]{0,11})(\.[0-9]{1,4})?$"
SIGNED_AMOUNT_PATTERN = r"^-?(0|[1-9][0-9]{0,11})(\.[0-9]{1,4})?$"


class InvalidAmount(ValueError):
    pass


def to_minor(value: str, minor_units: int, *, allow_negative: bool = False) -> int:
    try:
        amount = Decimal(value)
    except InvalidOperation as exc:
        raise InvalidAmount("not a decimal number") from exc
    if not amount.is_finite():
        raise InvalidAmount("not a finite number")
    exponent = amount.as_tuple().exponent
    if isinstance(exponent, int) and -exponent > minor_units:
        raise InvalidAmount(f"at most {minor_units} decimal places are allowed for this currency")
    minor = int(amount.scaleb(minor_units))
    if minor == 0 or (minor < 0 and not allow_negative):
        raise InvalidAmount("amount must be strictly positive" if not allow_negative else "amount must be non-zero")
    return minor


def format_minor(minor: int, minor_units: int) -> str:
    value = Decimal(minor).scaleb(-minor_units)
    return f"{value:.{minor_units}f}"
