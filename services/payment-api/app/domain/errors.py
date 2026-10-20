"""Erreurs du domaine de paiement : chacune porte sa sémantique HTTP (RFC 9457)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any


class PaymentError(Exception):
    status = 400
    code = "MALFORMED_REQUEST"
    title = "Bad request"

    def __init__(self, detail: str, *, errors: Sequence[Mapping[str, Any]] | None = None) -> None:
        super().__init__(detail)
        self.detail = detail
        self.errors = list(errors) if errors else None

    @property
    def headers(self) -> dict[str, str]:
        return {}


class MalformedRequest(PaymentError):
    pass


class ValidationFailure(PaymentError):
    status, code, title = 422, "VALIDATION_ERROR", "Validation error"

    def __init__(self, location: str, message: str) -> None:
        super().__init__("Request failed validation", errors=[{"location": location, "message": message}])


class CurrencyMismatch(PaymentError):
    status, code, title = 422, "CURRENCY_MISMATCH", "Currency mismatch"


class SyntheticSegregation(PaymentError):
    status, code, title = 422, "SYNTHETIC_SEGREGATION", "Synthetic segregation"


class AmountLimitExceeded(PaymentError):
    status, code, title = 422, "AMOUNT_LIMIT_EXCEEDED", "Amount limit exceeded"


class ResourceNotFound(PaymentError):
    status, code, title = 404, "NOT_FOUND", "Resource not found"


class IdempotencyConflict(PaymentError):
    status, code, title = 409, "IDEMPOTENCY_CONFLICT", "Idempotency conflict"


class InvalidState(PaymentError):
    status, code, title = 409, "INVALID_STATE", "Conflict"


class LedgerCompromised(PaymentError):
    status, code, title = 409, "LEDGER_COMPROMISED", "Ledger compromised"


class LabUnavailable(PaymentError):
    status, code, title = 409, "LAB_PRIMITIVES_MISSING", "Lab primitives missing"


class Forbidden(PaymentError):
    status, code, title = 403, "FORBIDDEN", "Forbidden"


class RateLimited(PaymentError):
    status, code, title = 429, "RATE_LIMITED", "Too many requests"

    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__("Request rate limit exceeded for this principal")
        self.retry_after_seconds = max(retry_after_seconds, 1)

    @property
    def headers(self) -> dict[str, str]:
        return {"Retry-After": str(self.retry_after_seconds)}


class WriteModeRestricted(PaymentError):
    status, code, title = 503, "WRITE_MODE_RESTRICTED", "Write operations restricted"

    def __init__(self, mode: str) -> None:
        super().__init__(f"The platform is in {mode} mode: this write operation is temporarily refused")
        self.mode = mode

    @property
    def headers(self) -> dict[str, str]:
        return {"Retry-After": "10"}
