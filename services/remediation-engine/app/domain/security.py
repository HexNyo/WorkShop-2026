"""Signature HMAC du webhook et empreinte de déduplication."""

from __future__ import annotations

import hashlib
import hmac
import time


class SignatureError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def sign(secret: bytes, body: bytes, timestamp: int) -> str:
    digest = hmac.new(secret, f"{timestamp}.".encode() + body, hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={digest}"


def verify_signature(secret: bytes, header: str | None, body: bytes, *, tolerance_seconds: int, now: float | None = None) -> int:
    """Vérifie `X-RA-Signature: t=<unix>,v1=<hex>` ; renvoie l'horodatage signé."""
    if not header:
        raise SignatureError("missing_signature")
    timestamp: int | None = None
    candidates: list[str] = []
    for part in header.split(","):
        key, _, value = part.strip().partition("=")
        if key == "t" and value.isdigit():
            timestamp = int(value)
        elif key == "v1" and value:
            candidates.append(value.lower())
    if timestamp is None or not candidates:
        raise SignatureError("malformed_signature")
    current = time.time() if now is None else now
    if abs(current - timestamp) > tolerance_seconds:
        raise SignatureError("timestamp_out_of_tolerance")
    expected = hmac.new(secret, f"{timestamp}.".encode() + body, hashlib.sha256).hexdigest()
    if not any(hmac.compare_digest(expected, candidate) for candidate in candidates):
        raise SignatureError("bad_signature")
    return timestamp


def fingerprint(
    *, explicit: str | None, category: str, service: str, principal_id: str | None, account_id: str | None
) -> str:
    """Clé de regroupement : fournie par le détecteur, sinon dérivée de la cible."""
    basis = explicit or "|".join([category, service, principal_id or "", account_id or ""])
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()
