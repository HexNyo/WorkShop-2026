"""Journalisation JSON structurée (une ligne par événement, sur stdout)."""

from __future__ import annotations

import json
import logging
import sys
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from ra_common.context import current_context

_REDACTED = "[REDACTED]"
_SENSITIVE_EXACT = frozenset(
    {
        "authorization",
        "cookie",
        "set-cookie",
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "ticket",
    }
)
_SENSITIVE_FRAGMENTS = ("password", "secret", "private_key")


def _is_sensitive(key: str) -> bool:
    lowered = key.lower()
    return lowered in _SENSITIVE_EXACT or any(fragment in lowered for fragment in _SENSITIVE_FRAGMENTS)


def redact(value: Any) -> Any:
    """Masque récursivement toute valeur dont la clé est réputée sensible."""
    if isinstance(value, Mapping):
        return {key: (_REDACTED if _is_sensitive(str(key)) else redact(item)) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [redact(item) for item in value]
    return value


class JsonFormatter(logging.Formatter):
    def __init__(self, service: str, version: str) -> None:
        super().__init__()
        self._service = service
        self._version = version

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "level": record.levelname,
            "service": self._service,
            "version": self._version,
            "logger": record.name,
            "event": getattr(record, "event", None) or record.name,
            "message": record.getMessage(),
        }
        payload.update(current_context())
        for attribute in ("http", "attributes"):
            data = getattr(record, attribute, None)
            if data:
                payload[attribute] = redact(data)
        if record.exc_info and record.exc_info[0] is not None:
            payload["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
                "stack": self.formatException(record.exc_info),
            }
        return json.dumps(payload, default=str, ensure_ascii=False)


def configure_logging(service: str, version: str, level: str = "INFO") -> None:
    """Installe le formateur JSON sur le logger racine et neutralise les handlers d'uvicorn."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter(service, version))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logger = logging.getLogger(name)
        logger.handlers[:] = []
        logger.propagate = True
    # Le journal d'accès est produit par RequestContextMiddleware (format unifié).
    logging.getLogger("uvicorn.access").disabled = True
    for noisy in ("httpx", "httpcore", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def log_event(logger: logging.Logger, level: int, event: str, message: str, **attributes: Any) -> None:
    """Émet un événement métier nommé avec des attributs structurés."""
    logger.log(level, message, extra={"event": event, "attributes": attributes or None})
