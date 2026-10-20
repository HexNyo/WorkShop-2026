"""Configuration dynamique avec cache court (≤ flags_cache_seconds de propagation)."""

from __future__ import annotations

import asyncio
import logging
import time

from ra_common.db import UNAVAILABLE_ERRORS, Database

from app.domain.models import RuntimeFlags, WriteMode
from app.observability import WRITE_MODE
from app.repositories.operations import FlagRepository

logger = logging.getLogger("payment.flags")


class RuntimeFlagsProvider:
    def __init__(self, db: Database, repository: FlagRepository, ttl_seconds: float) -> None:
        self._db = db
        self._repository = repository
        self._ttl = ttl_seconds
        self._flags: RuntimeFlags | None = None
        self._loaded_at = 0.0
        self._lock = asyncio.Lock()

    async def get(self) -> RuntimeFlags:
        if self._flags is not None and time.monotonic() - self._loaded_at < self._ttl:
            return self._flags
        async with self._lock:
            if self._flags is not None and time.monotonic() - self._loaded_at < self._ttl:
                return self._flags
            try:
                async with self._db.connection() as conn:
                    self.set(await self._repository.load(conn))
            except UNAVAILABLE_ERRORS:
                # Dernière valeur connue : la base indisponible fera de toute façon échouer l'écriture.
                if self._flags is None:
                    raise
                logger.warning("runtime flags refresh failed, using last known values", extra={"event": "flags.stale"})
            return self._flags

    def set(self, flags: RuntimeFlags) -> None:
        previous = self._flags
        self._flags = flags
        self._loaded_at = time.monotonic()
        for mode in WriteMode:
            WRITE_MODE.labels(mode=mode.value).set(1 if mode is flags.write_mode else 0)
        if previous is not None and previous.write_mode is not flags.write_mode:
            logger.warning(
                "write mode is now %s",
                flags.write_mode.value,
                extra={"event": "flags.write_mode_changed", "attributes": {"previous": previous.write_mode.value}},
            )

    @property
    def current(self) -> RuntimeFlags | None:
        return self._flags
