"""Tâche de fond : purge des jetons et révocations expirés."""

from __future__ import annotations

import asyncio
import contextlib
import logging

from app.core.db import UNAVAILABLE_ERRORS, Database
from app.repositories.refresh_tokens import RefreshTokenRepository
from app.repositories.revocations import RevocationRepository
from ra_common.logging import log_event

logger = logging.getLogger("auth.maintenance")
_REFRESH_RETENTION_SECONDS = 86400  # conserve 24 h les jetons expirés (investigation)


class MaintenanceWorker:
    def __init__(
        self,
        *,
        db: Database,
        refresh_tokens: RefreshTokenRepository,
        revocations: RevocationRepository,
        interval_seconds: int,
    ) -> None:
        self._db = db
        self._refresh = refresh_tokens
        self._revocations = revocations
        self._interval = interval_seconds
        self._task: asyncio.Task[None] | None = None

    def start(self) -> None:
        self._task = asyncio.create_task(self._loop(), name="auth-maintenance")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task

    async def run_once(self) -> tuple[int, int]:
        async with self._db.transaction() as conn:
            refresh = await self._refresh.purge_expired(conn, older_than_seconds=_REFRESH_RETENTION_SECONDS)
            revocations = await self._revocations.purge_expired(conn)
        if refresh or revocations:
            log_event(
                logger,
                logging.INFO,
                "auth.maintenance_purged",
                "expired credentials purged",
                refresh_tokens=refresh,
                revocations=revocations,
            )
        return refresh, revocations

    async def _loop(self) -> None:
        while True:
            await asyncio.sleep(self._interval)
            try:
                await self.run_once()
            except UNAVAILABLE_ERRORS as exc:
                logger.warning("maintenance skipped: %s", exc.__class__.__name__, extra={"event": "auth.maintenance_skipped"})
