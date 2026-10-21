"""Laboratoire d'injection de pannes (CHAOS_LAB_ENABLED=true uniquement).

Pannes en mémoire : elles disparaissent au redémarrage du processus — c'est
précisément ce qui rend le playbook de redémarrage efficace contre elles.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import random
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from ra_common.db import Database, DatabaseError, sqlstate
from ra_common.logging import log_event

from app.domain.errors import LabUnavailable, ValidationFailure
from app.domain.money import InvalidAmount, to_minor
from app.observability import FAULTS
from app.repositories.operations import MaintenanceRepository

logger = logging.getLogger("payment.lab")

PERSISTENT_TYPES = ("LATENCY", "ERROR_RATE", "READINESS_FAILURE", "POOL_EXHAUSTION")
ONE_SHOT_TYPES = ("CRASH", "BALANCE_TAMPER")
FAULT_TYPES = PERSISTENT_TYPES + ONE_SHOT_TYPES


@dataclass(slots=True)
class ActiveFault:
    id: UUID
    type: str
    params: dict[str, Any]
    activated_at: datetime
    active_until: datetime | None
    _tasks: list[asyncio.Task[Any]] = field(default_factory=list, repr=False)


class FaultInjector:
    def __init__(
        self,
        *,
        app_db: Database,
        maint_db: Database,
        maintenance: MaintenanceRepository,
        currencies: dict[str, int],
    ) -> None:
        self._app_db = app_db
        self._maint_db = maint_db
        self._maintenance = maintenance
        self._currencies = currencies
        self._active: dict[str, ActiveFault] = {}

    # ---------------------------------------------------------- lecture (hot path)
    @property
    def latency_ms(self) -> int:
        fault = self._active.get("LATENCY")
        return int(fault.params["ms"]) if fault else 0

    def should_fail_request(self) -> bool:
        fault = self._active.get("ERROR_RATE")
        return fault is not None and random.random() < float(fault.params["ratio"])  # noqa: S311 - simulation

    @property
    def readiness_failure(self) -> bool:
        return "READINESS_FAILURE" in self._active

    def active(self) -> list[ActiveFault]:
        return list(self._active.values())

    # ----------------------------------------------------------------- pilotage
    async def activate(self, fault_type: str, params: dict[str, Any], duration_seconds: int | None) -> ActiveFault:
        params = self._validate(fault_type, params)
        now = datetime.now(UTC)
        fault = ActiveFault(
            id=uuid4(),
            type=fault_type,
            params=params,
            activated_at=now,
            active_until=now + timedelta(seconds=duration_seconds) if duration_seconds else None,
        )
        log_event(
            logger,
            logging.WARNING,
            "lab.fault_injected",
            f"lab fault injected: {fault_type}",
            fault_type=fault_type,
            params=params,
            duration_seconds=duration_seconds,
        )

        if fault_type == "BALANCE_TAMPER":
            await self._tamper(params)
            fault.active_until = None
            return fault
        if fault_type == "CRASH":
            # Laisse la réponse partir, puis termine brutalement le processus.
            asyncio.get_running_loop().call_later(0.5, os._exit, 1)
            return fault

        await self._clear(fault_type)
        if fault_type == "POOL_EXHAUSTION":
            fault._tasks.append(asyncio.create_task(self._exhaust_pool(), name="lab-pool-exhaustion"))
        if duration_seconds:
            fault._tasks.append(asyncio.create_task(self._expire(fault, duration_seconds), name=f"lab-expire-{fault_type}"))
        self._active[fault_type] = fault
        FAULTS.labels(type=fault_type).set(1)
        return fault

    async def clear_all(self) -> int:
        count = len(self._active)
        for fault_type in list(self._active):
            await self._clear(fault_type)
        if count:
            log_event(logger, logging.WARNING, "lab.faults_cleared", "lab faults cleared", count=count)
        return count

    async def _clear(self, fault_type: str) -> None:
        fault = self._active.pop(fault_type, None)
        if fault is None:
            return
        current = asyncio.current_task()
        for task in fault._tasks:
            if task is not current:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
        FAULTS.labels(type=fault_type).set(0)

    async def _expire(self, fault: ActiveFault, delay: int) -> None:
        await asyncio.sleep(delay)
        if self._active.get(fault.type) is fault:
            await self._clear(fault.type)
            log_event(logger, logging.INFO, "lab.fault_expired", f"lab fault expired: {fault.type}", fault_type=fault.type)

    async def _exhaust_pool(self) -> None:
        """Retient toutes les connexions du pool applicatif jusqu'à la levée de la panne."""
        held: list[Any] = []
        pool = self._app_db.pool
        try:
            while len(held) < pool.maxsize:
                held.append(await pool.acquire())
            await asyncio.Event().wait()
        finally:
            for connection in held:
                pool.release(connection)

    async def _tamper(self, params: dict[str, Any]) -> None:
        async with self._maint_db.transaction() as conn:
            currency = await conn.fetchval(
                "SELECT currency FROM ra_payment.accounts WHERE account_number = $1", params["account_number"]
            )
            if currency is None:
                raise ValidationFailure("body.params.account_number", "unknown account")
            try:
                delta = to_minor(params["delta"], self._currencies[currency], allow_negative=True)
            except InvalidAmount as exc:
                raise ValidationFailure("body.params.delta", str(exc)) from exc
            try:
                async with conn.transaction():
                    await self._maintenance.tamper_balance(conn, params["account_number"], delta)
            except DatabaseError as exc:
                if sqlstate(exc) == "42883":
                    raise LabUnavailable(
                        "Lab primitives are not installed in the database (initialise it with CHAOS_LAB_ENABLED=true)"
                    ) from exc
                if sqlstate(exc) == "23514":
                    raise ValidationFailure("body.params.delta", "would make the balance negative") from exc
                raise

    # -------------------------------------------------------------- validation
    @staticmethod
    def _validate(fault_type: str, params: dict[str, Any]) -> dict[str, Any]:
        def number(name: str, minimum: float, maximum: float) -> float:
            value = params.get(name)
            if isinstance(value, bool) or not isinstance(value, int | float) or not minimum <= value <= maximum:
                raise ValidationFailure(f"body.params.{name}", f"must be a number between {minimum} and {maximum}")
            return value

        if fault_type == "LATENCY":
            return {"ms": int(number("ms", 1, 10_000))}
        if fault_type == "ERROR_RATE":
            return {"ratio": float(number("ratio", 0.01, 1.0))}
        if fault_type == "BALANCE_TAMPER":
            account, delta = params.get("account_number"), params.get("delta")
            if not isinstance(account, str) or not isinstance(delta, str):
                raise ValidationFailure("body.params", "account_number and delta (decimal string) are required")
            return {"account_number": account, "delta": delta}
        return {}
