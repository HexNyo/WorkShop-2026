"""Actions de remédiation exposées au remediation-engine (identité PostgreSQL payment_maint)."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from ra_common.db import Database, DatabaseError, Record, sqlstate
from ra_common.logging import log_event

from app.domain.errors import InvalidState, LedgerCompromised, ResourceNotFound
from app.domain.models import Caller
from app.domain.policies import validate_flag_value
from app.repositories.operations import FlagRepository, MaintenanceRepository
from app.services.integrity import IntegrityOutcome, IntegrityService
from app.services.runtime_flags import RuntimeFlagsProvider

logger = logging.getLogger("payment.administration")
SQLSTATE_LEDGER_COMPROMISED = "RA012"


@dataclass(frozen=True, slots=True)
class RepairOutcome:
    dry_run: bool
    repaired: list[dict[str, str]]
    integrity_after: IntegrityOutcome | None


class AdministrationService:
    def __init__(
        self,
        *,
        maint_db: Database,
        app_db: Database,
        flags_repository: FlagRepository,
        maintenance: MaintenanceRepository,
        flags: RuntimeFlagsProvider,
        integrity: IntegrityService,
    ) -> None:
        self._maint = maint_db
        self._app = app_db
        self._flags_repository = flags_repository
        self._maintenance = maintenance
        self._flags = flags
        self._integrity = integrity

    # ------------------------------------------------------------------ flags
    async def list_flags(self) -> list[Record]:
        async with self._maint.connection() as conn:
            return await self._flags_repository.list(conn)

    async def update_flag(
        self, actor: Caller, key: str, value: Any, *, reason: str, incident_id: UUID | None
    ) -> tuple[Any, Record]:
        value = validate_flag_value(key, value)
        async with self._maint.transaction() as conn:
            result = await self._flags_repository.update(
                conn, key=key, value=value, reason=reason, updated_by=actor.id, incident_id=incident_id
            )
            if result is None:
                raise ResourceNotFound(f"Runtime flag {key} not found")
            fresh = await self._flags_repository.load(conn)
        # Application immédiate sur cette instance ; les autres suivent sous flags_cache_seconds.
        self._flags.set(fresh)
        previous, row = result
        log_event(
            logger,
            logging.WARNING,
            "runtime_flag.changed",
            f"runtime flag {key} changed",
            key=key,
            previous=previous,
            value=value,
            reason=reason,
            incident_id=str(incident_id) if incident_id else None,
        )
        return previous, row

    # -------------------------------------------------------------- intégrité
    async def integrity_report(self, incident_id: UUID | None) -> IntegrityOutcome:
        return await self._integrity.evaluate(trigger_source="REMEDIATION", incident_id=incident_id)

    async def repair(self, *, reason: str, incident_id: UUID | None, dry_run: bool) -> RepairOutcome:
        try:
            async with self._maint.transaction() as conn:
                rows = await self._maintenance.repair_balances(
                    conn, reason=reason, incident_id=incident_id, dry_run=dry_run
                )
        except DatabaseError as exc:
            if sqlstate(exc) == SQLSTATE_LEDGER_COMPROMISED:
                log_event(
                    logger,
                    logging.CRITICAL,
                    "integrity.ledger_compromised",
                    "ledger hash chain broken: automatic repair refused, restore from backup required",
                    incident_id=str(incident_id) if incident_id else None,
                )
                raise LedgerCompromised(
                    "The ledger itself is compromised: automatic repair refused, restore from backup required"
                ) from exc
            raise
        repaired = [
            {
                "account_id": str(row["repaired_account_id"]),
                "field": row["field_name"],
                "previous": row["previous_value"],
                "corrected": row["corrected_value"],
            }
            for row in rows
        ]
        if repaired and not dry_run:
            log_event(
                logger,
                logging.WARNING,
                "integrity.repaired",
                "balances rebuilt from the ledger",
                corrections=len(repaired),
                incident_id=str(incident_id) if incident_id else None,
            )
        after = None if dry_run else await self._integrity.evaluate(trigger_source="REMEDIATION", incident_id=incident_id)
        return RepairOutcome(dry_run=dry_run, repaired=repaired, integrity_after=after)

    async def purge_stale(self, *, older_than_seconds: int, reason: str, incident_id: UUID | None) -> int:
        async with self._maint.transaction() as conn:
            purged = await self._maintenance.fail_stale(
                conn, older_than_seconds=older_than_seconds, reason=reason, incident_id=incident_id
            )
        if purged:
            log_event(
                logger,
                logging.WARNING,
                "maintenance.stale_purged",
                "in-flight transactions purged",
                purged=purged,
                incident_id=str(incident_id) if incident_id else None,
            )
        return purged

    async def set_account_status(
        self, account_id: UUID, *, frozen: bool, reason: str, incident_id: UUID | None
    ) -> str:
        target = "FROZEN" if frozen else "ACTIVE"
        async with self._maint.transaction() as conn:
            account = await self._maintenance.account_status(conn, account_id)
            if account is None:
                raise ResourceNotFound("Account not found")
            if account["is_synthetic"]:
                raise InvalidState("Synthetic monitoring accounts cannot be frozen")
            if account["status"] == "CLOSED":
                raise InvalidState("Closed accounts cannot change status")
            if account["status"] != target:
                await self._maintenance.set_account_status(conn, account_id, target)
        log_event(
            logger,
            logging.WARNING,
            "account.frozen" if frozen else "account.unfrozen",
            f"account {target.lower()}",
            account_id=str(account_id),
            reason=reason,
            incident_id=str(incident_id) if incident_id else None,
        )
        return target
