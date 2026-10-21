"""Diagnostic d'intégrité : cohérence des données ET de la logique métier.

* données : `ra_payment.sp_integrity_report` (7 contrôles, cf. docs/02) ;
* logique  : exécution complète d'une transaction synthétique dans une transaction
  SQL systématiquement annulée (déclencheurs, partie double, chaîne de hachage).
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from ra_common.db import Database, DatabaseError, sqlstate
from ra_common.logging import log_event

from app.core.config import Settings
from app.observability import INTEGRITY
from app.repositories.operations import IntegrityRepository

logger = logging.getLogger("payment.integrity")
DRY_RUN_CHECK = "logic:dry-run-execution"


class _Rollback(Exception):
    """Force l'annulation de la transaction SQL du test à blanc."""


@dataclass(frozen=True, slots=True)
class CheckOutcome:
    name: str
    severity: str
    passed: bool
    observed_value: Any
    observed_unit: str
    output: Any = None

    @property
    def status(self) -> str:
        if self.passed:
            return "pass"
        return "fail" if self.severity == "CRITICAL" else "warn"

    def as_dict(self) -> dict[str, Any]:
        data = {
            "check": self.name,
            "severity": self.severity,
            "passed": self.passed,
            "observed_value": self.observed_value,
            "observed_unit": self.observed_unit,
        }
        if self.output:
            data["output"] = self.output
        return data


@dataclass(frozen=True, slots=True)
class IntegrityOutcome:
    report_id: UUID | None
    generated_at: datetime | None
    duration_ms: int
    checks: list[CheckOutcome]

    @property
    def critical_failures(self) -> int:
        return sum(1 for check in self.checks if not check.passed and check.severity == "CRITICAL")

    @property
    def warnings(self) -> int:
        return sum(1 for check in self.checks if not check.passed and check.severity == "WARNING")

    @property
    def status(self) -> str:
        if self.critical_failures:
            return "fail"
        return "warn" if self.warnings else "pass"


class IntegrityService:
    def __init__(self, *, db: Database, repository: IntegrityRepository, settings: Settings) -> None:
        self._db = db
        self._repository = repository
        self._settings = settings
        self._cached: IntegrityOutcome | None = None
        self._cached_at = 0.0

    async def evaluate(
        self, *, trigger_source: str, incident_id: UUID | None = None, use_cache: bool = False
    ) -> IntegrityOutcome:
        if use_cache and self._cached and time.monotonic() - self._cached_at < self._settings.integrity_cache_seconds:
            return self._cached

        started = time.perf_counter()
        async with self._db.connection() as conn:
            rows = await self._repository.report(conn, self._settings.stale_after_seconds)
        checks = [
            CheckOutcome(
                name=f"data:{row['check_code']}",
                severity=row["severity"],
                passed=row["passed"],
                observed_value=row["violations"],
                observed_unit="violations",
                output=None if row["passed"] else row["sample"],
            )
            for row in rows
        ]
        checks.append(await self._dry_run())
        duration_ms = int((time.perf_counter() - started) * 1000)

        draft = IntegrityOutcome(report_id=None, generated_at=None, duration_ms=duration_ms, checks=checks)
        async with self._db.transaction() as conn:
            report_id, generated_at = await self._repository.save_report(
                conn,
                trigger_source=trigger_source,
                passed=draft.critical_failures == 0,
                critical_failures=draft.critical_failures,
                warnings=draft.warnings,
                duration_ms=duration_ms,
                checks=[check.as_dict() for check in checks],
                incident_id=incident_id,
            )
        outcome = IntegrityOutcome(report_id=report_id, generated_at=generated_at, duration_ms=duration_ms, checks=checks)

        for check in checks:
            INTEGRITY.labels(check=check.name).set(1 if check.passed else 0)
        if outcome.status != "pass":
            log_event(
                logger,
                logging.ERROR if outcome.status == "fail" else logging.WARNING,
                "integrity.check_failed",
                "integrity checks reported anomalies",
                report_id=str(report_id),
                failed=[check.name for check in checks if not check.passed],
                trigger_source=trigger_source,
            )
        self._cached, self._cached_at = outcome, time.monotonic()
        return outcome

    async def _dry_run(self) -> CheckOutcome:
        started = time.perf_counter()
        result: str
        try:
            async with self._db.connection() as conn:
                try:
                    async with conn.transaction():
                        result = await self._repository.dry_run_execution(
                            conn,
                            initiator=self._settings.synthetic_principal_id,
                            account_a=self._settings.synthetic_account_a,
                            account_b=self._settings.synthetic_account_b,
                        )
                        raise _Rollback
                except _Rollback:
                    pass
        except DatabaseError as exc:
            result = f"SQLSTATE_{sqlstate(exc) or 'UNKNOWN'}"
        latency = round((time.perf_counter() - started) * 1000, 2)
        passed = result == "EXECUTED"
        return CheckOutcome(
            name=DRY_RUN_CHECK,
            severity="CRITICAL",
            passed=passed,
            observed_value=latency,
            observed_unit="ms",
            output=None if passed else {"result": result},
        )
