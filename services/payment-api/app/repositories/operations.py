"""Flags dynamiques, intégrité et maintenance (procédures SQL de ra_payment_maint)."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from ra_common.db import Connection, Record, json_value

from app.domain.models import RuntimeFlags, WriteMode

_FLAG_COLUMNS = "`key`, value, reason, updated_by, incident_id, updated_at"


def _flag(row: Record) -> Record:
    return {**row, "value": json_value(row["value"])}


class FlagRepository:
    async def load(self, conn: Connection) -> RuntimeFlags:
        rows = await conn.fetch("SELECT `key`, value FROM ra_payment.runtime_flags")
        values = {row["key"]: json_value(row["value"]) for row in rows}
        return RuntimeFlags(
            write_mode=WriteMode(values.get("write_mode", "READ_WRITE")),
            max_transaction_amount_minor=int(values.get("max_transaction_amount_minor", 1_000_000)),
            max_requests_per_minute_per_principal=int(values.get("max_requests_per_minute_per_principal", 600)),
        )

    async def list(self, conn: Connection) -> list[Record]:
        rows = await conn.fetch(f"SELECT {_FLAG_COLUMNS} FROM ra_payment.runtime_flags ORDER BY `key`")
        return [_flag(row) for row in rows]

    async def update(
        self, conn: Connection, *, key: str, value: Any, reason: str, updated_by: UUID, incident_id: UUID | None
    ) -> tuple[Any, Record] | None:
        previous = await conn.fetchrow("SELECT value FROM ra_payment.runtime_flags WHERE `key` = $1 FOR UPDATE", key)
        if previous is None:
            return None
        await conn.execute(
            """
            UPDATE ra_payment.runtime_flags
               SET value = $2, reason = $3, updated_by = $4, incident_id = $5
             WHERE `key` = $1
            """,
            key,
            json.dumps(value),
            reason,
            updated_by,
            incident_id,
        )
        row = await conn.fetchrow(f"SELECT {_FLAG_COLUMNS} FROM ra_payment.runtime_flags WHERE `key` = $1", key)
        return json_value(previous["value"]), _flag(row)


class IntegrityRepository:
    async def report(self, conn: Connection, stale_after_seconds: int) -> list[Record]:
        rows = await conn.fetch("CALL ra_payment.sp_integrity_report($1)", stale_after_seconds)
        return [{**row, "passed": bool(row["passed"]), "sample": json_value(row["sample"])} for row in rows]

    async def save_report(
        self,
        conn: Connection,
        *,
        trigger_source: str,
        passed: bool,
        critical_failures: int,
        warnings: int,
        duration_ms: int,
        checks: list[dict[str, Any]],
        incident_id: UUID | None,
    ) -> tuple[UUID, datetime]:
        report_id = uuid4()
        generated_at = await conn.fetchval(
            """
            INSERT INTO ra_payment.integrity_reports (id, trigger_source, passed, critical_failures, warnings,
                                                      duration_ms, checks, incident_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING generated_at
            """,
            report_id,
            trigger_source,
            passed,
            critical_failures,
            warnings,
            duration_ms,
            checks,
            incident_id,
        )
        return report_id, generated_at

    async def dry_run_execution(
        self, conn: Connection, *, initiator: UUID, account_a: str, account_b: str
    ) -> str:
        """Exécute une transaction synthétique complète puis annule tout (aucune trace).
        Doit être appelée dans une transaction SQL qui sera annulée par l'appelant."""
        transaction_id = uuid4()
        inserted = await conn.execute(
            """
            INSERT INTO ra_payment.transactions (id, initiator_principal_id, idempotency_key, request_fingerprint,
                                                 debit_account_id, credit_account_id, amount_minor, currency,
                                                 description, is_synthetic)
            SELECT $1, $2, CONCAT('dryrun-', REPLACE($1, '-', '')), UNHEX(SHA2('dry-run', 256)),
                   a.id, b.id, 1, a.currency, 'integrity probe (rolled back)', true
              FROM ra_payment.accounts a, ra_payment.accounts b
             WHERE a.account_number = $3 AND b.account_number = $4
            """,
            transaction_id,
            initiator,
            account_a,
            account_b,
        )
        if inserted == "INSERT 0 0":
            return "SYNTHETIC_ACCOUNTS_MISSING"
        await conn.execute("UPDATE ra_payment.transactions SET status = 'VALIDATED' WHERE id = $1", transaction_id)
        row = await conn.fetchrow("CALL ra_payment.sp_execute_transaction($1)", transaction_id)
        return row["status"]


class MaintenanceRepository:
    async def repair_balances(
        self, conn: Connection, *, reason: str, incident_id: UUID | None, dry_run: bool
    ) -> list[Record]:
        return await conn.fetch("CALL ra_payment.sp_repair_balances($1, $2, $3)", reason, incident_id, dry_run)

    async def fail_stale(
        self, conn: Connection, *, older_than_seconds: int, reason: str, incident_id: UUID | None
    ) -> int:
        return await conn.fetchval(
            "CALL ra_payment.sp_fail_stale_transactions($1, $2, $3)", older_than_seconds, reason, incident_id
        )

    async def account_status(self, conn: Connection, account_id: UUID) -> Record | None:
        return await conn.fetchrow(
            "SELECT id, status, is_synthetic, currency FROM ra_payment.accounts WHERE id = $1",
            account_id,
        )

    async def set_account_status(self, conn: Connection, account_id: UUID, status: str) -> None:
        await conn.execute("UPDATE ra_payment.accounts SET status = $2 WHERE id = $1", account_id, status)

    async def tamper_balance(self, conn: Connection, account_number: str, delta_minor: int) -> int | None:
        """Laboratoire uniquement : altère un solde sans écriture au grand livre."""
        return await conn.fetchval("CALL ra_payment.sp_lab_tamper_balance($1, $2)", account_number, delta_minor)
