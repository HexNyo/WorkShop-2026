"""Flags dynamiques, intégrité et maintenance (fonctions SQL de payment_maint)."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

import asyncpg

from app.domain.models import RuntimeFlags, WriteMode


class FlagRepository:
    async def load(self, conn: asyncpg.Connection) -> RuntimeFlags:
        rows = await conn.fetch("SELECT key, value FROM payment.runtime_flags")
        values = {row["key"]: row["value"] for row in rows}
        return RuntimeFlags(
            write_mode=WriteMode(values.get("write_mode", "READ_WRITE")),
            max_transaction_amount_minor=int(values.get("max_transaction_amount_minor", 1_000_000)),
            max_requests_per_minute_per_principal=int(values.get("max_requests_per_minute_per_principal", 600)),
        )

    async def list(self, conn: asyncpg.Connection) -> list[asyncpg.Record]:
        return await conn.fetch(
            "SELECT key, value, reason, updated_by, incident_id, updated_at FROM payment.runtime_flags ORDER BY key"
        )

    async def update(
        self, conn: asyncpg.Connection, *, key: str, value: Any, reason: str, updated_by: UUID, incident_id: UUID | None
    ) -> tuple[Any, asyncpg.Record] | None:
        previous = await conn.fetchval("SELECT value FROM payment.runtime_flags WHERE key = $1 FOR UPDATE", key)
        row = await conn.fetchrow(
            """
            UPDATE payment.runtime_flags
               SET value = $2::jsonb, reason = $3, updated_by = $4, incident_id = $5
             WHERE key = $1
         RETURNING key, value, reason, updated_by, incident_id, updated_at
            """,
            key,
            value,
            reason,
            updated_by,
            incident_id,
        )
        return (previous, row) if row else None


class IntegrityRepository:
    async def report(self, conn: asyncpg.Connection, stale_after_seconds: int) -> list[asyncpg.Record]:
        return await conn.fetch(
            "SELECT check_code, severity::text AS severity, passed, violations, sample "
            "FROM payment.fn_integrity_report($1)",
            timedelta(seconds=stale_after_seconds),
        )

    async def save_report(
        self,
        conn: asyncpg.Connection,
        *,
        trigger_source: str,
        passed: bool,
        critical_failures: int,
        warnings: int,
        duration_ms: int,
        checks: list[dict[str, Any]],
        incident_id: UUID | None,
    ) -> tuple[UUID, datetime]:
        row = await conn.fetchrow(
            """
            INSERT INTO payment.integrity_reports (trigger_source, passed, critical_failures, warnings,
                                                   duration_ms, checks, incident_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id, generated_at
            """,
            trigger_source,
            passed,
            critical_failures,
            warnings,
            duration_ms,
            checks,
            incident_id,
        )
        return UUID(str(row["id"])), row["generated_at"]

    async def dry_run_execution(
        self, conn: asyncpg.Connection, *, initiator: UUID, account_a: str, account_b: str
    ) -> str:
        """Exécute une transaction synthétique complète puis annule tout (aucune trace).
        Doit être appelée dans une transaction SQL qui sera annulée par l'appelant."""
        transaction_id = await conn.fetchval(
            """
            INSERT INTO payment.transactions (initiator_principal_id, idempotency_key, request_fingerprint,
                                              debit_account_id, credit_account_id, amount_minor, currency,
                                              description, is_synthetic)
            SELECT $1, 'dryrun-' || replace(gen_random_uuid()::text, '-', ''), sha256('dry-run'::bytea),
                   a.id, b.id, 1, a.currency, 'integrity probe (rolled back)', true
              FROM payment.accounts a, payment.accounts b
             WHERE a.account_number = $2 AND b.account_number = $3
            RETURNING id
            """,
            initiator,
            account_a,
            account_b,
        )
        if transaction_id is None:
            return "SYNTHETIC_ACCOUNTS_MISSING"
        await conn.execute("UPDATE payment.transactions SET status = 'VALIDATED' WHERE id = $1", transaction_id)
        status = await conn.fetchval("SELECT status::text FROM payment.fn_execute_transaction($1)", transaction_id)
        await conn.execute("SET CONSTRAINTS ALL IMMEDIATE")
        return status


class MaintenanceRepository:
    async def repair_balances(
        self, conn: asyncpg.Connection, *, reason: str, incident_id: UUID | None, dry_run: bool
    ) -> list[asyncpg.Record]:
        return await conn.fetch(
            "SELECT repaired_account_id, field_name, previous_value, corrected_value "
            "FROM payment.fn_repair_balances($1, $2, $3)",
            reason,
            incident_id,
            dry_run,
        )

    async def fail_stale(
        self, conn: asyncpg.Connection, *, older_than_seconds: int, reason: str, incident_id: UUID | None
    ) -> int:
        return await conn.fetchval(
            "SELECT payment.fn_fail_stale_transactions($1, $2, $3)",
            timedelta(seconds=older_than_seconds),
            reason,
            incident_id,
        )

    async def account_status(self, conn: asyncpg.Connection, account_id: UUID) -> asyncpg.Record | None:
        return await conn.fetchrow(
            "SELECT id, status::text AS status, is_synthetic, currency FROM payment.accounts WHERE id = $1",
            account_id,
        )

    async def set_account_status(self, conn: asyncpg.Connection, account_id: UUID, status: str) -> None:
        await conn.execute(
            "UPDATE payment.accounts SET status = $2::payment.account_status WHERE id = $1", account_id, status
        )

    async def tamper_balance(self, conn: asyncpg.Connection, account_number: str, delta_minor: int) -> int | None:
        """Laboratoire uniquement : altère un solde sans écriture au grand livre."""
        return await conn.fetchval(
            """
            SELECT payment.fn_lab_tamper_balance(a.id, $2)
              FROM payment.accounts a
             WHERE a.account_number = $1
            """,
            account_number,
            delta_minor,
        )
