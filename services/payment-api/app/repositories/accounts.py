"""Comptes fictifs et projection de leurs soldes."""

from __future__ import annotations

from uuid import UUID

import asyncpg

from app.domain.models import Account

_SELECT = """
SELECT a.id, a.account_number, a.owner_principal_id, a.holder_name, a.currency, a.status::text AS status,
       a.is_synthetic, b.available_minor, b.updated_at AS balance_updated_at
  FROM payment.accounts a
  JOIN payment.account_balances b ON b.account_id = a.id
"""


def _to_account(row: asyncpg.Record) -> Account:
    return Account(
        id=UUID(str(row["id"])),
        account_number=row["account_number"],
        owner_principal_id=UUID(str(row["owner_principal_id"])),
        holder_name=row["holder_name"],
        currency=row["currency"],
        status=row["status"],
        is_synthetic=row["is_synthetic"],
        available_minor=row["available_minor"],
        balance_updated_at=row["balance_updated_at"],
    )


class AccountRepository:
    async def get(self, conn: asyncpg.Connection, account_id: UUID) -> Account | None:
        row = await conn.fetchrow(_SELECT + " WHERE a.id = $1", account_id)
        return _to_account(row) if row else None

    async def get_by_number(self, conn: asyncpg.Connection, account_number: str) -> Account | None:
        row = await conn.fetchrow(_SELECT + " WHERE a.account_number = $1", account_number)
        return _to_account(row) if row else None

    async def list(
        self, conn: asyncpg.Connection, *, owner_id: UUID | None, synthetic: bool | None
    ) -> list[Account]:
        rows = await conn.fetch(
            _SELECT
            + """
             WHERE ($1::uuid IS NULL OR a.owner_principal_id = $1)
               AND ($2::boolean IS NULL OR a.is_synthetic = $2)
             ORDER BY a.account_number
            """,
            owner_id,
            synthetic,
        )
        return [_to_account(row) for row in rows]

    async def currencies(self, conn: asyncpg.Connection) -> dict[str, int]:
        rows = await conn.fetch("SELECT code, minor_units FROM payment.currencies")
        return {row["code"]: row["minor_units"] for row in rows}
