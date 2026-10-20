"""Consultation des comptes fictifs et de leur grand livre."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query

from app.api.deps import caller, decode_seq_cursor, get_container
from app.api.schemas import AccountList, AccountOut, LedgerEntryOut, LedgerPage
from app.container import Container
from app.domain.models import ROLE_CUSTOMER, ROLE_OPERATOR, ROLE_SYNTHETIC, Caller

router = APIRouter(prefix="/v1/accounts", tags=["accounts"])
READERS = (ROLE_CUSTOMER, ROLE_OPERATOR, ROLE_SYNTHETIC)


@router.get("", response_model=AccountList, summary="Comptes visibles par l'appelant")
async def list_accounts(
    include_synthetic: bool = Query(False, description="Opérateurs uniquement"),
    container: Container = Depends(get_container),
    current: Caller = Depends(caller(*READERS)),
) -> AccountList:
    accounts = await container.transactions.list_accounts(current, include_synthetic=include_synthetic)
    return AccountList(items=[AccountOut.of(account, container.currencies[account.currency]) for account in accounts])


@router.get("/{account_id}", response_model=AccountOut, summary="Détail d'un compte")
async def get_account(
    account_id: UUID, container: Container = Depends(get_container), current: Caller = Depends(caller(*READERS))
) -> AccountOut:
    account = await container.transactions.get_account(current, account_id)
    return AccountOut.of(account, container.currencies[account.currency])


@router.get("/{account_id}/ledger", response_model=LedgerPage, summary="Écritures du grand livre d'un compte")
async def ledger(
    account_id: UUID,
    limit: int = Query(50, ge=1, le=200),
    cursor: str | None = Query(None, max_length=20),
    container: Container = Depends(get_container),
    current: Caller = Depends(caller(*READERS)),
) -> LedgerPage:
    account, entries = await container.transactions.ledger(
        current, account_id, before_seq=decode_seq_cursor(cursor), limit=limit + 1
    )
    units = container.currencies[account.currency]
    page = entries[:limit]
    next_cursor = str(page[-1].seq) if len(entries) > limit else None
    return LedgerPage(items=[LedgerEntryOut.of(entry, units) for entry in page], next_cursor=next_cursor)
