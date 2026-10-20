"""Cycle de vie des transactions fictives."""

from __future__ import annotations

import re
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Request, status
from starlette.responses import JSONResponse

from app.api.deps import caller, decode_time_cursor, encode_time_cursor, get_container
from app.api.schemas import (
    IDEMPOTENCY_KEY_PATTERN,
    BatchRequest,
    BatchResponse,
    BatchResultItem,
    CreateTransactionRequest,
    TransactionDetailOut,
    TransactionOut,
    TransactionPage,
)
from app.container import Container
from app.domain.errors import MalformedRequest, PaymentError
from app.domain.models import (
    ROLE_CUSTOMER,
    ROLE_OPERATOR,
    ROLE_SYNTHETIC,
    Caller,
    CreateTransactionCommand,
    Transaction,
    TransactionStatus,
)

router = APIRouter(prefix="/v1/transactions", tags=["transactions"])
READERS = (ROLE_CUSTOMER, ROLE_OPERATOR, ROLE_SYNTHETIC)
INITIATORS = (ROLE_CUSTOMER, ROLE_SYNTHETIC)
_IDEMPOTENCY_KEY = re.compile(IDEMPOTENCY_KEY_PATTERN)


def _command(body: CreateTransactionRequest, idempotency_key: str) -> CreateTransactionCommand:
    return CreateTransactionCommand(
        idempotency_key=idempotency_key,
        debit_account_id=body.debit_account_id,
        credit_account_number=body.credit_account_number,
        amount_value=body.amount.value,
        currency=body.amount.currency,
        description=body.description or None,
        auto_execute=body.auto_execute,
    )


def _out(container: Container, transaction: Transaction) -> TransactionOut:
    return TransactionOut.of(transaction, container.currencies[transaction.currency])


@router.post(
    "",
    response_model=TransactionOut,
    status_code=status.HTTP_201_CREATED,
    summary="Initier une transaction (Idempotency-Key obligatoire)",
    responses={200: {"description": "Rejeu idempotent"}},
)
async def create_transaction(
    body: CreateTransactionRequest,
    request: Request,
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
    container: Container = Depends(get_container),
    current: Caller = Depends(caller(*INITIATORS)),
) -> JSONResponse:
    if not idempotency_key or not _IDEMPOTENCY_KEY.match(idempotency_key):
        raise MalformedRequest("An Idempotency-Key header matching ^[A-Za-z0-9_:.-]{8,64}$ is required")
    outcome = await container.transactions.create(current, _command(body, idempotency_key))
    payload = _out(container, outcome.transaction).model_dump(mode="json")
    if outcome.created:
        location = str(request.url_for("get_transaction", transaction_id=str(outcome.transaction.id)).path)
        return JSONResponse(payload, status_code=201, headers={"Location": location})
    return JSONResponse(payload, status_code=200, headers={"Idempotent-Replayed": "true"})


@router.post(
    "/batch",
    response_model=BatchResponse,
    status_code=207,
    summary="Flux de transactions (1 à 50, chacune atomique indépendamment)",
)
async def create_batch(
    body: BatchRequest,
    container: Container = Depends(get_container),
    current: Caller = Depends(caller(*INITIATORS)),
) -> JSONResponse:
    results: list[BatchResultItem] = []
    for index, item in enumerate(body.items):
        request_body = CreateTransactionRequest(**item.model_dump(exclude={"idempotency_key"}))
        try:
            outcome = await container.transactions.create(current, _command(request_body, item.idempotency_key))
        except PaymentError as exc:
            results.append(
                BatchResultItem(index=index, status=exc.status, error={"code": exc.code, "detail": exc.detail, "errors": exc.errors})
            )
            continue
        results.append(
            BatchResultItem(
                index=index,
                status=201 if outcome.created else 200,
                transaction=_out(container, outcome.transaction),
            )
        )
    return JSONResponse(BatchResponse(results=results).model_dump(mode="json"), status_code=207)


@router.get("", response_model=TransactionPage, summary="Transactions visibles par l'appelant")
async def list_transactions(
    status_filter: TransactionStatus | None = Query(None, alias="status"),
    account_id: UUID | None = None,
    synthetic: bool | None = Query(None, description="Opérateurs uniquement"),
    limit: int = Query(50, ge=1, le=200),
    cursor: str | None = Query(None, max_length=200),
    container: Container = Depends(get_container),
    current: Caller = Depends(caller(*READERS)),
) -> TransactionPage:
    items = await container.transactions.list(
        current,
        status=status_filter,
        account_id=account_id,
        synthetic=synthetic,
        before=decode_time_cursor(cursor),
        limit=limit + 1,
    )
    page = items[:limit]
    next_cursor = encode_time_cursor(page[-1].created_at, page[-1].id) if len(items) > limit else None
    return TransactionPage(items=[_out(container, item) for item in page], next_cursor=next_cursor)


@router.get("/{transaction_id}", response_model=TransactionDetailOut, summary="Détail et historique d'une transaction")
async def get_transaction(
    transaction_id: UUID, container: Container = Depends(get_container), current: Caller = Depends(caller(*READERS))
) -> TransactionDetailOut:
    transaction, history = await container.transactions.get(current, transaction_id)
    return TransactionDetailOut.with_history(transaction, container.currencies[transaction.currency], history)


@router.post("/{transaction_id}/execute", response_model=TransactionOut, summary="Exécuter une transaction VALIDATED")
async def execute_transaction(
    transaction_id: UUID, container: Container = Depends(get_container), current: Caller = Depends(caller(*INITIATORS))
) -> TransactionOut:
    return _out(container, await container.transactions.execute(current, transaction_id))


@router.post("/{transaction_id}/cancel", response_model=TransactionOut, summary="Annuler une transaction non exécutée")
async def cancel_transaction(
    transaction_id: UUID, container: Container = Depends(get_container), current: Caller = Depends(caller(*INITIATORS))
) -> TransactionOut:
    return _out(container, await container.transactions.cancel(current, transaction_id))
