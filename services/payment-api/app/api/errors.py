"""Traduction des erreurs du domaine et des indisponibilités en problem+json."""

from __future__ import annotations

from fastapi import FastAPI, Request
from ra_common.db import UNAVAILABLE_ERRORS
from ra_common.problem import problem_response
from starlette.responses import JSONResponse

from app.domain.errors import PaymentError


def install_domain_handlers(app: FastAPI) -> None:
    @app.exception_handler(PaymentError)
    async def _payment_error(request: Request, exc: PaymentError) -> JSONResponse:
        return problem_response(
            instance=request.url.path,
            status=exc.status,
            code=exc.code,
            title=exc.title,
            detail=exc.detail,
            errors=exc.errors,
            headers=exc.headers,
        )

    async def _unavailable(request: Request, _: Exception) -> JSONResponse:
        return problem_response(
            instance=request.url.path,
            status=503,
            code="DEPENDENCY_UNAVAILABLE",
            title="Service unavailable",
            detail="The payment store is temporarily unavailable",
            headers={"Retry-After": "5"},
        )

    for error in UNAVAILABLE_ERRORS:
        app.add_exception_handler(error, _unavailable)
