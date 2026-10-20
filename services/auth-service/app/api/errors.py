"""Traduction des erreurs du domaine en réponses HTTP."""

from __future__ import annotations

from fastapi import FastAPI, Request
from starlette.responses import JSONResponse

from app.core.db import UNAVAILABLE_ERRORS
from app.domain.errors import (
    AccountLocked,
    InvalidCredentials,
    InvalidState,
    OAuthError,
    PolicyViolation,
    PrincipalNotFound,
    RefreshTokenInvalid,
    RefreshTokenReused,
)
from ra_common.problem import problem_response

NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def install_domain_handlers(app: FastAPI) -> None:
    @app.exception_handler(InvalidCredentials)
    async def _invalid_credentials(request: Request, _: InvalidCredentials) -> JSONResponse:
        return problem_response(
            instance=request.url.path,
            status=401,
            code="INVALID_CREDENTIALS",
            title="Authentication failed",
            detail="Invalid username or password",
            headers=NO_STORE,
        )

    @app.exception_handler(AccountLocked)
    async def _locked(request: Request, exc: AccountLocked) -> JSONResponse:
        return problem_response(
            instance=request.url.path,
            status=403,
            code="ACCOUNT_LOCKED",
            title="Account locked",
            detail="Too many failed attempts; try again later",
            headers={**NO_STORE, "Retry-After": str(exc.retry_after_seconds)},
        )

    @app.exception_handler(RefreshTokenInvalid)
    async def _refresh_invalid(request: Request, _: RefreshTokenInvalid) -> JSONResponse:
        return problem_response(
            instance=request.url.path,
            status=401,
            code="UNAUTHENTICATED",
            title="Authentication required",
            detail="The refresh token is invalid, expired or revoked",
            headers={**NO_STORE, "Set-Cookie": request.app.state.clear_refresh_cookie},
        )

    @app.exception_handler(RefreshTokenReused)
    async def _refresh_reused(request: Request, _: RefreshTokenReused) -> JSONResponse:
        return problem_response(
            instance=request.url.path,
            status=409,
            code="REFRESH_TOKEN_REUSED",
            title="Refresh token reuse detected",
            detail="The session has been terminated for security reasons; please sign in again",
            headers={**NO_STORE, "Set-Cookie": request.app.state.clear_refresh_cookie},
        )

    @app.exception_handler(PrincipalNotFound)
    async def _not_found(request: Request, _: PrincipalNotFound) -> JSONResponse:
        return problem_response(
            instance=request.url.path, status=404, code="NOT_FOUND", title="Resource not found", detail="Principal not found"
        )

    @app.exception_handler(PolicyViolation)
    async def _policy(request: Request, exc: PolicyViolation) -> JSONResponse:
        return problem_response(instance=request.url.path, status=403, code="FORBIDDEN", title="Forbidden", detail=str(exc))

    @app.exception_handler(InvalidState)
    async def _state(request: Request, exc: InvalidState) -> JSONResponse:
        return problem_response(instance=request.url.path, status=409, code="INVALID_STATE", title="Conflict", detail=str(exc))

    @app.exception_handler(OAuthError)
    async def _oauth(_: Request, exc: OAuthError) -> JSONResponse:
        headers = dict(NO_STORE)
        if exc.status == 401:
            headers["WWW-Authenticate"] = 'Basic realm="resilience-alpha", charset="UTF-8"'
        return JSONResponse(
            {"error": exc.error, "error_description": exc.description}, status_code=exc.status, headers=headers
        )

    async def _unavailable(request: Request, _: Exception) -> JSONResponse:
        return problem_response(
            instance=request.url.path,
            status=503,
            code="DEPENDENCY_UNAVAILABLE",
            title="Service unavailable",
            detail="The identity store is temporarily unavailable",
            headers={"Retry-After": "5"},
        )

    for error in UNAVAILABLE_ERRORS:
        app.add_exception_handler(error, _unavailable)
