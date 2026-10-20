"""Erreurs HTTP au format RFC 9457 (application/problem+json) et gestionnaires FastAPI."""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import JSONResponse

from ra_common.context import request_id_var

PROBLEM_MEDIA_TYPE = "application/problem+json"
ERROR_TYPE_BASE = "https://errors.resilience-alpha.local/"

logger = logging.getLogger("ra_common.problem")

_STATUS_CODES: Mapping[int, tuple[str, str]] = {
    400: ("MALFORMED_REQUEST", "Malformed request"),
    401: ("UNAUTHENTICATED", "Authentication required"),
    403: ("FORBIDDEN", "Forbidden"),
    404: ("NOT_FOUND", "Resource not found"),
    405: ("METHOD_NOT_ALLOWED", "Method not allowed"),
    409: ("INVALID_STATE", "Conflict"),
    413: ("PAYLOAD_TOO_LARGE", "Payload too large"),
    415: ("UNSUPPORTED_MEDIA_TYPE", "Unsupported media type"),
    422: ("VALIDATION_ERROR", "Validation error"),
    429: ("RATE_LIMITED", "Too many requests"),
    500: ("INTERNAL_ERROR", "Internal error"),
    503: ("DEPENDENCY_UNAVAILABLE", "Service unavailable"),
}


class ProblemException(Exception):
    """Exception métier convertie en réponse problem+json."""

    def __init__(
        self,
        status: int,
        code: str,
        title: str,
        detail: str | None = None,
        *,
        errors: Sequence[Mapping[str, Any]] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(detail or title)
        self.status = status
        self.code = code
        self.title = title
        self.detail = detail
        self.errors = list(errors) if errors else None
        self.headers = dict(headers) if headers else None


def problem_response(
    *,
    instance: str,
    status: int,
    code: str,
    title: str,
    detail: str | None = None,
    errors: Sequence[Mapping[str, Any]] | None = None,
    headers: Mapping[str, str] | None = None,
) -> JSONResponse:
    body: dict[str, Any] = {
        "type": ERROR_TYPE_BASE + code.lower().replace("_", "-"),
        "title": title,
        "status": status,
        "code": code,
        "instance": instance,
    }
    if detail:
        body["detail"] = detail
    if request_id := request_id_var.get():
        body["correlation_id"] = request_id
    if errors:
        body["errors"] = list(errors)
    return JSONResponse(body, status_code=status, media_type=PROBLEM_MEDIA_TYPE, headers=dict(headers or {}))


# --- fabriques usuelles -------------------------------------------------------
def unauthenticated(detail: str = "A valid bearer token is required", code: str = "UNAUTHENTICATED") -> ProblemException:
    return ProblemException(
        401,
        code,
        "Authentication required",
        detail,
        headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
    )


def forbidden(detail: str = "Insufficient privileges for this operation", code: str = "FORBIDDEN") -> ProblemException:
    return ProblemException(403, code, "Forbidden", detail)


def not_found(detail: str = "Resource not found") -> ProblemException:
    return ProblemException(404, "NOT_FOUND", "Resource not found", detail)


def conflict(code: str, detail: str) -> ProblemException:
    return ProblemException(409, code, "Conflict", detail)


def unavailable(detail: str = "A required dependency is unavailable", retry_after: int = 5) -> ProblemException:
    return ProblemException(
        503, "DEPENDENCY_UNAVAILABLE", "Service unavailable", detail, headers={"Retry-After": str(retry_after)}
    )


# --- installation ---------------------------------------------------------------
def install_problem_handlers(app: FastAPI) -> None:
    @app.exception_handler(ProblemException)
    async def _problem(request: Request, exc: ProblemException) -> JSONResponse:
        return problem_response(
            instance=request.url.path,
            status=exc.status,
            code=exc.code,
            title=exc.title,
            detail=exc.detail,
            errors=exc.errors,
            headers=exc.headers,
        )

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        # Seuls l'emplacement et le message sont exposés : jamais la valeur saisie
        # (qui peut être un mot de passe).
        errors = [
            {"location": ".".join(str(part) for part in error.get("loc", ())), "message": error.get("msg", "invalid")}
            for error in exc.errors()
        ]
        return problem_response(
            instance=request.url.path,
            status=422,
            code="VALIDATION_ERROR",
            title="Validation error",
            detail="Request failed validation",
            errors=errors,
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code, title = _STATUS_CODES.get(exc.status_code, ("HTTP_ERROR", "HTTP error"))
        detail = exc.detail if isinstance(exc.detail, str) and exc.detail != title else None
        return problem_response(
            instance=request.url.path,
            status=exc.status_code,
            code=code,
            title=title,
            detail=detail,
            headers=getattr(exc, "headers", None),
        )
