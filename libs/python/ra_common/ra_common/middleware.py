"""Middleware ASGI : identifiants de requête, trace W3C, journal d'accès, métriques HTTP."""

from __future__ import annotations

import logging
import re
import secrets
import uuid
from time import perf_counter

from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from ra_common.context import (
    correlation_id_var,
    principal_id_var,
    request_id_var,
    span_id_var,
    trace_id_var,
)
from ra_common.metrics import observe_http
from ra_common.problem import problem_response

logger = logging.getLogger("ra_common.http")

_SAFE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_TRACEPARENT = re.compile(r"^[0-9a-f]{2}-([0-9a-f]{32})-([0-9a-f]{16})-[0-9a-f]{2}$")
_QUIET_PATHS = frozenset({"/health/liveness", "/health/readiness", "/metrics"})


def sanitize_identifier(value: str | None) -> str | None:
    """Accepte un identifiant fourni par le client uniquement s'il est sûr à journaliser."""
    if value and _SAFE_ID.match(value):
        return value
    return None


def parse_traceparent(value: str | None) -> str | None:
    """Renvoie le trace-id d'un en-tête traceparent W3C valide (sinon None)."""
    if not value:
        return None
    match = _TRACEPARENT.match(value.strip().lower())
    if not match or match.group(1) == "0" * 32:
        return None
    return match.group(1)


class RequestContextMiddleware:
    """À installer en dernier (donc le plus à l'extérieur après ServerErrorMiddleware)."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        request_id = sanitize_identifier(headers.get("x-request-id")) or str(uuid.uuid4())
        trace_id = parse_traceparent(headers.get("traceparent")) or uuid.uuid4().hex
        tokens = (
            request_id_var.set(request_id),
            trace_id_var.set(trace_id),
            span_id_var.set(secrets.token_hex(8)),
            correlation_id_var.set(sanitize_identifier(headers.get("x-correlation-id"))),
            principal_id_var.set(None),
        )
        state = {"status": 500, "started": False}
        start = perf_counter()

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                state["status"] = message["status"]
                state["started"] = True
                MutableHeaders(scope=message)["X-Request-ID"] = request_id
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        except Exception:
            logger.exception("unhandled exception", extra={"event": "http.unhandled_exception"})
            if not state["started"]:
                response = problem_response(
                    instance=scope.get("path", ""),
                    status=500,
                    code="INTERNAL_ERROR",
                    title="Internal error",
                    detail="An unexpected error occurred",
                )
                await response(scope, receive, send_wrapper)
        finally:
            duration = perf_counter() - start
            route_obj = scope.get("route")
            route = getattr(route_obj, "path", None) or "unmatched"
            method = scope.get("method", "")
            status = int(state["status"])
            observe_http(method, route, status, duration)
            path = scope.get("path", "")
            level = logging.WARNING if status >= 500 else (logging.DEBUG if path in _QUIET_PATHS else logging.INFO)
            logger.log(
                level,
                "%s %s -> %s",
                method,
                route,
                status,
                extra={
                    "event": "http.request",
                    "http": {
                        "method": method,
                        "route": route,
                        "path": path,
                        "status": status,
                        "duration_ms": round(duration * 1000, 2),
                    },
                },
            )
            for var, token in zip(
                (request_id_var, trace_id_var, span_id_var, correlation_id_var, principal_id_var), tokens, strict=True
            ):
                var.reset(token)
