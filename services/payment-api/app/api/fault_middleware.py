"""Application des pannes LATENCY / ERROR_RATE sur l'API métier (laboratoire uniquement)."""

from __future__ import annotations

import asyncio

from ra_common.problem import problem_response
from starlette.types import ASGIApp, Receive, Scope, Send

from app.services.faults import FaultInjector


class FaultInjectionMiddleware:
    def __init__(self, app: ASGIApp, injector: FaultInjector) -> None:
        self.app = app
        self.injector = injector

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope.get("path", "").startswith("/v1/"):
            if latency := self.injector.latency_ms:
                await asyncio.sleep(latency / 1000)
            if self.injector.should_fail_request():
                response = problem_response(
                    instance=scope["path"],
                    status=500,
                    code="INTERNAL_ERROR",
                    title="Internal error",
                    detail="An unexpected error occurred",
                )
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)
