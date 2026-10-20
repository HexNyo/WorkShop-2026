"""Point d'entrée ASGI de payment-api."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from ra_common.logging import configure_logging, log_event
from ra_common.middleware import RequestContextMiddleware
from ra_common.problem import install_problem_handlers

from app.api import routes_accounts, routes_admin, routes_health, routes_lab, routes_stream, routes_transactions
from app.api.errors import install_domain_handlers
from app.api.fault_middleware import FaultInjectionMiddleware
from app.container import Container
from app.core.config import Settings

logger = logging.getLogger("payment.main")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    configure_logging(settings.service_name, settings.version, settings.log_level)
    container = Container.build(settings)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        await container.start()
        log_event(
            logger,
            logging.INFO,
            "service.started",
            "payment-api started",
            chaos_lab_enabled=settings.chaos_lab_enabled,
            currencies=sorted(container.currencies),
        )
        if settings.chaos_lab_enabled:
            log_event(logger, logging.WARNING, "lab.enabled", "CHAOS LAB ENABLED — never use in production")
        try:
            yield
        finally:
            await container.stop()
            log_event(logger, logging.INFO, "service.stopped", "payment-api stopped")

    app = FastAPI(
        title="RESILIENCE-ALPHA payment-api",
        version=settings.version,
        lifespan=lifespan,
        docs_url="/docs" if settings.enable_docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.enable_docs else None,
    )
    app.state.container = container
    app.state.token_verifier = container.security.verifier

    install_problem_handlers(app)
    install_domain_handlers(app)
    if container.faults is not None:
        app.add_middleware(FaultInjectionMiddleware, injector=container.faults)
    app.add_middleware(RequestContextMiddleware)

    # routes_stream AVANT routes_transactions : /v1/transactions/events ne doit pas être
    # capturé par /v1/transactions/{transaction_id}.
    routers = [routes_stream, routes_accounts, routes_transactions, routes_health, routes_admin]
    if settings.chaos_lab_enabled:
        routers.append(routes_lab)
    for module in routers:
        app.include_router(module.router)
    return app


app = create_app()
