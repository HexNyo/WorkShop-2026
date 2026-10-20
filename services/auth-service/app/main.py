"""Point d'entrée ASGI de l'auth-service."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api import routes_admin, routes_auth, routes_health, routes_internal, routes_oauth, routes_tokens
from app.api.cookies import clear_refresh_cookie_header
from app.api.errors import install_domain_handlers
from app.container import Container
from app.core.config import Settings
from ra_common.logging import configure_logging, log_event
from ra_common.middleware import RequestContextMiddleware
from ra_common.problem import install_problem_handlers

logger = logging.getLogger("auth.main")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    configure_logging(settings.service_name, settings.version, settings.log_level)
    container = Container.build(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        await container.db.connect()
        await container.bootstrap.run()
        container.maintenance.start()
        log_event(logger, logging.INFO, "service.started", "auth-service started", kid=container.keys.kid)
        try:
            yield
        finally:
            await container.maintenance.stop()
            await container.led.close()
            await container.db.close()
            log_event(logger, logging.INFO, "service.stopped", "auth-service stopped")

    app = FastAPI(
        title="RESILIENCE-ALPHA auth-service",
        version=settings.version,
        lifespan=lifespan,
        docs_url="/docs" if settings.enable_docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.enable_docs else None,
    )
    app.state.container = container
    app.state.token_verifier = container.token_verifier
    app.state.clear_refresh_cookie = clear_refresh_cookie_header(settings)

    install_problem_handlers(app)
    install_domain_handlers(app)
    app.add_middleware(RequestContextMiddleware)

    for module in (routes_auth, routes_oauth, routes_tokens, routes_internal, routes_admin, routes_health):
        app.include_router(module.router)
    return app


app = create_app()
