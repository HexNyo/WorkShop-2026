"""Construction des deux applications ASGI (CONTROL et SUPERVISION) sur un conteneur commun."""

from __future__ import annotations

from fastapi import FastAPI
from ra_common.middleware import RequestContextMiddleware
from ra_common.problem import install_problem_handlers

from app.api import control, supervision
from app.api.common import health_router, install_unavailable_handler
from app.container import Container


def _base_app(container: Container, title: str) -> FastAPI:
    settings = container.settings
    app = FastAPI(
        title=title,
        version=settings.version,
        docs_url="/docs" if settings.enable_docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.enable_docs else None,
    )
    app.state.container = container
    install_problem_handlers(app)
    install_unavailable_handler(app)
    app.add_middleware(RequestContextMiddleware)
    app.include_router(health_router)
    return app


def create_control_app(container: Container) -> FastAPI:
    app = _base_app(container, "RESILIENCE-ALPHA remediation-engine — CONTROL")
    app.state.token_verifier = container.control_verifier
    app.include_router(control.router)
    app.include_router(control.pilot, prefix="/v1")
    return app


def create_supervision_app(container: Container) -> FastAPI:
    app = _base_app(container, "RESILIENCE-ALPHA remediation-engine — SUPERVISION")
    app.state.token_verifier = container.supervision_verifier
    app.include_router(supervision.router)
    # Pilotage restreint (remediation.admin) joignable via la passerelle ; le webhook reste sur CONTROL.
    app.include_router(control.pilot, prefix="/v1/admin")
    return app
