"""Éléments partagés par les deux listeners : dépendances, erreurs, santé, curseurs."""

from __future__ import annotations

import base64
import binascii
from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, FastAPI, Request
from ra_common.db import UNAVAILABLE_ERRORS
from ra_common.health import CheckResult, health_response
from ra_common.metrics import metrics_response
from ra_common.problem import ProblemException, problem_response
from starlette.responses import JSONResponse, Response

from app.container import Container


def get_container(request: Request) -> Container:
    return request.app.state.container


def encode_cursor(moment: datetime, identifier: UUID) -> str:
    return base64.urlsafe_b64encode(f"{moment.isoformat()}|{identifier}".encode()).decode().rstrip("=")


def decode_cursor(cursor: str | None) -> tuple[datetime, UUID] | None:
    if not cursor:
        return None
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode()
        moment, identifier = raw.split("|", 1)
        return datetime.fromisoformat(moment), UUID(identifier)
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise ProblemException(400, "MALFORMED_REQUEST", "Malformed request", "Invalid pagination cursor") from exc


def install_unavailable_handler(app: FastAPI) -> None:
    async def _unavailable(request: Request, _: Exception) -> JSONResponse:
        return problem_response(
            instance=request.url.path,
            status=503,
            code="DEPENDENCY_UNAVAILABLE",
            title="Service unavailable",
            detail="The remediation store is temporarily unavailable",
            headers={"Retry-After": "5"},
        )

    for error in UNAVAILABLE_ERRORS:
        app.add_exception_handler(error, _unavailable)


health_router = APIRouter(tags=["health"])


@health_router.get("/health/liveness")
async def liveness(container: Container = Depends(get_container)) -> JSONResponse:
    return health_response(service=container.settings.service_name, version=container.settings.version)


@health_router.get("/health/readiness")
async def readiness(container: Container = Depends(get_container)) -> JSONResponse:
    checks: dict[str, CheckResult] = {}
    try:
        latency = await container.db.ping()
        checks["database:connectivity"] = CheckResult("pass" if latency < 500 else "fail", round(latency, 2), "ms")
    except (*UNAVAILABLE_ERRORS, RuntimeError) as exc:
        checks["database:connectivity"] = CheckResult("fail", output=exc.__class__.__name__)
    checks.update(container.security.health_checks())
    docker_ok = await container.docker.ping()
    # Sans proxy Docker, seules les actions de redémarrage sont indisponibles : état dégradé.
    checks["docker:proxy"] = CheckResult("pass" if docker_ok else "warn", docker_ok, "reachable")
    checks["engine:phase"] = CheckResult("pass", container.phases.phase.value)
    return health_response(service=container.settings.service_name, version=container.settings.version, checks=checks)


@health_router.get("/metrics", include_in_schema=False)
async def metrics() -> Response:
    return metrics_response()
