"""Sondes de santé et métriques (réseau interne uniquement)."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from starlette.responses import JSONResponse, Response

from app.api.deps import get_container
from app.container import Container
from app.core.db import UNAVAILABLE_ERRORS
from ra_common.health import CheckResult, health_response
from ra_common.metrics import metrics_response

router = APIRouter(tags=["health"])

_DB_LATENCY_FAIL_MS = 500.0


@router.get("/health/liveness", summary="Processus vivant")
async def liveness(container: Container = Depends(get_container)) -> JSONResponse:
    settings = container.settings
    return health_response(service=settings.service_name, version=settings.version)


@router.get("/health/readiness", summary="Prêt à servir")
async def readiness(container: Container = Depends(get_container)) -> JSONResponse:
    settings = container.settings
    checks: dict[str, CheckResult] = {}
    try:
        latency = await container.db.ping()
        status = "pass" if latency < _DB_LATENCY_FAIL_MS else "fail"
        checks["postgres:connectivity"] = CheckResult(status, round(latency, 2), "ms")
    except (*UNAVAILABLE_ERRORS, RuntimeError) as exc:
        checks["postgres:connectivity"] = CheckResult("fail", output=exc.__class__.__name__)
    pool = container.db.pool
    in_use = pool.get_size() - pool.get_idle_size()
    ratio = in_use / max(pool.get_max_size(), 1)
    checks["postgres:pool"] = CheckResult("warn" if ratio > 0.8 else "pass", round(ratio, 2), "ratio_in_use")
    checks["signing:key"] = CheckResult("pass", container.keys.kid, "kid")
    return health_response(service=settings.service_name, version=settings.version, checks=checks)


@router.get("/metrics", include_in_schema=False)
async def metrics() -> Response:
    return metrics_response()
