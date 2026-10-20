"""Diagnostic : liveness, readiness, intégrité (données + logique métier), métriques."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from ra_common.db import UNAVAILABLE_ERRORS
from ra_common.health import CheckResult, health_response
from ra_common.metrics import metrics_response
from ra_common.security import AccessTokenClaims, require_roles
from starlette.responses import JSONResponse, Response

from app.api.deps import get_container
from app.container import Container
from app.domain.errors import RateLimited
from app.domain.models import ROLE_REMEDIATION, ROLE_SYNTHETIC, WriteMode
from app.observability import POOL
from app.services.integrity import IntegrityOutcome
from app.services.rate_limit import SlidingWindowLimiter

router = APIRouter(tags=["health"])
_DB_LATENCY_FAIL_MS = 500.0


@router.get("/health/liveness", summary="Processus vivant et boucle d'événements réactive")
async def liveness(container: Container = Depends(get_container)) -> JSONResponse:
    settings = container.settings
    return health_response(service=settings.service_name, version=settings.version)


@router.get("/health/readiness", summary="Prêt à servir")
async def readiness(container: Container = Depends(get_container)) -> JSONResponse:
    settings = container.settings
    checks: dict[str, CheckResult] = {}
    try:
        latency = await container.db.ping()
        checks["postgres:connectivity"] = CheckResult(
            "pass" if latency < _DB_LATENCY_FAIL_MS else "fail", round(latency, 2), "ms"
        )
    except (*UNAVAILABLE_ERRORS, RuntimeError) as exc:
        checks["postgres:connectivity"] = CheckResult("fail", output=exc.__class__.__name__)

    in_use, _idle, maximum = container.db.pool_usage()
    ratio = in_use / max(maximum, 1)
    checks["postgres:pool"] = CheckResult("warn" if ratio > 0.8 else "pass", round(ratio, 2), "ratio_in_use")
    checks.update(container.security.health_checks())

    flags = container.flags.current
    if flags is None:
        checks["runtime:write-mode"] = CheckResult("fail", output="runtime flags not loaded")
    else:
        mode = flags.write_mode
        checks["runtime:write-mode"] = CheckResult("pass" if mode is WriteMode.READ_WRITE else "warn", mode.value)
    checks["events:listener"] = CheckResult(
        "pass" if container.event_listener.connected else "warn", container.event_listener.connected, "connected"
    )
    if container.faults is not None and container.faults.readiness_failure:
        checks["lab:injected-fault"] = CheckResult("fail", output="READINESS_FAILURE")
    return health_response(service=settings.service_name, version=settings.version, checks=checks)


def integrity_response(container: Container, outcome: IntegrityOutcome, status_code: int | None = None) -> JSONResponse:
    settings = container.settings
    checks = {
        check.name: CheckResult(check.status, check.observed_value, check.observed_unit, output=check.output)
        for check in outcome.checks
    }
    response = health_response(
        service=settings.service_name,
        version=settings.version,
        checks=checks,
        extra={
            "report_id": str(outcome.report_id) if outcome.report_id else None,
            "generated_at": outcome.generated_at.isoformat() if outcome.generated_at else None,
            "duration_ms": outcome.duration_ms,
        },
    )
    if status_code is not None:
        response.status_code = status_code
    return response


@router.get("/health/integrity", summary="Cohérence des données et de la logique métier")
async def integrity(
    refresh: bool = Query(False, description="Ignore le cache (limité par principal)"),
    container: Container = Depends(get_container),
    claims: AccessTokenClaims = Depends(require_roles(ROLE_REMEDIATION, ROLE_SYNTHETIC)),
) -> JSONResponse:
    if refresh:
        delay = container.integrity_limiter.check(claims.sub, container.settings.integrity_refresh_per_minute)
        if delay is not None:
            raise RateLimited(SlidingWindowLimiter.retry_after(delay))
    outcome = await container.integrity.evaluate(trigger_source="HEALTH_PROBE", use_cache=not refresh)
    return integrity_response(container, outcome)


@router.get("/metrics", include_in_schema=False)
async def metrics(container: Container = Depends(get_container)) -> Response:
    for name, database in (("app", container.db), ("maint", container.maint_db)):
        in_use, idle, _ = database.pool_usage()
        POOL.labels(pool=name, state="in_use").set(in_use)
        POOL.labels(pool=name, state="idle").set(idle)
    return metrics_response()
