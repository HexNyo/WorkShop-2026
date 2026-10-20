"""Réponses de santé au format application/health+json (draft-inadarei-api-health-check)."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from starlette.responses import JSONResponse

HEALTH_MEDIA_TYPE = "application/health+json"
Status = Literal["pass", "warn", "fail"]
_SEVERITY: Mapping[str, int] = {"pass": 0, "warn": 1, "fail": 2}


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class CheckResult:
    status: Status
    observed_value: Any = None
    observed_unit: str | None = None
    output: Any = None
    time: str = field(default_factory=_now)

    def as_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"status": self.status, "time": self.time}
        if self.observed_value is not None:
            data["observedValue"] = self.observed_value
        if self.observed_unit:
            data["observedUnit"] = self.observed_unit
        if self.output is not None:
            data["output"] = self.output
        return data


def aggregate(checks: Mapping[str, CheckResult]) -> Status:
    worst: Status = "pass"
    for result in checks.values():
        if _SEVERITY[result.status] > _SEVERITY[worst]:
            worst = result.status
    return worst


def health_response(
    *,
    service: str,
    version: str,
    checks: Mapping[str, CheckResult] | None = None,
    extra: Mapping[str, Any] | None = None,
) -> JSONResponse:
    status = aggregate(checks or {})
    body: dict[str, Any] = {"status": status, "service": service, "version": version}
    if extra:
        body.update(extra)
    if checks:
        body["checks"] = {name: [result.as_dict()] for name, result in checks.items()}
    return JSONResponse(
        body,
        status_code=503 if status == "fail" else 200,
        media_type=HEALTH_MEDIA_TYPE,
        headers={"Cache-Control": "no-store"},
    )
