"""Registre (allowlist) des actions exécutables par les playbooks, avec validation des paramètres."""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.connectors.base import ActionError, StepContext
from app.connectors.docker import DockerConnector
from app.connectors.platform import AuthAdminConnector, PaymentAdminConnector, ProbeConnector

_REASON = re.compile(r"^[A-Z][A-Z_]{2,63}$")


class _Params(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RestartParams(_Params):
    stop_timeout_seconds: int = Field(10, ge=1, le=120)


class WaitReadyParams(_Params):
    timeout_seconds: int = Field(60, ge=1, le=600)
    interval_seconds: float = Field(2.0, ge=0.2, le=30)


class WriteModeParams(_Params):
    mode: Literal["READ_WRITE", "SYNTHETIC_ONLY", "READ_ONLY"]


class FlagParams(_Params):
    key: Literal["max_transaction_amount_minor", "max_requests_per_minute_per_principal"]
    value: int = Field(gt=0)


class IntegrityParams(_Params):
    require_pass: bool = False


class RepairParams(_Params):
    dry_run: bool = False


class PurgeParams(_Params):
    older_than_seconds: int = Field(120, ge=60, le=86400)


class ReasonParams(_Params):
    reason: str = Field(pattern=_REASON.pattern)


class NoParams(_Params):
    pass


Handler = Callable[[StepContext, str | None, Any], Awaitable[dict]]


def _uuid_target(target: str | None, what: str) -> str:
    try:
        return str(UUID(str(target)))
    except ValueError as exc:
        raise ActionError(f"target must be a {what} UUID", fatal=True) from exc


def _service_target(target: str | None) -> str:
    if not target:
        raise ActionError("target service is required", fatal=True)
    return target


class ActionRegistry:
    def __init__(
        self,
        *,
        docker: DockerConnector,
        payment: PaymentAdminConnector,
        auth: AuthAdminConnector,
        probes: ProbeConnector,
    ) -> None:
        self._actions: dict[str, tuple[type[_Params], Handler]] = {
            "docker.restart_container": (
                RestartParams,
                lambda ctx, target, p: docker.restart(ctx, _service_target(target), p.stop_timeout_seconds),
            ),
            "probe.wait_ready": (
                WaitReadyParams,
                lambda ctx, target, p: probes.wait_ready(ctx, _service_target(target), p.timeout_seconds, p.interval_seconds),
            ),
            "payment.set_write_mode": (
                WriteModeParams,
                lambda ctx, _target, p: payment.set_flag(ctx, "write_mode", p.mode),
            ),
            "payment.set_runtime_flag": (
                FlagParams,
                lambda ctx, _target, p: payment.set_flag(ctx, p.key, p.value),
            ),
            "payment.integrity_report": (
                IntegrityParams,
                lambda ctx, _target, p: payment.integrity_report(ctx, p.require_pass),
            ),
            "payment.repair_balances": (
                RepairParams,
                lambda ctx, _target, p: payment.repair_balances(ctx, p.dry_run),
            ),
            "payment.purge_stale": (
                PurgeParams,
                lambda ctx, _target, p: payment.purge_stale(ctx, p.older_than_seconds),
            ),
            "payment.freeze_account": (
                ReasonParams,
                lambda ctx, target, _p: payment.freeze_account(ctx, _uuid_target(target, "account")),
            ),
            "auth.revoke_principal_tokens": (
                ReasonParams,
                lambda ctx, target, p: auth.contain(ctx, _uuid_target(target, "principal"), disable=False, reason=p.reason),
            ),
            "auth.disable_principal": (
                ReasonParams,
                lambda ctx, target, p: auth.contain(ctx, _uuid_target(target, "principal"), disable=True, reason=p.reason),
            ),
        }

    @property
    def actions(self) -> frozenset[str]:
        return frozenset(self._actions)

    def validate(self, action: str, params: dict[str, Any]) -> _Params:
        entry = self._actions.get(action)
        if entry is None:
            raise ActionError(f"action {action} is not allowed", fatal=True)
        try:
            return entry[0].model_validate(params)
        except ValidationError as exc:
            raise ActionError(f"invalid parameters for {action}: {exc.errors()[0]['msg']}", fatal=True) from exc

    async def run(self, ctx: StepContext, action: str, target: str | None, params: dict[str, Any]) -> dict:
        validated = self.validate(action, params)
        return await self._actions[action][1](ctx, target, validated)
