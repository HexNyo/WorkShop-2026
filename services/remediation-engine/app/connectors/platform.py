"""Connecteurs vers payment-api (/admin) et auth-service (/internal), identité svc-remediation."""

from __future__ import annotations

import asyncio
import time

import httpx
from ra_common.security.service_token import ServiceTokenClient

from app.connectors.base import ActionError, StepContext, call, expect


class PaymentAdminConnector:
    def __init__(self, http: httpx.AsyncClient, base_url: str, tokens: ServiceTokenClient) -> None:
        self._http = http
        self._base = base_url.rstrip("/")
        self._tokens = tokens

    async def _request(self, ctx: StepContext, method: str, path: str, body: dict | None = None) -> httpx.Response:
        return await call(
            self._http, method, f"{self._base}{path}", tokens=self._tokens, json=body, correlation_id=str(ctx.incident.id)
        )

    def _reasoned(self, ctx: StepContext, **fields) -> dict:
        return {"reason": ctx.reason, "incident_id": str(ctx.incident.id), **fields}

    async def set_flag(self, ctx: StepContext, key: str, value) -> dict:
        body = expect(await self._request(ctx, "PUT", f"/admin/v1/runtime-flags/{key}", self._reasoned(ctx, value=value)), 200)
        return {"key": key, "previous_value": body.get("previous_value"), "value": body.get("value")}

    async def integrity_report(self, ctx: StepContext, require_pass: bool) -> dict:
        body = expect(await self._request(ctx, "POST", "/admin/v1/integrity/reports", {"incident_id": str(ctx.incident.id)}), 201)
        failing = sorted(name for name, results in body.get("checks", {}).items() if results[0]["status"] != "pass")
        output = {"status": body.get("status"), "report_id": body.get("report_id"), "failing_checks": failing}
        if require_pass and body.get("status") == "fail":
            raise ActionError(f"integrity still failing: {', '.join(failing)}", output=output)
        return output

    async def repair_balances(self, ctx: StepContext, dry_run: bool) -> dict:
        response = await self._request(ctx, "POST", "/admin/v1/integrity/repair", self._reasoned(ctx, dry_run=dry_run))
        if response.status_code == 409 and response.json().get("code") == "LEDGER_COMPROMISED":
            raise ActionError(
                "ledger hash chain is broken: automatic repair refused, restore from backup required",
                fatal=True,
                output={"code": "LEDGER_COMPROMISED"},
            )
        body = expect(response, 200)
        return {
            "corrections": len(body.get("repaired", [])),
            "repaired": body.get("repaired", [])[:20],
            "integrity_after": body.get("integrity_after"),
        }

    async def purge_stale(self, ctx: StepContext, older_than_seconds: int) -> dict:
        body = expect(
            await self._request(
                ctx, "POST", "/admin/v1/maintenance/purge-stale", self._reasoned(ctx, older_than_seconds=older_than_seconds)
            ),
            200,
        )
        return {"purged": body.get("purged", 0)}

    async def freeze_account(self, ctx: StepContext, account_id: str) -> dict:
        response = await self._request(ctx, "POST", f"/admin/v1/accounts/{account_id}/freeze", self._reasoned(ctx))
        if response.status_code in (404, 409):
            # Compte inexistant ou non gelable (synthétique, clôturé) : retenter est inutile.
            try:
                expect(response, 200)
            except ActionError as exc:
                raise ActionError(str(exc), fatal=True, output=exc.output) from exc
        body = expect(response, 200)
        return {"account_id": account_id, "status": body.get("status")}


class AuthAdminConnector:
    def __init__(self, http: httpx.AsyncClient, base_url: str, tokens: ServiceTokenClient) -> None:
        self._http = http
        self._base = base_url.rstrip("/")
        self._tokens = tokens

    async def contain(self, ctx: StepContext, principal_id: str, *, disable: bool, reason: str) -> dict:
        action = "disable" if disable else "revoke-tokens"
        response = await call(
            self._http,
            "POST",
            f"{self._base}/internal/v1/principals/{principal_id}/{action}",
            tokens=self._tokens,
            json={"reason": reason, "incident_id": str(ctx.incident.id)},
            correlation_id=str(ctx.incident.id),
        )
        if response.status_code in (403, 404):
            # Garde-fou d'auth-service (principal privilégié ou de service) ou cible inconnue.
            body = response.json() if response.content else {}
            raise ActionError(
                f"containment refused by auth-service: {body.get('detail', response.status_code)}",
                fatal=True,
                output={"status": response.status_code, "code": body.get("code")},
            )
        body = expect(response, 200)
        return {
            "principal_id": principal_id,
            "is_active": body.get("is_active"),
            "refresh_tokens_revoked": body.get("refresh_tokens_revoked"),
        }


class ProbeConnector:
    def __init__(self, http: httpx.AsyncClient, readiness_urls: dict[str, str]) -> None:
        self._http = http
        self._urls = readiness_urls

    async def wait_ready(self, ctx: StepContext, service: str, timeout_seconds: int, interval_seconds: float) -> dict:
        url = self._urls.get(service)
        if url is None:
            raise ActionError(f"no readiness probe configured for {service}", fatal=True)
        started = time.monotonic()
        attempts, last = 0, "no response"
        while time.monotonic() - started < timeout_seconds:
            attempts += 1
            try:
                response = await self._http.get(url, timeout=2.0)
                if response.status_code == 200:
                    return {
                        "service": service,
                        "ready_after_seconds": round(time.monotonic() - started, 2),
                        "attempts": attempts,
                        "status": response.json().get("status"),
                    }
                last = f"HTTP {response.status_code}"
            except httpx.HTTPError as exc:
                last = exc.__class__.__name__
            await asyncio.sleep(interval_seconds)
        raise ActionError(f"{service} not ready after {timeout_seconds}s ({last})", output={"attempts": attempts})
