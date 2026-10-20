"""Protocole de validation post-reprise : Synthetic Transaction Monitoring (V1 → V9).

Un redémarrage réussi ne suffit jamais. Le vérificateur emploie son identité
dédiée `svc-synthetic` (et non celle de la remédiation) et prouve successivement
que l'API est joignable, l'authentification opérationnelle, le traitement métier
fonctionnel (transaction réelle, idempotence, historisation, grand livre), la base
intègre et la reprise stable. Le premier contrôle en échec interrompt la séquence.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

import httpx
import jwt
from ra_common.db import Database
from ra_common.logging import log_event
from ra_common.security.service_token import ServiceTokenClient, ServiceTokenError

from app.connectors.base import ActionError, call
from app.core.config import Settings
from app.observability import VERIFICATIONS
from app.repositories.runs import VerificationRepository
from app.services.events import SupervisionEvents

logger = logging.getLogger("remediation.verifier")

CHECKS = (
    "API_READINESS",
    "AUTH_M2M_TOKEN",
    "SYNTHETIC_BALANCES_READ",
    "SYNTHETIC_TX_EXECUTE",
    "IDEMPOTENCY_REPLAY",
    "TX_READ_BACK",
    "SYNTHETIC_TX_COMPENSATE",
    "DATA_INTEGRITY",
    "STABILITY_WINDOW",
)
READINESS_MAX_MS = 1000
EXECUTION_MAX_MS = 2000


class CheckFailed(Exception):
    def __init__(self, message: str, **detail: Any) -> None:
        super().__init__(message)
        self.detail = {"reason": message, **detail}


@dataclass(slots=True)
class _RunState:
    run_id: UUID
    correlation_id: str | None
    token: str | None = None
    accounts: dict[str, dict[str, Any]] = field(default_factory=dict)
    initial: dict[str, int] = field(default_factory=dict)
    forward_id: str | None = None
    forward_body: dict[str, Any] | None = None
    forward_key: str | None = None
    transaction_ids: list[UUID] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class VerificationOutcome:
    run_id: UUID
    passed: bool
    failed_check: str | None
    transaction_ids: list[UUID]


class SyntheticVerifier:
    def __init__(
        self,
        *,
        db: Database,
        repository: VerificationRepository,
        http: httpx.AsyncClient,
        tokens: ServiceTokenClient,
        events: SupervisionEvents,
        settings: Settings,
    ) -> None:
        self._db = db
        self._repository = repository
        self._http = http
        self._tokens = tokens
        self._events = events
        self._settings = settings
        self._base = settings.payment_base_url.rstrip("/")
        self._amount_minor = int(settings.stm_amount.replace(".", ""))
        self._lock = asyncio.Lock()

    async def run(self, *, incident_id: UUID | None, execution_id: UUID | None, trigger_source: str) -> VerificationOutcome:
        # Une seule vérification à la fois : les sondes partagent les comptes RA-9xxx.
        async with self._lock:
            return await self._run(incident_id=incident_id, execution_id=execution_id, trigger_source=trigger_source)

    async def _run(self, *, incident_id: UUID | None, execution_id: UUID | None, trigger_source: str) -> VerificationOutcome:
        async with self._db.transaction() as conn:
            run_id = await self._repository.create(
                conn, incident_id=incident_id, execution_id=execution_id, trigger_source=trigger_source
            )
        self._events.publish(
            "verification.started",
            {"run_id": str(run_id), "trigger_source": trigger_source, "planned_checks": list(CHECKS)},
            incident_id,
        )
        state = _RunState(run_id=run_id, correlation_id=str(incident_id) if incident_id else None)
        steps: list[tuple[str, Callable[[_RunState], Awaitable[dict[str, Any]]]]] = [
            ("API_READINESS", self._api_readiness),
            ("AUTH_M2M_TOKEN", self._auth_token),
            ("SYNTHETIC_BALANCES_READ", self._read_balances),
            ("SYNTHETIC_TX_EXECUTE", self._execute),
            ("IDEMPOTENCY_REPLAY", self._replay),
            ("TX_READ_BACK", self._read_back),
            ("SYNTHETIC_TX_COMPENSATE", self._compensate),
            ("DATA_INTEGRITY", self._integrity),
            ("STABILITY_WINDOW", self._stability),
        ]
        failed: str | None = None
        for seq, (code, check) in enumerate(steps, start=1):
            started = time.perf_counter()
            try:
                detail, passed = await check(state), True
            except CheckFailed as exc:
                detail, passed = exc.detail, False
            except (ActionError, httpx.HTTPError, ServiceTokenError, KeyError, ValueError, TypeError) as exc:
                detail, passed = {"reason": f"{exc.__class__.__name__}: {exc}"[:500]}, False
            latency = int((time.perf_counter() - started) * 1000)
            async with self._db.transaction() as conn:
                await self._repository.add_check(
                    conn, run_id=run_id, seq=seq, code=code, passed=passed, latency_ms=latency, detail=detail
                )
            self._events.publish(
                "verification.check",
                {"run_id": str(run_id), "seq": seq, "code": code, "passed": passed, "latency_ms": latency, "detail": detail},
                incident_id,
            )
            if not passed:
                failed = code
                break

        passed_all = failed is None
        async with self._db.transaction() as conn:
            await self._repository.finish(
                conn, run_id, passed=passed_all, failed_check=failed, transaction_ids=state.transaction_ids
            )
        self._events.publish(
            "verification.completed",
            {
                "run_id": str(run_id),
                "status": "PASSED" if passed_all else "FAILED",
                "failed_check": failed,
                "synthetic_transaction_ids": [str(tx) for tx in state.transaction_ids],
            },
            incident_id,
        )
        VERIFICATIONS.labels(status="PASSED" if passed_all else "FAILED", trigger=trigger_source).inc()
        log_event(
            logger,
            logging.INFO if passed_all else logging.WARNING,
            "verification.completed",
            f"synthetic verification {'passed' if passed_all else 'failed'}",
            run_id=str(run_id),
            incident_id=str(incident_id) if incident_id else None,
            trigger_source=trigger_source,
            failed_check=failed,
        )
        return VerificationOutcome(run_id=run_id, passed=passed_all, failed_check=failed, transaction_ids=state.transaction_ids)

    # ------------------------------------------------------------------- helpers
    async def _api(self, state: _RunState, method: str, path: str, **kwargs: Any) -> httpx.Response:
        return await call(
            self._http,
            method,
            f"{self._base}{path}",
            tokens=self._tokens,
            correlation_id=state.correlation_id,
            attempts=1,
            **kwargs,
        )

    async def _balances(self, state: _RunState) -> dict[str, int]:
        response = await self._api(state, "GET", "/v1/accounts")
        if response.status_code != 200:
            raise CheckFailed("cannot read synthetic accounts", status=response.status_code)
        found = {item["account_number"]: item for item in response.json()["items"]}
        wanted = (self._settings.synthetic_account_a, self._settings.synthetic_account_b)
        missing = [number for number in wanted if number not in found]
        if missing:
            raise CheckFailed("synthetic accounts not visible", missing=missing)
        state.accounts = {number: found[number] for number in wanted}
        return {number: found[number]["balance"]["minor"] for number in wanted}

    def _transfer_body(self, debit: str, credit: str, state: _RunState) -> dict[str, Any]:
        return {
            "debit_account_id": state.accounts[debit]["id"],
            "credit_account_number": credit,
            "amount": {"value": self._settings.stm_amount, "currency": self._settings.stm_currency},
            "description": f"STM {state.run_id}",
        }

    async def _transfer(self, state: _RunState, body: dict[str, Any], key: str) -> httpx.Response:
        return await self._api(state, "POST", "/v1/transactions", json=body, extra_headers={"Idempotency-Key": key})

    # -------------------------------------------------------------------- checks
    async def _api_readiness(self, _: _RunState) -> dict[str, Any]:
        started = time.perf_counter()
        response = await self._http.get(f"{self._base}/health/readiness", timeout=3.0)
        latency = int((time.perf_counter() - started) * 1000)
        status = response.json().get("status") if response.content else None
        if response.status_code != 200:
            raise CheckFailed("payment-api is not ready", http_status=response.status_code, status=status)
        if latency > READINESS_MAX_MS:
            raise CheckFailed("readiness probe too slow", latency_ms=latency)
        return {"http_status": 200, "status": status}

    async def _auth_token(self, state: _RunState) -> dict[str, Any]:
        self._tokens.invalidate()  # preuve d'une émission fraîche, pas d'un jeton en cache
        try:
            token = await self._tokens.get_token()
        except ServiceTokenError as exc:
            raise CheckFailed(f"auth-service did not issue a token: {exc}") from exc
        claims = jwt.decode(token, options={"verify_signature": False})
        if "payment-api" not in claims.get("aud", []) or "svc.synthetic" not in claims.get("roles", []):
            raise CheckFailed("unexpected token scope", aud=claims.get("aud"), roles=claims.get("roles"))
        state.token = token
        return {"aud": claims["aud"], "expires_in": claims["exp"] - claims["iat"]}

    async def _read_balances(self, state: _RunState) -> dict[str, Any]:
        state.initial = await self._balances(state)
        return {"balances_minor": state.initial}

    async def _execute(self, state: _RunState) -> dict[str, Any]:
        a, b = self._settings.synthetic_account_a, self._settings.synthetic_account_b
        state.forward_body = self._transfer_body(a, b, state)
        state.forward_key = f"stm-{state.run_id}-fwd"
        started = time.perf_counter()
        response = await self._transfer(state, state.forward_body, state.forward_key)
        latency = int((time.perf_counter() - started) * 1000)
        body = response.json() if response.content else {}
        if response.status_code != 201 or body.get("status") != "EXECUTED":
            raise CheckFailed(
                "synthetic transaction not executed",
                http_status=response.status_code,
                status=body.get("status"),
                code=body.get("code") or (body.get("failure") or {}).get("code"),
            )
        if latency > EXECUTION_MAX_MS:
            raise CheckFailed("synthetic transaction too slow", latency_ms=latency)
        state.forward_id = body["id"]
        state.transaction_ids.append(UUID(body["id"]))
        return {"transaction_id": body["id"], "status": "EXECUTED"}

    async def _replay(self, state: _RunState) -> dict[str, Any]:
        response = await self._transfer(state, state.forward_body, state.forward_key)
        body = response.json() if response.content else {}
        if (
            response.status_code != 200
            or response.headers.get("idempotent-replayed") != "true"
            or body.get("id") != state.forward_id
        ):
            raise CheckFailed("idempotency guarantee broken", http_status=response.status_code, id=body.get("id"))
        return {"replayed_id": body["id"]}

    async def _read_back(self, state: _RunState) -> dict[str, Any]:
        detail = await self._api(state, "GET", f"/v1/transactions/{state.forward_id}")
        history = [item["status"] for item in detail.json().get("history", [])] if detail.status_code == 200 else []
        if history != ["PENDING", "VALIDATED", "EXECUTED"]:
            raise CheckFailed("transaction history inconsistent", history=history, http_status=detail.status_code)

        b = self._settings.synthetic_account_b
        ledger = await self._api(state, "GET", f"/v1/accounts/{state.accounts[b]['id']}/ledger", params={"limit": 5})
        entries = ledger.json().get("items", []) if ledger.status_code == 200 else []
        if not any(e["transaction_id"] == state.forward_id and e["direction"] == "CREDIT" for e in entries):
            raise CheckFailed("credit entry missing from the ledger", http_status=ledger.status_code)

        balances = await self._balances(state)
        a = self._settings.synthetic_account_a
        expected = {a: state.initial[a] - self._amount_minor, b: state.initial[b] + self._amount_minor}
        if balances != expected:
            raise CheckFailed("balances did not move as expected", expected=expected, actual=balances)
        return {"history": history, "balances_minor": balances}

    async def _compensate(self, state: _RunState) -> dict[str, Any]:
        a, b = self._settings.synthetic_account_a, self._settings.synthetic_account_b
        response = await self._transfer(state, self._transfer_body(b, a, state), f"stm-{state.run_id}-rev")
        body = response.json() if response.content else {}
        if response.status_code != 201 or body.get("status") != "EXECUTED":
            raise CheckFailed("compensation not executed", http_status=response.status_code, status=body.get("status"))
        state.transaction_ids.append(UUID(body["id"]))
        balances = await self._balances(state)
        if balances != state.initial:
            raise CheckFailed("probe balances not restored", expected=state.initial, actual=balances)
        return {"transaction_id": body["id"], "balances_minor": balances}

    async def _integrity(self, state: _RunState) -> dict[str, Any]:
        response = await self._api(state, "GET", "/health/integrity", params={"refresh": "true"})
        if response.status_code == 429:
            await asyncio.sleep(min(int(response.headers.get("retry-after", "5")), 15))
            response = await self._api(state, "GET", "/health/integrity", params={"refresh": "true"})
        body = response.json() if response.content else {}
        failing = sorted(name for name, results in body.get("checks", {}).items() if results[0]["status"] == "fail")
        if response.status_code != 200 or body.get("status") == "fail":
            raise CheckFailed("data integrity checks failing", http_status=response.status_code, failing=failing)
        return {"status": body.get("status"), "report_id": body.get("report_id")}

    async def _stability(self, _: _RunState) -> dict[str, Any]:
        samples = []
        for index in range(self._settings.stm_stability_samples):
            if index:
                await asyncio.sleep(self._settings.stm_stability_interval_seconds)
            response = await self._http.get(f"{self._base}/health/readiness", timeout=3.0)
            samples.append(response.status_code)
            if response.status_code != 200:
                raise CheckFailed("service unstable after recovery", samples=samples)
        return {"samples": samples}
