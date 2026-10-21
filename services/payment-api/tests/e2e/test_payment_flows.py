from __future__ import annotations

import asyncio
import contextlib
import json
import time

import httpx
import pytest

from tests.e2e.conftest import ACCOUNTS, NUMBERS, PAYMENT_URL, balance, new_key, pay


# ===================================================================== diagnostic
def test_liveness_readiness_and_metrics(api: httpx.Client) -> None:
    assert api.get("/health/liveness").json()["status"] == "pass"
    readiness = api.get("/health/readiness")
    assert readiness.status_code == 200, readiness.text
    checks = readiness.json()["checks"]
    for name in ("database:connectivity", "auth:jwks", "auth:revocation-feed", "runtime:write-mode", "events:listener"):
        assert checks[name][0]["status"] == "pass", (name, checks[name])
    metrics = api.get("/metrics").text
    assert "ra_http_requests_total" in metrics and 'ra_write_mode{mode="READ_WRITE"} 1.0' in metrics


def test_integrity_endpoint_checks_data_and_logic(api: httpx.Client, as_) -> None:
    assert api.get("/health/integrity", headers=as_("alice")).status_code == 403
    response = api.get("/health/integrity", params={"refresh": "true"}, headers=as_("svc-remediation"))
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "pass" and body["report_id"]
    assert body["checks"]["logic:dry-run-execution"][0]["status"] == "pass"
    assert {name for name in body["checks"] if name.startswith("data:")} == {
        "data:LEDGER_HASH_CHAIN", "data:LEDGER_RUNNING_BALANCE", "data:BALANCE_MATCHES_LEDGER", "data:DOUBLE_ENTRY",
        "data:MONEY_CONSERVATION", "data:SYNTHETIC_SEGREGATION", "data:STALE_IN_FLIGHT",
    }


# ======================================================================= comptes
def test_account_visibility(api: httpx.Client, as_) -> None:
    mine = {item["account_number"] for item in api.get("/v1/accounts", headers=as_("alice")).json()["items"]}
    assert mine == {"RA-1000-0001", "RA-1000-0002"}
    assert api.get(f"/v1/accounts/{ACCOUNTS['bob']}", headers=as_("alice")).status_code == 404

    operator = {item["account_number"] for item in api.get("/v1/accounts", headers=as_("noc-operator")).json()["items"]}
    assert "RA-1000-0003" in operator and not any(number.startswith("RA-9") for number in operator)

    probes = {item["account_number"] for item in api.get("/v1/accounts", headers=as_("svc-synthetic")).json()["items"]}
    assert probes == {"RA-9000-0001", "RA-9000-0002"}

    assert api.get("/v1/accounts").status_code == 401
    assert api.get("/v1/accounts", headers=as_("svc-remediation")).status_code == 403


# ===================================================================== paiements
def test_payment_lifecycle_history_ledger_and_balances(api: httpx.Client, as_) -> None:
    alice, bob = as_("alice"), as_("bob")
    alice_before, bob_before = balance(api, alice, "alice"), balance(api, bob, "bob")

    created = pay(api, alice, "alice", "bob", "12.34")
    assert created.status_code == 201, created.text
    assert created.headers["location"].endswith(created.json()["id"])
    body = created.json()
    assert body["status"] == "EXECUTED" and body["failure"] is None
    assert body["amount"] == {"value": "12.34", "currency": "EUR", "minor": 1234}
    assert body["validated_at"] and body["executed_at"]

    detail = api.get(f"/v1/transactions/{body['id']}", headers=alice).json()
    assert [step["status"] for step in detail["history"]] == ["PENDING", "VALIDATED", "EXECUTED"]
    assert balance(api, alice, "alice") == alice_before - 1234
    assert balance(api, bob, "bob") == bob_before + 1234

    # Le bénéficiaire voit le paiement entrant, et l'écriture CREDIT au grand livre.
    assert api.get(f"/v1/transactions/{body['id']}", headers=bob).status_code == 200
    ledger = api.get(f"/v1/accounts/{ACCOUNTS['bob']}/ledger", params={"limit": 1}, headers=bob).json()
    entry = ledger["items"][0]
    assert entry["transaction_id"] == body["id"] and entry["direction"] == "CREDIT"
    assert entry["balance_after"]["minor"] == bob_before + 1234 and len(entry["entry_hash"]) == 64

    # Remboursement : les soldes de démonstration restent stables d'une exécution à l'autre.
    assert pay(api, bob, "bob", "alice", "12.34").json()["status"] == "EXECUTED"
    assert balance(api, alice, "alice") == alice_before


def test_concurrent_double_spend_is_impossible(api: httpx.Client, as_) -> None:
    from concurrent.futures import ThreadPoolExecutor

    bob = as_("bob")
    available = balance(api, bob, "bob")
    amount_minor = available // 4 + 1  # exactement 3 paiements peuvent passer
    value = f"{amount_minor // 100}.{amount_minor % 100:02d}"

    with ThreadPoolExecutor(max_workers=10) as pool:
        responses = list(pool.map(lambda _: pay(api, bob, "bob", "merchant", value), range(10)))
    statuses = sorted(response.json()["status"] for response in responses)
    assert statuses.count("EXECUTED") == 3 and statuses.count("REJECTED") == 7, statuses
    assert balance(api, bob, "bob") == available - 3 * amount_minor

    integrity = api.get("/health/integrity", params={"refresh": "true"}, headers=as_("svc-remediation"))
    assert integrity.status_code == 200, integrity.text
    # Restitution via le compte marchand pour garder les soldes de démonstration stables.
    merchant = as_("merchant")
    for _ in range(3):
        assert pay(api, merchant, "merchant", "bob", value).json()["status"] == "EXECUTED"


def test_idempotency(api: httpx.Client, as_) -> None:
    alice, key = as_("alice"), new_key("idem")
    first = pay(api, alice, "alice", "alice-savings", "1.00", key=key)
    replay = pay(api, alice, "alice", "alice-savings", "1.00", key=key)
    assert first.status_code == 201 and replay.status_code == 200
    assert replay.headers["idempotent-replayed"] == "true"
    assert replay.json()["id"] == first.json()["id"]

    conflict = pay(api, alice, "alice", "alice-savings", "2.00", key=key)
    assert conflict.status_code == 409 and conflict.json()["code"] == "IDEMPOTENCY_CONFLICT"

    missing = api.post("/v1/transactions", json={}, headers=alice)
    assert missing.status_code in (400, 422)
    no_key = api.post(
        "/v1/transactions",
        json={"debit_account_id": ACCOUNTS["alice"], "credit_account_number": "RA-1000-0002",
              "amount": {"value": "1.00", "currency": "EUR"}},
        headers=alice,
    )
    assert no_key.status_code == 400 and no_key.json()["code"] == "MALFORMED_REQUEST"
    assert pay(api, alice, "alice-savings", "alice", "1.00").json()["status"] == "EXECUTED"


def test_business_rejections_and_validation(api: httpx.Client, as_) -> None:
    alice, bob = as_("alice"), as_("bob")
    rejected = pay(api, bob, "bob", "alice", "9000.00")
    assert rejected.status_code == 201
    assert rejected.json()["status"] == "REJECTED" and rejected.json()["failure"]["code"] == "INSUFFICIENT_FUNDS"

    cases = [
        (pay(api, alice, "alice", "bob", "20000.00"), 422, "AMOUNT_LIMIT_EXCEEDED"),
        (pay(api, alice, "alice", "bob", "1.001"), 422, "VALIDATION_ERROR"),
        (pay(api, alice, "alice", "bob-usd", "1.00"), 422, "CURRENCY_MISMATCH"),
        (pay(api, alice, "alice", "syn-a", "1.00"), 422, "SYNTHETIC_SEGREGATION"),
        (pay(api, alice, "bob", "alice", "1.00"), 404, "NOT_FOUND"),
        (pay(api, alice, "alice", "alice", "1.00"), 422, "VALIDATION_ERROR"),
        (pay(api, as_("noc-operator"), "alice", "bob", "1.00"), 403, "FORBIDDEN"),
    ]
    for response, status, code in cases:
        assert response.status_code == status, response.text
        assert response.json()["code"] == code

    unknown = api.post(
        "/v1/transactions",
        json={"debit_account_id": ACCOUNTS["alice"], "credit_account_number": "RA-7777-7777",
              "amount": {"value": "1.00", "currency": "EUR"}},
        headers={**alice, "Idempotency-Key": new_key()},
    )
    assert unknown.status_code == 422 and unknown.json()["errors"][0]["location"] == "body.credit_account_number"


def test_two_step_execution_and_cancellation(api: httpx.Client, as_) -> None:
    alice, bob = as_("alice"), as_("bob")
    validated = pay(api, alice, "alice", "merchant", "3.00", auto_execute=False).json()
    assert validated["status"] == "VALIDATED" and validated["executed_at"] is None

    assert api.post(f"/v1/transactions/{validated['id']}/execute", headers=bob).status_code == 404
    executed = api.post(f"/v1/transactions/{validated['id']}/execute", headers=alice)
    assert executed.status_code == 200 and executed.json()["status"] == "EXECUTED"
    again = api.post(f"/v1/transactions/{validated['id']}/execute", headers=alice)
    assert again.status_code == 200 and again.json()["status"] == "EXECUTED", "execute is idempotent"
    late_cancel = api.post(f"/v1/transactions/{validated['id']}/cancel", headers=alice)
    assert late_cancel.status_code == 409 and late_cancel.json()["code"] == "INVALID_STATE"

    to_cancel = pay(api, alice, "alice", "merchant", "4.00", auto_execute=False).json()
    cancelled = api.post(f"/v1/transactions/{to_cancel['id']}/cancel", headers=alice).json()
    assert cancelled["status"] == "CANCELLED"
    assert api.post(f"/v1/transactions/{to_cancel['id']}/execute", headers=alice).status_code == 409


def test_batch_flow(api: httpx.Client, as_) -> None:
    alice = as_("alice")
    item = {"debit_account_id": ACCOUNTS["alice"], "credit_account_number": "RA-2000-0001",
            "amount": {"value": "0.50", "currency": "EUR"}}
    response = api.post(
        "/v1/transactions/batch",
        json={"items": [
            {**item, "idempotency_key": new_key("batch")},
            {**item, "idempotency_key": new_key("batch"), "credit_account_number": "RA-1000-0004"},
            {**item, "idempotency_key": new_key("batch"), "amount": {"value": "0.25", "currency": "EUR"}},
        ]},
        headers=alice,
    )
    assert response.status_code == 207, response.text
    results = response.json()["results"]
    assert [result["status"] for result in results] == [201, 422, 201]
    assert results[1]["error"]["code"] == "CURRENCY_MISMATCH"
    assert results[0]["transaction"]["status"] == "EXECUTED"


def test_listing_and_pagination(api: httpx.Client, as_) -> None:
    alice = as_("alice")
    first = api.get("/v1/transactions", params={"limit": 2}, headers=alice).json()
    assert len(first["items"]) == 2 and first["next_cursor"]
    second = api.get("/v1/transactions", params={"limit": 2, "cursor": first["next_cursor"]}, headers=alice).json()
    assert {item["id"] for item in first["items"]}.isdisjoint({item["id"] for item in second["items"]})
    executed = api.get("/v1/transactions", params={"status": "EXECUTED", "limit": 5}, headers=alice).json()["items"]
    assert executed and all(item["status"] == "EXECUTED" for item in executed)
    assert api.get("/v1/transactions", params={"cursor": "garbage!"}, headers=alice).status_code == 400


# ================================================================ trafic synthétique
def test_synthetic_round_trip(api: httpx.Client, as_) -> None:
    probe = as_("svc-synthetic")
    before = balance(api, probe, "syn-a")
    forward = pay(api, probe, "syn-a", "syn-b", "0.01", key=new_key("stm"))
    assert forward.status_code == 201 and forward.json()["status"] == "EXECUTED" and forward.json()["is_synthetic"]
    assert pay(api, probe, "syn-a", "alice", "0.01").json()["code"] == "SYNTHETIC_SEGREGATION"
    assert pay(api, probe, "syn-b", "syn-a", "0.01").json()["status"] == "EXECUTED"
    assert balance(api, probe, "syn-a") == before
    listed = api.get("/v1/transactions", params={"limit": 5}, headers=probe).json()["items"]
    assert listed and all(item["is_synthetic"] for item in listed)


# ============================================================ administration / RBAC
def test_admin_is_reserved_to_remediation(api: httpx.Client, as_) -> None:
    for principal in ("alice", "admin", "svc-synthetic"):
        assert api.get("/admin/v1/runtime-flags", headers=as_(principal)).status_code == 403
    flags = api.get("/admin/v1/runtime-flags", headers=as_("svc-remediation")).json()["items"]
    assert {flag["key"] for flag in flags} == {
        "write_mode", "max_transaction_amount_minor", "max_requests_per_minute_per_principal",
    }
    invalid = api.put(
        "/admin/v1/runtime-flags/write_mode",
        json={"value": "OPEN_BAR", "reason": "e2e invalid value"},
        headers=as_("svc-remediation"),
    )
    assert invalid.status_code == 422


def test_synthetic_quarantine_mode(api: httpx.Client, as_) -> None:
    remediation = as_("svc-remediation")

    def set_mode(mode: str) -> httpx.Response:
        return api.put(
            "/admin/v1/runtime-flags/write_mode",
            json={"value": mode, "reason": "e2e quarantine test", "incident_id": "c7d1b3f4-8a7e-4f3a-9a8e-2d1b0c9e8f7a"},
            headers=remediation,
        )

    try:
        changed = set_mode("SYNTHETIC_ONLY")
        assert changed.status_code == 200 and changed.json()["previous_value"] == "READ_WRITE"
        blocked = pay(api, as_("alice"), "alice", "bob", "1.00")
        assert blocked.status_code == 503 and blocked.json()["code"] == "WRITE_MODE_RESTRICTED"
        assert blocked.headers["retry-after"]
        assert pay(api, as_("svc-synthetic"), "syn-a", "syn-b", "0.01").json()["status"] == "EXECUTED"
        assert pay(api, as_("svc-synthetic"), "syn-b", "syn-a", "0.01").json()["status"] == "EXECUTED"
        readiness = api.get("/health/readiness")
        assert readiness.status_code == 200 and readiness.json()["status"] == "warn"
        assert set_mode("READ_ONLY").status_code == 200
        assert pay(api, as_("svc-synthetic"), "syn-a", "syn-b", "0.01").status_code == 503
    finally:
        assert set_mode("READ_WRITE").status_code == 200
    assert pay(api, as_("alice"), "alice", "alice-savings", "1.00").json()["status"] == "EXECUTED"
    assert pay(api, as_("alice"), "alice-savings", "alice", "1.00").json()["status"] == "EXECUTED"


def test_freeze_unfreeze_and_purge(api: httpx.Client, as_) -> None:
    remediation, alice = as_("svc-remediation"), as_("alice")
    reason = {"reason": "e2e FRAUD_PATTERN containment"}
    try:
        frozen = api.post(f"/admin/v1/accounts/{ACCOUNTS['merchant']}/freeze", json=reason, headers=remediation)
        assert frozen.status_code == 200 and frozen.json()["status"] == "FROZEN"
        refused = pay(api, alice, "alice", "merchant", "1.00").json()
        assert refused["status"] == "REJECTED" and refused["failure"]["code"] == "ACCOUNT_NOT_ACTIVE"
    finally:
        unfrozen = api.post(f"/admin/v1/accounts/{ACCOUNTS['merchant']}/unfreeze", json=reason, headers=remediation)
        assert unfrozen.json()["status"] == "ACTIVE"
    assert api.post(f"/admin/v1/accounts/{ACCOUNTS['syn-a']}/freeze", json=reason, headers=remediation).status_code == 409

    purge = api.post(
        "/admin/v1/maintenance/purge-stale",
        json={"older_than_seconds": 3600, "reason": "e2e purge of stale in-flight transactions"},
        headers=remediation,
    )
    assert purge.status_code == 200 and purge.json()["purged"] >= 0
    too_short = api.post(
        "/admin/v1/maintenance/purge-stale",
        json={"older_than_seconds": 10, "reason": "e2e purge"},
        headers=remediation,
    )
    assert too_short.status_code == 422


def test_dynamic_rate_limit(api: httpx.Client, as_) -> None:
    remediation, merchant = as_("svc-remediation"), as_("merchant")

    def set_limit(value: int) -> None:
        response = api.put(
            "/admin/v1/runtime-flags/max_requests_per_minute_per_principal",
            json={"value": value, "reason": "e2e throttling test"},
            headers=remediation,
        )
        assert response.status_code == 200, response.text

    try:
        set_limit(3)
        # La fenêtre glissante peut déjà contenir des requêtes récentes de ce principal.
        statuses = [api.get("/v1/accounts", headers=merchant).status_code for _ in range(5)]
        assert 429 in statuses and set(statuses) <= {200, 429}
        limited = api.get("/v1/accounts", headers=merchant)
        assert limited.status_code == 429 and int(limited.headers["retry-after"]) >= 1
        # Les sondes synthétiques ne sont jamais bridées.
        assert all(api.get("/v1/accounts", headers=as_("svc-synthetic")).status_code == 200 for _ in range(5))
    finally:
        set_limit(600)


# ========================================================= révocation et temps réel
def test_revoked_token_is_rejected_within_seconds(api: httpx.Client, auth: httpx.Client, as_) -> None:
    token = as_.fresh_user("alice")
    headers = {"Authorization": f"Bearer {token}"}
    assert api.get("/v1/accounts", headers=headers).status_code == 200
    assert auth.post("/v1/auth/logout", headers=headers).status_code == 204
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if api.get("/v1/accounts", headers=headers).status_code == 401:
            return
        time.sleep(0.5)
    pytest.fail("revocation was not propagated to payment-api within 10 s")


async def test_server_sent_events(api: httpx.Client, as_) -> None:
    alice = as_("alice")
    ticket = api.post("/v1/stream-tickets", headers=alice).json()["ticket"]
    events: list[dict] = []

    async with httpx.AsyncClient(base_url=PAYMENT_URL, timeout=httpx.Timeout(20.0)) as client:
        async with client.stream("GET", "/v1/transactions/events", params={"ticket": ticket}) as stream:
            assert stream.status_code == 200
            assert stream.headers["content-type"].startswith("text/event-stream")
            created = await asyncio.to_thread(pay, api, alice, "alice", "alice-savings", "0.42")
            transaction_id = created.json()["id"]

            async def collect() -> None:
                async for line in stream.aiter_lines():
                    if line.startswith("data: "):
                        event = json.loads(line[6:])
                        if event["payload"].get("id") == transaction_id:
                            events.append(event)
                            if event["payload"]["status"] == "EXECUTED":
                                return

            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(collect(), timeout=10)

    assert [event["type"] for event in events] == ["transaction.created", "transaction.updated"]
    assert events[-1]["payload"]["amount"]["value"] == "0.42" and events[-1]["seq"] > events[0]["seq"]
    assert api.get("/v1/transactions/events", params={"ticket": ticket}).status_code == 401, "tickets are single-use"
    assert pay(api, alice, "alice-savings", "alice", "0.42").json()["status"] == "EXECUTED"


# ======================================================== laboratoire : attaque & reprise
def _lab(api: httpx.Client, as_, body: dict) -> httpx.Response:
    return api.post("/lab/v1/faults", json=body, headers=as_("admin"))


@pytest.fixture
def lab_enabled(api: httpx.Client, as_) -> None:
    if api.get("/lab/v1/faults", headers=as_("admin")).status_code == 404:
        pytest.skip("chaos lab disabled (CHAOS_LAB_ENABLED=false)")


def test_lab_requires_chaos_role(api: httpx.Client, as_, lab_enabled) -> None:
    assert api.get("/lab/v1/faults", headers=as_("alice")).status_code == 403


def test_balance_tamper_is_detected_contained_and_repaired(api: httpx.Client, as_, lab_enabled) -> None:
    remediation, alice, bob = as_("svc-remediation"), as_("alice"), as_("bob")
    incident = "c7d1b3f4-8a7e-4f3a-9a8e-2d1b0c9e8f7a"
    bob_before = balance(api, bob, "bob")

    tampered = _lab(api, as_, {"type": "BALANCE_TAMPER", "params": {"account_number": NUMBERS["bob"], "delta": "500.00"}})
    assert tampered.status_code == 201, tampered.text
    assert balance(api, bob, "bob") == bob_before + 50000

    diagnosis = api.get("/health/integrity", params={"refresh": "true"}, headers=remediation)
    assert diagnosis.status_code == 503
    failing = {name for name, results in diagnosis.json()["checks"].items() if results[0]["status"] == "fail"}
    assert failing == {"data:BALANCE_MATCHES_LEDGER", "data:MONEY_CONSERVATION"}

    blocked = pay(api, alice, "alice", "bob", "1.00").json()
    assert blocked["status"] == "FAILED" and blocked["failure"]["code"] == "LEDGER_INTEGRITY_FAULT"
    metric = next(
        line for line in api.get("/metrics").text.splitlines() if line.startswith("ra_ledger_divergence_total ")
    )
    assert float(metric.split()[1]) >= 1, "the divergence must be visible to the detection engine"

    simulation = api.post(
        "/admin/v1/integrity/repair",
        json={"reason": "e2e PB-INTEGRITY-RESTORE dry run", "incident_id": incident, "dry_run": True},
        headers=remediation,
    ).json()
    assert simulation["dry_run"] and simulation["integrity_after"] is None
    assert {
        "account_id": ACCOUNTS["bob"], "field": "available_minor",
        "previous": str(bob_before + 50000), "corrected": str(bob_before),
    } in simulation["repaired"]

    repaired = api.post(
        "/admin/v1/integrity/repair",
        json={"reason": "e2e PB-INTEGRITY-RESTORE step 4", "incident_id": incident},
        headers=remediation,
    )
    assert repaired.status_code == 200, repaired.text
    assert repaired.json()["integrity_after"]["status"] == "pass"
    assert balance(api, bob, "bob") == bob_before

    report = api.post("/admin/v1/integrity/reports", json={"incident_id": incident}, headers=remediation)
    assert report.status_code == 201 and report.json()["status"] == "pass"
    assert pay(api, alice, "alice", "bob", "1.00").json()["status"] == "EXECUTED"
    assert pay(api, bob, "bob", "alice", "1.00").json()["status"] == "EXECUTED"


def test_latency_and_readiness_faults(api: httpx.Client, as_, lab_enabled) -> None:
    try:
        assert _lab(api, as_, {"type": "LATENCY", "params": {"ms": 400}, "duration_seconds": 30}).status_code == 201
        started = time.monotonic()
        assert api.get("/v1/accounts", headers=as_("alice")).status_code == 200
        assert time.monotonic() - started >= 0.4
        assert api.get("/health/liveness").status_code == 200, "probes are never slowed down"

        assert _lab(api, as_, {"type": "READINESS_FAILURE"}).status_code == 201
        assert api.get("/health/readiness").status_code == 503
        assert {fault["type"] for fault in api.get("/lab/v1/faults", headers=as_("admin")).json()["items"]} == {
            "LATENCY", "READINESS_FAILURE",
        }
    finally:
        assert api.delete("/lab/v1/faults", headers=as_("admin")).json()["cleared"] >= 0
    assert api.get("/health/readiness").status_code == 200


def test_pool_exhaustion_degrades_gracefully(api: httpx.Client, as_, lab_enabled) -> None:
    alice = as_("alice")
    try:
        assert _lab(api, as_, {"type": "POOL_EXHAUSTION", "duration_seconds": 60}).status_code == 201
        time.sleep(0.5)
        degraded = api.get("/v1/accounts", headers=alice)
        assert degraded.status_code == 503 and degraded.json()["code"] == "DEPENDENCY_UNAVAILABLE"
        assert api.get("/health/readiness").status_code == 503
        assert api.get("/health/liveness").status_code == 200
    finally:
        api.delete("/lab/v1/faults", headers=as_("admin"))
    assert api.get("/v1/accounts", headers=alice).status_code == 200


def test_zz_crash_is_recovered_by_restart_policy(api: httpx.Client, as_, lab_enabled) -> None:
    assert _lab(api, as_, {"type": "CRASH"}).status_code == 201
    time.sleep(1.5)
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        with contextlib.suppress(httpx.HTTPError):
            if api.get("/health/readiness").status_code == 200:
                break
        time.sleep(1)
    else:
        pytest.fail("payment-api did not come back after the injected crash")
    assert api.get("/lab/v1/faults", headers=as_("admin")).json()["items"] == [], "in-memory faults vanish on restart"
    assert pay(api, as_("alice"), "alice", "alice-savings", "1.00").json()["status"] == "EXECUTED"
    assert pay(api, as_("alice"), "alice-savings", "alice", "1.00").json()["status"] == "EXECUTED"
