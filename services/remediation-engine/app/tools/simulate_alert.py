"""Simulateur de détecteur : émet une alerte conforme au contrat alert-webhook 1.0.

Remplace le moteur ML/SIEM (autre lot) pour les démonstrations et les tests. Il
s'authentifie comme `svc-detector` (client_credentials) et signe le corps en HMAC.

    docker compose --profile tools run --rm detector-simulator \
        --category DATA_INTEGRITY_VIOLATION --severity CRITICAL --service payment-api \
        --title "Balance/ledger divergence detected"
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from datetime import UTC, datetime

import httpx

from app.domain.security import sign

CATEGORIES = (
    "SERVICE_UNAVAILABLE",
    "PERFORMANCE_DEGRADATION",
    "RESOURCE_EXHAUSTION",
    "DATA_INTEGRITY_VIOLATION",
    "CREDENTIAL_COMPROMISE",
    "ANOMALOUS_TRAFFIC",
    "FRAUD_PATTERN",
)


def _required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        sys.exit(f"{name} must be set")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="simulate-alert")
    parser.add_argument("--category", choices=CATEGORIES, required=True)
    parser.add_argument("--severity", choices=("INFO", "WARNING", "HIGH", "CRITICAL"), default="CRITICAL")
    parser.add_argument("--service", default="payment-api")
    parser.add_argument("--principal-id")
    parser.add_argument("--account-id")
    parser.add_argument("--confidence", type=float, default=0.95)
    parser.add_argument("--title")
    parser.add_argument("--external-id")
    args = parser.parse_args(argv)

    auth_url = os.environ.get("SIMULATOR_AUTH_URL", "http://auth-service:8000")
    engine_url = os.environ.get("SIMULATOR_ENGINE_URL", "http://remediation-engine:8001")
    token = httpx.post(
        f"{auth_url}/v1/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": os.environ.get("SIMULATOR_CLIENT_ID", "svc-detector"),
            "client_secret": _required("SIMULATOR_CLIENT_SECRET"),
            "audience": "remediation-control",
        },
        timeout=10,
    )
    token.raise_for_status()

    alert = {
        "schema_version": "1.0",
        "source": "detector-simulator",
        "external_id": args.external_id or f"sim-{uuid.uuid4().hex[:16]}",
        "detected_at": datetime.now(UTC).isoformat(),
        "category": args.category,
        "severity": args.severity,
        "confidence": args.confidence,
        "title": args.title or f"Simulated {args.category.lower().replace('_', ' ')} on {args.service}",
        "target": {"service": args.service, "principal_id": args.principal_id, "account_id": args.account_id},
        "evidence": {"simulated": True},
        "labels": {"env": "demo"},
    }
    body = json.dumps(alert, separators=(",", ":")).encode()
    response = httpx.post(
        f"{engine_url}/v1/alerts",
        content=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token.json()['access_token']}",
            "X-RA-Signature": sign(_required("SIMULATOR_HMAC_SECRET").encode(), body, int(time.time())),
        },
        timeout=10,
    )
    print(json.dumps({"status": response.status_code, **response.json()}, indent=2))
    return 0 if response.is_success else 1


if __name__ == "__main__":
    sys.exit(main())
