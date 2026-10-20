"""ra-ctl — pilotage du moteur depuis le réseau control (ex. `docker compose exec`).

    docker compose exec remediation-engine ra-ctl --user admin incidents --status ESCALATED
    docker compose exec remediation-engine ra-ctl --user admin show <incident-id>
    docker compose exec remediation-engine ra-ctl --user admin retry <incident-id> --reason "ledger restored"
    docker compose exec remediation-engine ra-ctl --user admin verify <incident-id> --reason "fixed manually"
    docker compose exec remediation-engine ra-ctl --user admin playbooks
    docker compose exec remediation-engine ra-ctl --user admin playbook-disable PB-PERF-RECOVERY
    docker compose exec remediation-engine ra-ctl --user admin stm --reason "post-change check"

Le mot de passe est demandé de façon interactive (ou lu dans RA_CTL_PASSWORD). Le
jeton n'est jamais écrit sur disque.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys

import httpx


def _login(auth_url: str, username: str) -> str:
    password = os.environ.get("RA_CTL_PASSWORD") or getpass.getpass(f"password for {username}: ")
    response = httpx.post(f"{auth_url}/v1/auth/login", json={"username": username, "password": password}, timeout=10)
    if response.status_code != 200:
        sys.exit(f"login failed: {response.status_code} {response.json().get('code', '')}")
    return response.json()["access_token"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ra-ctl", description="RESILIENCE-ALPHA remediation control")
    parser.add_argument("--user", required=True, help="principal humain portant remediation.admin")
    parser.add_argument("--auth-url", default=os.environ.get("REMEDIATION_AUTH_BASE_URL", "http://auth-service:8000"))
    parser.add_argument(
        "--control-url",
        default=f"http://{os.environ.get('REMEDIATION_CONTROL_BIND_HOST', '127.0.0.1')}:"
        f"{os.environ.get('REMEDIATION_CONTROL_PORT', '8001')}",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    listing = commands.add_parser("incidents")
    listing.add_argument("--status")
    listing.add_argument("--limit", type=int, default=20)
    for name in ("show", "retry", "verify"):
        sub = commands.add_parser(name)
        sub.add_argument("incident_id")
        if name != "show":
            sub.add_argument("--reason", required=True)
    commands.add_parser("playbooks")
    for name in ("playbook-enable", "playbook-disable"):
        commands.add_parser(name).add_argument("code")
    commands.add_parser("stm").add_argument("--reason", required=True)
    args = parser.parse_args(argv)

    token = _login(args.auth_url, args.user)
    client = httpx.Client(base_url=args.control_url, headers={"Authorization": f"Bearer {token}"}, timeout=120)
    if args.command == "incidents":
        params = {"limit": args.limit, **({"status": args.status} if args.status else {})}
        response = client.get("/v1/incidents", params=params)
    elif args.command == "show":
        response = client.get(f"/v1/incidents/{args.incident_id}")
    elif args.command in ("retry", "verify"):
        response = client.post(f"/v1/incidents/{args.incident_id}/{args.command}", json={"reason": args.reason})
    elif args.command == "playbooks":
        response = client.get("/v1/playbooks")
    elif args.command in ("playbook-enable", "playbook-disable"):
        response = client.patch(f"/v1/playbooks/{args.code}", json={"enabled": args.command == "playbook-enable"})
    else:
        response = client.post("/v1/verifications", json={"reason": args.reason})
    print(json.dumps(response.json(), indent=2, ensure_ascii=False))
    return 0 if response.is_success else 1


if __name__ == "__main__":
    sys.exit(main())
