"""Redémarrage de conteneurs via le proxy Docker restreint.

Le moteur n'a jamais accès au socket Docker : le proxy (wollomatic/socket-proxy)
n'autorise que `GET /_ping`, `GET /containers/json` et
`POST /containers/<id>/restart`. En défense en profondeur, le moteur ne cible que
les conteneurs portant `resilience.remediable=true` ET figurant dans son allowlist.
"""

from __future__ import annotations

import json
import logging

import httpx
from ra_common.logging import log_event

from app.connectors.base import ActionError, StepContext, call, expect

logger = logging.getLogger("remediation.connectors.docker")


class DockerConnector:
    def __init__(self, http: httpx.AsyncClient, base_url: str, restartable: frozenset[str]) -> None:
        self._http = http
        self._base = base_url.rstrip("/")
        self._restartable = restartable

    async def ping(self) -> bool:
        try:
            response = await self._http.get(f"{self._base}/_ping", timeout=2.0)
        except httpx.HTTPError:
            return False
        return response.status_code == 200

    async def _container_id(self, service: str) -> str:
        filters = json.dumps({"label": [f"resilience.service={service}", "resilience.remediable=true"]})
        # all=true : un conteneur arrêté ou en boucle de redémarrage doit rester ciblable.
        response = await call(
            self._http, "GET", f"{self._base}/containers/json", params={"filters": filters, "all": "true"}
        )
        containers = expect(response, 200).get("body", [])
        if len(containers) != 1:
            raise ActionError(f"expected exactly one remediable container for {service}, found {len(containers)}")
        return containers[0]["Id"]

    async def restart(self, ctx: StepContext, service: str, stop_timeout_seconds: int) -> dict:
        if service not in self._restartable:
            raise ActionError(f"service {service} is not in the restart allowlist", fatal=True)
        container_id = await self._container_id(service)
        response = await call(
            self._http,
            "POST",
            f"{self._base}/containers/{container_id}/restart",
            params={"t": stop_timeout_seconds},
            timeout=stop_timeout_seconds + 20,
            attempts=1,
        )
        expect(response, 204)
        log_event(
            logger,
            logging.WARNING,
            "remediation.container_restarted",
            f"container restarted: {service}",
            service=service,
            container_id=container_id[:12],
            incident_id=str(ctx.incident.id),
        )
        return {"service": service, "container_id": container_id[:12]}
