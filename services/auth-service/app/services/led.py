"""Pilotage de la LED bicolore de l'ESP8266 (best effort : jamais bloquant, jamais fatal)."""

from __future__ import annotations

import asyncio
import logging
from typing import Literal

import httpx

from ra_common.logging import log_event

logger = logging.getLogger("auth.led")

LedState = Literal["OFF", "GREEN_BLINK", "GREEN_SOLID_30S", "RED_SOLID_30S", "RED_BLINK_10"]


class LedController:
    def __init__(self, base_url: str) -> None:
        self._url = f"{base_url.rstrip('/')}/api/led" if base_url else None
        self._client = httpx.AsyncClient(timeout=1.5)
        self._tasks: set[asyncio.Task[None]] = set()

    def send(self, state: LedState) -> None:
        """Envoi en tâche de fond : la réponse au login n'attend jamais la LED."""
        if self._url is None:
            return
        task = asyncio.create_task(self._post(state))
        self._tasks.add(task)  # référence forte, sinon la tâche peut être collectée en vol
        task.add_done_callback(self._tasks.discard)

    async def _post(self, state: LedState) -> None:
        try:
            (await self._client.post(self._url, json={"state": state})).raise_for_status()
        except httpx.HTTPError as exc:
            log_event(logger, logging.WARNING, "led.unreachable", "ESP8266 LED unreachable", state=state, error=type(exc).__name__)

    async def close(self) -> None:
        await self._client.aclose()
