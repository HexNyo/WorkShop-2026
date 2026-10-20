"""Point d'entrée : un processus, deux listeners HTTP liés chacun à l'adresse d'un seul réseau.

    CONTROL     (REMEDIATION_CONTROL_BIND_HOST:8001)      webhook + pilotage, réseau `control`
    SUPERVISION (REMEDIATION_SUPERVISION_BIND_HOST:8002)  lecture seule + SSE, réseau `app`
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
from collections.abc import Iterator

import uvicorn
from ra_common.logging import configure_logging, log_event

from app.apps import create_control_app, create_supervision_app
from app.container import Container
from app.core.config import Settings

logger = logging.getLogger("remediation.main")


class _Server(uvicorn.Server):
    """Les signaux sont gérés une seule fois pour les deux serveurs (cf. _serve)."""

    @contextlib.contextmanager
    def capture_signals(self) -> Iterator[None]:
        yield


def _server(app, host: str, port: int) -> _Server:
    return _Server(
        uvicorn.Config(
            app,
            host=host,
            port=port,
            lifespan="off",
            log_config=None,
            access_log=False,
            server_header=False,
            proxy_headers=True,
            timeout_graceful_shutdown=20,
        )
    )


async def _serve(settings: Settings) -> None:
    container = Container.build(settings)
    servers = [
        _server(create_control_app(container), settings.control_bind_host, settings.control_port),
        _server(create_supervision_app(container), settings.supervision_bind_host, settings.supervision_port),
    ]
    loop = asyncio.get_running_loop()

    def shutdown() -> None:
        for server in servers:
            server.should_exit = True

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, shutdown)

    await container.start()
    log_event(
        logger,
        logging.INFO,
        "service.started",
        "remediation-engine started",
        control=f"{settings.control_bind_host}:{settings.control_port}",
        supervision=f"{settings.supervision_bind_host}:{settings.supervision_port}",
        watchdog=settings.watchdog_enabled,
    )
    try:
        await asyncio.gather(*(server.serve() for server in servers))
    finally:
        await container.stop()
        log_event(logger, logging.INFO, "service.stopped", "remediation-engine stopped")


def main() -> None:
    settings = Settings()
    configure_logging(settings.service_name, settings.version, settings.log_level)
    asyncio.run(_serve(settings))


if __name__ == "__main__":
    main()
