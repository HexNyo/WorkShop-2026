"""Bus d'événements de supervision (diffusés en SSE vers la console NOC/SOC)."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from ra_common.sse import EventBroadcaster


class SupervisionEvents:
    def __init__(self, broadcaster: EventBroadcaster) -> None:
        self.broadcaster = broadcaster

    def publish(self, event_type: str, payload: dict[str, Any], incident_id: UUID | str | None = None) -> None:
        self.broadcaster.publish(event_type, payload, incident_id=str(incident_id) if incident_id else None)

    @property
    def last_seq(self) -> int:
        return self.broadcaster.last_seq
