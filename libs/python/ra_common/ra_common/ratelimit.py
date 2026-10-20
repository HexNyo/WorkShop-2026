"""Limiteur à fenêtre glissante, par clé (principal, source…) et par instance."""

from __future__ import annotations

import math
import time
from collections import deque


class SlidingWindowLimiter:
    def __init__(self, window_seconds: float = 60.0, max_tracked_keys: int = 50_000) -> None:
        self._window = window_seconds
        self._max_keys = max_tracked_keys
        self._hits: dict[str, deque[float]] = {}

    def check(self, key: str, limit: int, now: float | None = None) -> float | None:
        """Enregistre une requête ; renvoie None si autorisée, sinon le délai d'attente (s)."""
        now = time.monotonic() if now is None else now
        hits = self._hits.get(key)
        if hits is None:
            if len(self._hits) >= self._max_keys:
                self._evict(now)
            hits = self._hits[key] = deque()
        horizon = now - self._window
        while hits and hits[0] <= horizon:
            hits.popleft()
        if len(hits) >= limit:
            return max(hits[0] + self._window - now, 0.001)
        hits.append(now)
        return None

    def _evict(self, now: float) -> None:
        horizon = now - self._window
        for key in [key for key, hits in self._hits.items() if not hits or hits[-1] <= horizon]:
            del self._hits[key]

    @staticmethod
    def retry_after(delay: float) -> int:
        return max(math.ceil(delay), 1)
