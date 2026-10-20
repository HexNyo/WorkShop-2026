"""Limiteur à fenêtre glissante (implémentation partagée dans ra_common)."""

from ra_common.ratelimit import SlidingWindowLimiter

__all__ = ["SlidingWindowLimiter"]
