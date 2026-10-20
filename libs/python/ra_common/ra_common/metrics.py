"""Métriques Prometheus communes à tous les services."""

from __future__ import annotations

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from starlette.responses import Response

HTTP_REQUESTS = Counter(
    "ra_http_requests_total",
    "Requêtes HTTP traitées",
    ["method", "route", "status"],
)
HTTP_DURATION = Histogram(
    "ra_http_request_duration_seconds",
    "Durée de traitement des requêtes HTTP",
    ["method", "route"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
)
AUTH_REJECTIONS = Counter(
    "ra_auth_rejections_total",
    "Requêtes rejetées à l'authentification ou à l'autorisation",
    ["reason"],
)


def observe_http(method: str, route: str, status: int, duration_seconds: float) -> None:
    HTTP_REQUESTS.labels(method=method, route=route, status=str(status)).inc()
    HTTP_DURATION.labels(method=method, route=route).observe(duration_seconds)


def metrics_response() -> Response:
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
