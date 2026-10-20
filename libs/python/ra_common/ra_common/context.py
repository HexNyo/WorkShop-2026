"""Contexte de requête propagé dans les logs (request_id, trace, corrélation, principal)."""

from __future__ import annotations

from contextvars import ContextVar

request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)
trace_id_var: ContextVar[str | None] = ContextVar("trace_id", default=None)
span_id_var: ContextVar[str | None] = ContextVar("span_id", default=None)
correlation_id_var: ContextVar[str | None] = ContextVar("correlation_id", default=None)
principal_id_var: ContextVar[str | None] = ContextVar("principal_id", default=None)


def current_context() -> dict[str, str]:
    """Champs de contexte non vides, prêts à être fusionnés dans une ligne de log."""
    values = {
        "request_id": request_id_var.get(),
        "trace_id": trace_id_var.get(),
        "span_id": span_id_var.get(),
        "correlation_id": correlation_id_var.get(),
        "principal_id": principal_id_var.get(),
    }
    return {key: value for key, value in values.items() if value}


def outgoing_headers() -> dict[str, str]:
    """En-têtes à propager vers un service aval (traçabilité de bout en bout)."""
    headers: dict[str, str] = {}
    if request_id := request_id_var.get():
        headers["X-Request-ID"] = request_id
    if correlation_id := correlation_id_var.get():
        headers["X-Correlation-ID"] = correlation_id
    trace_id, span_id = trace_id_var.get(), span_id_var.get()
    if trace_id and span_id:
        headers["traceparent"] = f"00-{trace_id}-{span_id}-01"
    return headers
