"""Dépendances communes aux routes."""

from __future__ import annotations

from urllib.parse import parse_qsl

from fastapi import Request

from app.container import Container
from app.domain.errors import OAuthError

MAX_FORM_BYTES = 4096


def get_container(request: Request) -> Container:
    return request.app.state.container


def client_ip(request: Request) -> str | None:
    # uvicorn --proxy-headers renseigne request.client à partir de X-Forwarded-For
    # lorsque la passerelle figure dans FORWARDED_ALLOW_IPS.
    return request.client.host if request.client else None


def user_agent(request: Request) -> str | None:
    return request.headers.get("user-agent")


async def read_urlencoded_form(request: Request) -> dict[str, str]:
    """Analyse stricte d'un formulaire application/x-www-form-urlencoded (RFC 6749 § 3.2)."""
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/x-www-form-urlencoded":
        raise OAuthError("invalid_request", "content type must be application/x-www-form-urlencoded")
    body = await request.body()
    if len(body) > MAX_FORM_BYTES:
        raise OAuthError("invalid_request", "request body too large")
    try:
        pairs = parse_qsl(body.decode("utf-8"), keep_blank_values=True, strict_parsing=bool(body))
    except (UnicodeDecodeError, ValueError) as exc:
        raise OAuthError("invalid_request", "malformed form body") from exc
    form: dict[str, str] = {}
    for key, value in pairs:
        if key in form:
            raise OAuthError("invalid_request", f"parameter '{key}' must not be repeated")
        form[key] = value
    return form
