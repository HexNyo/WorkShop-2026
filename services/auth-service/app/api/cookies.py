"""Cookie de rafraîchissement : HttpOnly, SameSite=Strict, limité au chemin d'authentification."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import Response

from app.core.config import Settings


def set_refresh_cookie(response: Response, settings: Settings, token: str, expires_at: datetime) -> None:
    max_age = max(int((expires_at - datetime.now(UTC)).total_seconds()), 0)
    response.set_cookie(
        key=settings.refresh_cookie_name,
        value=token,
        max_age=max_age,
        path=settings.refresh_cookie_path,
        secure=settings.cookie_secure,
        httponly=True,
        samesite="strict",
    )


def clear_refresh_cookie(response: Response, settings: Settings) -> None:
    response.delete_cookie(
        key=settings.refresh_cookie_name,
        path=settings.refresh_cookie_path,
        secure=settings.cookie_secure,
        httponly=True,
        samesite="strict",
    )


def clear_refresh_cookie_header(settings: Settings) -> str:
    """Valeur Set-Cookie d'effacement, utilisée dans les réponses d'erreur."""
    secure = "; Secure" if settings.cookie_secure else ""
    return (
        f"{settings.refresh_cookie_name}=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; "
        f"Path={settings.refresh_cookie_path}; HttpOnly; SameSite=strict{secure}"
    )
