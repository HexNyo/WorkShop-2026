"""Authentification humaine : /v1/auth/* et /v1/me."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Request, Response, status

from app.api.cookies import clear_refresh_cookie, set_refresh_cookie
from app.api.deps import client_ip, get_container, user_agent
from app.api.errors import NO_STORE
from app.api.schemas import LoginRequest, MeResponse, PrincipalView, TokenResponse
from app.container import Container
from app.domain.errors import RefreshTokenInvalid
from app.domain.models import LoginResult
from ra_common.problem import forbidden
from ra_common.security import AccessTokenClaims, authenticate

router = APIRouter(prefix="/v1", tags=["auth"])


def _token_response(response: Response, container: Container, result: LoginResult) -> TokenResponse:
    set_refresh_cookie(response, container.settings, result.refresh_token, result.refresh_expires_at)
    response.headers.update(NO_STORE)
    return TokenResponse(
        access_token=result.access.token,
        expires_in=result.access.expires_in,
        principal=PrincipalView.of(result.principal),
    )


@router.post("/auth/login", response_model=TokenResponse, summary="Connexion par identifiant et mot de passe")
async def login(
    body: LoginRequest, request: Request, response: Response, container: Container = Depends(get_container)
) -> TokenResponse:
    result = await container.authentication.login(
        body.username, body.password.get_secret_value(), client_ip=client_ip(request), user_agent=user_agent(request)
    )
    return _token_response(response, container, result)


@router.post("/auth/refresh", response_model=TokenResponse, summary="Rotation du jeton de rafraîchissement")
async def refresh(request: Request, response: Response, container: Container = Depends(get_container)) -> TokenResponse:
    settings = container.settings
    # Défense CSRF complémentaire à SameSite=Strict : un formulaire tiers ne peut pas poser cet en-tête.
    if request.headers.get("x-requested-with") != settings.csrf_header_value:
        raise forbidden("Missing or invalid X-Requested-With header", code="CSRF_PROTECTION")
    token = request.cookies.get(settings.refresh_cookie_name)
    if not token or len(token) > 256:
        raise RefreshTokenInvalid()
    result = await container.authentication.refresh(token, client_ip=client_ip(request), user_agent=user_agent(request))
    return _token_response(response, container, result)


@router.post("/auth/logout", status_code=status.HTTP_204_NO_CONTENT, summary="Déconnexion (révocation de la session)")
async def logout(
    request: Request,
    container: Container = Depends(get_container),
    claims: AccessTokenClaims = Depends(authenticate),
) -> Response:
    await container.authentication.logout(
        claims, request.cookies.get(container.settings.refresh_cookie_name), client_ip=client_ip(request)
    )
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    clear_refresh_cookie(response, container.settings)
    return response


@router.get("/me", response_model=MeResponse, summary="Principal courant")
async def me(
    container: Container = Depends(get_container), claims: AccessTokenClaims = Depends(authenticate)
) -> MeResponse:
    principal = await container.authentication.me(claims)
    return MeResponse(
        **PrincipalView.of(principal).model_dump(),
        token_expires_at=datetime.fromtimestamp(claims.exp, UTC),
    )
