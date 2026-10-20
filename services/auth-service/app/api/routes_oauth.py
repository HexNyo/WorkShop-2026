"""Endpoint OAuth2 token (client_credentials) et publication JWKS."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from starlette.responses import JSONResponse

from app.api.deps import client_ip, get_container, read_urlencoded_form
from app.api.errors import NO_STORE
from app.api.schemas import OAuthTokenResponse
from app.container import Container
from app.domain.errors import OAuthError

router = APIRouter(tags=["oauth"])

_AUDIENCE_MAX = 64


@router.post("/v1/oauth/token", response_model=OAuthTokenResponse, summary="Jeton de service (client_credentials)")
async def token(request: Request, container: Container = Depends(get_container)) -> JSONResponse:
    form = await read_urlencoded_form(request)
    if form.get("grant_type") != "client_credentials":
        raise OAuthError("unsupported_grant_type", "only client_credentials is supported")
    client_id, client_secret = form.get("client_id", ""), form.get("client_secret", "")
    if not client_id or not client_secret or len(client_id) > 64 or len(client_secret) > 256:
        raise OAuthError("invalid_client", "client_id and client_secret are required", status=401)
    audience = form.get("audience") or None
    if audience is not None and len(audience) > _AUDIENCE_MAX:
        raise OAuthError("invalid_target", "audience is too long")

    issued = await container.client_credentials.issue(
        client_id=client_id, client_secret=client_secret, audience=audience, client_ip=client_ip(request)
    )
    body = OAuthTokenResponse(access_token=issued.token, expires_in=issued.expires_in, scope=" ".join(issued.roles))
    return JSONResponse(body.model_dump(), headers=NO_STORE)


@router.get("/.well-known/jwks.json", summary="Clés publiques de signature (JWKS)")
async def jwks(container: Container = Depends(get_container)) -> JSONResponse:
    return JSONResponse(container.keys.jwks(), headers={"Cache-Control": "public, max-age=600"})
