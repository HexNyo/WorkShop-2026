"""Révocation (RFC 7009) et introspection (RFC 7662) des jetons d'accès."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response, status
from starlette.responses import JSONResponse

from app.api.deps import get_container, read_urlencoded_form
from app.api.errors import NO_STORE
from app.api.schemas import IntrospectionResponse, RevokeRequest
from app.container import Container
from app.domain.policies import ROLE_SVC_RESOURCE_SERVER
from ra_common.security import AccessTokenClaims, TokenError, authenticate, require_roles

router = APIRouter(prefix="/v1/tokens", tags=["tokens"])


@router.post("/revoke", status_code=status.HTTP_204_NO_CONTENT, summary="Révoquer un jeton d'accès")
async def revoke(
    body: RevokeRequest | None = None,
    container: Container = Depends(get_container),
    claims: AccessTokenClaims = Depends(authenticate),
) -> Response:
    request_body = body or RevokeRequest()
    await container.principals.revoke_token(claims, request_body.jti, request_body.reason)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/introspect", response_model=IntrospectionResponse, summary="Introspection d'un jeton (resource servers)")
async def introspect(
    request: Request,
    container: Container = Depends(get_container),
    _: AccessTokenClaims = Depends(require_roles(ROLE_SVC_RESOURCE_SERVER)),
) -> JSONResponse:
    form = await read_urlencoded_form(request)
    token = form.get("token", "")
    inactive = JSONResponse(IntrospectionResponse(active=False).model_dump(exclude_none=True), headers=NO_STORE)
    if not token or len(token) > 8192:
        return inactive
    try:
        claims = await container.introspection_verifier.verify(token)
    except TokenError:
        return inactive
    body = IntrospectionResponse(
        active=True,
        sub=claims.sub,
        aud=list(claims.aud),
        roles=list(claims.roles),
        exp=claims.exp,
        iat=claims.iat,
        jti=claims.jti,
        pkind=claims.pkind,
    )
    return JSONResponse(body.model_dump(exclude_none=True), headers=NO_STORE)
