"""Endpoints internes (jamais routés par la passerelle publique)."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response, status

from app.api.deps import get_container
from app.api.schemas import (
    ContainmentRequest,
    ContainmentResponse,
    EnableRequest,
    PrincipalAdminView,
    RevocationFeedResponse,
    RevocationItem,
)
from app.container import Container
from app.domain.models import ContainmentResult
from app.domain.policies import ROLE_AUTH_ADMIN, ROLE_SVC_REMEDIATION, ROLE_SVC_RESOURCE_SERVER
from ra_common.metrics import AUTH_REJECTIONS
from ra_common.problem import forbidden
from ra_common.security import AccessTokenClaims, authenticate, require_roles

router = APIRouter(prefix="/internal/v1", tags=["internal"])

ROLE_PATTERN = r"^[a-z]+(\.[a-z_]+)+$"


@router.get("/revocations", response_model=RevocationFeedResponse, summary="Flux de révocation incrémental")
async def revocations(
    since: int = Query(0, ge=0),
    limit: int = Query(500, ge=1, le=1000),
    container: Container = Depends(get_container),
    _: AccessTokenClaims = Depends(require_roles(ROLE_SVC_RESOURCE_SERVER)),
) -> RevocationFeedResponse:
    cursor, items = await container.principals.revocation_feed(since=since, limit=limit)
    return RevocationFeedResponse(
        cursor=cursor,
        items=[
            RevocationItem(
                seq=item.seq,
                kind=item.kind,
                jti=item.jti,
                principal_id=item.principal_id,
                not_before=item.not_before,
                expires_at=item.expires_at,
            )
            for item in items
        ],
    )


@router.get(
    "/authz/check",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Sous-requête d'autorisation de la passerelle (nginx auth_request)",
)
async def authz_check(
    role: str = Query(pattern=ROLE_PATTERN, max_length=64),
    claims: AccessTokenClaims = Depends(authenticate),
) -> Response:
    if role not in claims.roles:
        AUTH_REJECTIONS.labels(reason="forbidden").inc()
        raise forbidden()
    return Response(
        status_code=status.HTTP_204_NO_CONTENT,
        headers={"X-Auth-Sub": claims.sub, "X-Auth-Roles": ",".join(claims.roles), "Cache-Control": "no-store"},
    )


def _containment_view(result: ContainmentResult) -> ContainmentResponse:
    return ContainmentResponse(
        principal_id=result.principal_id,
        is_active=result.is_active,
        tokens_valid_after=result.tokens_valid_after,
        refresh_tokens_revoked=result.refresh_tokens_revoked,
    )


@router.post("/principals/{principal_id}/revoke-tokens", response_model=ContainmentResponse)
async def revoke_principal_tokens(
    principal_id: UUID,
    body: ContainmentRequest,
    container: Container = Depends(get_container),
    claims: AccessTokenClaims = Depends(require_roles(ROLE_SVC_REMEDIATION, ROLE_AUTH_ADMIN)),
) -> ContainmentResponse:
    result = await container.principals.contain(
        claims, principal_id, disable=False, reason=body.reason, incident_id=body.incident_id
    )
    return _containment_view(result)


@router.post("/principals/{principal_id}/disable", response_model=ContainmentResponse)
async def disable_principal(
    principal_id: UUID,
    body: ContainmentRequest,
    container: Container = Depends(get_container),
    claims: AccessTokenClaims = Depends(require_roles(ROLE_SVC_REMEDIATION, ROLE_AUTH_ADMIN)),
) -> ContainmentResponse:
    result = await container.principals.contain(
        claims, principal_id, disable=True, reason=body.reason, incident_id=body.incident_id
    )
    return _containment_view(result)


@router.post("/principals/{principal_id}/enable", response_model=PrincipalAdminView)
async def enable_principal(
    principal_id: UUID,
    body: EnableRequest,
    container: Container = Depends(get_container),
    claims: AccessTokenClaims = Depends(require_roles(ROLE_AUTH_ADMIN)),
) -> PrincipalAdminView:
    # La réactivation est une décision humaine : un jeton de service ne peut jamais porter auth.admin.
    principal = await container.principals.enable(claims, principal_id, reason=body.reason)
    return PrincipalAdminView.of(principal)
