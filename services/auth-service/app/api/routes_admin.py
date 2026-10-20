"""Administration des principaux (auth.admin)."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Path, Query
from fastapi.encoders import jsonable_encoder
from starlette.responses import JSONResponse

from app.api.deps import get_container
from app.api.schemas import ContainmentRequest, FaceImage, PrincipalAdminView, PrincipalPage
from app.container import Container
from app.domain.policies import ROLE_AUTH_ADMIN
from ra_common.security import AccessTokenClaims, require_roles

router = APIRouter(prefix="/v1/admin", tags=["admin"])


@router.get("/principals", response_model=PrincipalPage, summary="Lister les principaux")
async def list_principals(
    limit: int = Query(50, ge=1, le=200),
    cursor: str | None = Query(None, pattern=r"^[a-z0-9][a-z0-9._-]{2,63}$"),
    container: Container = Depends(get_container),
    _: AccessTokenClaims = Depends(require_roles(ROLE_AUTH_ADMIN)),
) -> PrincipalPage:
    items, next_cursor = await container.principals.list_page(after_username=cursor, limit=limit)
    return PrincipalPage(
        items=[PrincipalAdminView.of(item, container.face_login.blocked_seconds(item.username)) for item in items],
        next_cursor=next_cursor,
    )


@router.put("/principals/{principal_id}/face", response_model=PrincipalAdminView, summary="Enrôler ou remplacer le visage")
async def enroll_face(
    principal_id: UUID,
    body: FaceImage,
    container: Container = Depends(get_container),
    claims: AccessTokenClaims = Depends(require_roles(ROLE_AUTH_ADMIN)),
) -> PrincipalAdminView:
    return PrincipalAdminView.of(await container.face_login.enroll(claims.sub, principal_id, body.image))


ROLE_PATH = Path(pattern=r"^[a-z]+(\.[a-z_]+)+$", max_length=64)


@router.post("/principals/{principal_id}/roles/{role}", response_model=PrincipalAdminView, summary="Attribuer un rôle")
async def grant_role(
    principal_id: UUID,
    role: str = ROLE_PATH,
    container: Container = Depends(get_container),
    claims: AccessTokenClaims = Depends(require_roles(ROLE_AUTH_ADMIN)),
) -> PrincipalAdminView:
    return PrincipalAdminView.of(await container.principals.set_role(claims, principal_id, role, grant=True))


@router.delete("/principals/{principal_id}/roles/{role}", response_model=PrincipalAdminView, summary="Retirer un rôle (révoque les jetons)")
async def revoke_role(
    principal_id: UUID,
    role: str = ROLE_PATH,
    container: Container = Depends(get_container),
    claims: AccessTokenClaims = Depends(require_roles(ROLE_AUTH_ADMIN)),
) -> PrincipalAdminView:
    return PrincipalAdminView.of(await container.principals.set_role(claims, principal_id, role, grant=False))


@router.post("/principals/{principal_id}/{action}", response_model=None, summary="Désactiver, réactiver ou révoquer les jetons")
async def principal_action(
    principal_id: UUID,
    body: ContainmentRequest,
    action: str = Path(pattern="^(disable|enable|revoke-tokens)$"),
    container: Container = Depends(get_container),
    claims: AccessTokenClaims = Depends(require_roles(ROLE_AUTH_ADMIN)),
) -> JSONResponse:
    if action == "enable":
        # Déblocage manuel : lève aussi le blocage de l'étape faciale.
        principal = await container.principals.enable(claims, principal_id, reason=body.reason)
        container.face_login.unlock(principal.username)
        return JSONResponse(PrincipalAdminView.of(principal).model_dump(mode="json"))
    result = await container.principals.contain(
        claims, principal_id, disable=action == "disable", reason=body.reason, incident_id=body.incident_id
    )
    return JSONResponse({"principal_id": str(result.principal_id), "is_active": result.is_active,
                         "refresh_tokens_revoked": result.refresh_tokens_revoked})


@router.get("/sessions", summary="Sessions actives (une par famille de refresh token)")
async def sessions(
    container: Container = Depends(get_container), _: AccessTokenClaims = Depends(require_roles(ROLE_AUTH_ADMIN))
) -> JSONResponse:
    return JSONResponse({"items": [jsonable_encoder(dict(row)) for row in await container.principals.sessions()]})


@router.get("/audit", summary="Journal d'audit d'authentification")
async def audit(
    limit: int = Query(100, ge=1, le=500),
    container: Container = Depends(get_container),
    _: AccessTokenClaims = Depends(require_roles(ROLE_AUTH_ADMIN)),
) -> JSONResponse:
    return JSONResponse({"items": [jsonable_encoder(dict(row)) for row in await container.principals.audit_log(limit)]})
