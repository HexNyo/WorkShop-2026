"""Laboratoire de pannes (monté uniquement si PAYMENT_CHAOS_LAB_ENABLED=true)."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from ra_common.security import AccessTokenClaims, require_roles

from app.api.deps import get_container
from app.api.schemas import ClearedOut, FaultList, FaultOut, FaultRequest
from app.container import Container
from app.domain.models import ROLE_CHAOS
from app.services.faults import ActiveFault

router = APIRouter(prefix="/lab/v1", tags=["lab"])


def _out(fault: ActiveFault) -> FaultOut:
    return FaultOut(
        fault_id=fault.id,
        type=fault.type,
        params=fault.params,
        activated_at=fault.activated_at,
        active_until=fault.active_until,
    )


@router.get("/faults", response_model=FaultList, summary="Pannes actives")
async def list_faults(
    container: Container = Depends(get_container), _: AccessTokenClaims = Depends(require_roles(ROLE_CHAOS))
) -> FaultList:
    return FaultList(items=[_out(fault) for fault in container.faults.active()])


@router.post("/faults", response_model=FaultOut, status_code=201, summary="Injecter une panne")
async def inject_fault(
    body: FaultRequest,
    container: Container = Depends(get_container),
    _: AccessTokenClaims = Depends(require_roles(ROLE_CHAOS)),
) -> FaultOut:
    return _out(await container.faults.activate(body.type, body.params, body.duration_seconds))


@router.delete("/faults", response_model=ClearedOut, summary="Lever toutes les pannes actives")
async def clear_faults(
    container: Container = Depends(get_container), _: AccessTokenClaims = Depends(require_roles(ROLE_CHAOS))
) -> ClearedOut:
    return ClearedOut(cleared=await container.faults.clear_all())
