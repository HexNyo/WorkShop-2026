"""Administration de remédiation (svc.remediation, réseau interne, jamais routé par la passerelle)."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Path
from ra_common.security import require_roles
from starlette.responses import JSONResponse

from app.api.deps import get_container
from app.api.routes_health import integrity_response
from app.api.schemas import (
    AccountStatusOut,
    FlagList,
    FlagOut,
    FlagUpdateOut,
    FlagUpdateRequest,
    IntegrityReportRequest,
    IntegritySummary,
    PurgeOut,
    PurgeRequest,
    Reasoned,
    RepairedField,
    RepairOut,
    RepairRequest,
)
from app.container import Container
from app.domain.models import ROLE_REMEDIATION, Caller

router = APIRouter(prefix="/admin/v1", tags=["administration"])


async def remediation_caller(claims=Depends(require_roles(ROLE_REMEDIATION))) -> Caller:
    return Caller.from_claims(claims)


def _flag_out(row) -> FlagOut:
    return FlagOut(
        key=row["key"],
        value=row["value"],
        reason=row["reason"],
        updated_by=row["updated_by"],
        incident_id=row["incident_id"],
        updated_at=row["updated_at"],
    )


@router.get("/runtime-flags", response_model=FlagList, summary="Configuration dynamique courante")
async def list_flags(container: Container = Depends(get_container), _: Caller = Depends(remediation_caller)) -> FlagList:
    return FlagList(items=[_flag_out(row) for row in await container.administration.list_flags()])


@router.put("/runtime-flags/{key}", response_model=FlagUpdateOut, summary="Reconfiguration à chaud")
async def update_flag(
    body: FlagUpdateRequest,
    key: str = Path(pattern=r"^[a-z_]{3,64}$"),
    container: Container = Depends(get_container),
    actor: Caller = Depends(remediation_caller),
) -> FlagUpdateOut:
    previous, row = await container.administration.update_flag(
        actor, key, body.value, reason=body.reason, incident_id=body.incident_id
    )
    return FlagUpdateOut(key=row["key"], previous_value=previous, value=row["value"], updated_at=row["updated_at"])


@router.post("/integrity/reports", status_code=201, summary="Rapport d'intégrité persistant")
async def integrity_report(
    body: IntegrityReportRequest | None = None,
    container: Container = Depends(get_container),
    _: Caller = Depends(remediation_caller),
) -> JSONResponse:
    outcome = await container.administration.integrity_report(body.incident_id if body else None)
    # 201 même en cas d'anomalie : le rapport est créé, son `status` porte le diagnostic.
    return integrity_response(container, outcome, status_code=201)


@router.post("/integrity/repair", response_model=RepairOut, summary="Reconstruire les soldes depuis le grand livre")
async def repair(
    body: RepairRequest, container: Container = Depends(get_container), _: Caller = Depends(remediation_caller)
) -> RepairOut:
    outcome = await container.administration.repair(reason=body.reason, incident_id=body.incident_id, dry_run=body.dry_run)
    after = outcome.integrity_after
    return RepairOut(
        dry_run=outcome.dry_run,
        repaired=[RepairedField(**item) for item in outcome.repaired],
        integrity_after=IntegritySummary(status=after.status, report_id=after.report_id) if after else None,
    )


@router.post("/maintenance/purge-stale", response_model=PurgeOut, summary="Purger les transactions bloquées en vol")
async def purge_stale(
    body: PurgeRequest, container: Container = Depends(get_container), _: Caller = Depends(remediation_caller)
) -> PurgeOut:
    purged = await container.administration.purge_stale(
        older_than_seconds=body.older_than_seconds, reason=body.reason, incident_id=body.incident_id
    )
    return PurgeOut(purged=purged)


@router.post("/accounts/{account_id}/freeze", response_model=AccountStatusOut, summary="Geler un compte")
async def freeze(
    account_id: UUID, body: Reasoned, container: Container = Depends(get_container), _: Caller = Depends(remediation_caller)
) -> AccountStatusOut:
    status = await container.administration.set_account_status(
        account_id, frozen=True, reason=body.reason, incident_id=body.incident_id
    )
    return AccountStatusOut(id=account_id, status=status)


@router.post("/accounts/{account_id}/unfreeze", response_model=AccountStatusOut, summary="Dégeler un compte")
async def unfreeze(
    account_id: UUID, body: Reasoned, container: Container = Depends(get_container), _: Caller = Depends(remediation_caller)
) -> AccountStatusOut:
    status = await container.administration.set_account_status(
        account_id, frozen=False, reason=body.reason, incident_id=body.incident_id
    )
    return AccountStatusOut(id=account_id, status=status)
