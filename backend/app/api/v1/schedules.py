"""Scan schedule API — create/list/update/delete recurring VA jobs."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import RequirePentesterOrAdmin, RequireTenant
from app.schemas.scan_schedule import (
    ScanScheduleCreate,
    ScanScheduleListResponse,
    ScanScheduleRead,
    ScanScheduleUpdate,
)
from app.services.scan_schedule_service import (
    ScanScheduleNotFoundError,
    ScanScheduleService,
)
from app.services.scan_service import ScanValidationError

router = APIRouter(prefix="/scan-schedules", tags=["scan-schedules"])


def get_schedule_service(db: AsyncSession = Depends(get_db)) -> ScanScheduleService:
    return ScanScheduleService(db)


def _org_scope(tenant: RequireTenant) -> uuid.UUID | None:
    return None if tenant.cross_tenant else tenant.organization_id


@router.post(
    "",
    response_model=ScanScheduleRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create a recurring scan schedule (Admin/Pentester)",
)
async def create_schedule(
    payload: ScanScheduleCreate,
    tenant: RequireTenant,
    current_user: RequirePentesterOrAdmin,
    service: ScanScheduleService = Depends(get_schedule_service),
) -> ScanScheduleRead:
    org_id = tenant.require_organization_id()
    try:
        return await service.create(
            payload, organization_id=org_id, created_by_id=current_user.id
        )
    except ScanValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.get(
    "",
    response_model=ScanScheduleListResponse,
    summary="List scan schedules",
)
async def list_schedules(
    tenant: RequireTenant,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    enabled: bool | None = Query(None),
    service: ScanScheduleService = Depends(get_schedule_service),
) -> ScanScheduleListResponse:
    return await service.list(
        page=page,
        page_size=page_size,
        organization_id=_org_scope(tenant),
        enabled=enabled,
    )


@router.get(
    "/{schedule_id}",
    response_model=ScanScheduleRead,
    summary="Get scan schedule by ID",
)
async def get_schedule(
    schedule_id: uuid.UUID,
    tenant: RequireTenant,
    service: ScanScheduleService = Depends(get_schedule_service),
) -> ScanScheduleRead:
    try:
        return await service.get(schedule_id, organization_id=_org_scope(tenant))
    except ScanScheduleNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.patch(
    "/{schedule_id}",
    response_model=ScanScheduleRead,
    summary="Update scan schedule",
)
async def update_schedule(
    schedule_id: uuid.UUID,
    payload: ScanScheduleUpdate,
    tenant: RequireTenant,
    _: RequirePentesterOrAdmin,
    service: ScanScheduleService = Depends(get_schedule_service),
) -> ScanScheduleRead:
    try:
        return await service.update(
            schedule_id, payload, organization_id=_org_scope(tenant)
        )
    except ScanScheduleNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ScanValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.delete(
    "/{schedule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete scan schedule",
)
async def delete_schedule(
    schedule_id: uuid.UUID,
    tenant: RequireTenant,
    _: RequirePentesterOrAdmin,
    service: ScanScheduleService = Depends(get_schedule_service),
) -> None:
    try:
        await service.delete(schedule_id, organization_id=_org_scope(tenant))
    except ScanScheduleNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
