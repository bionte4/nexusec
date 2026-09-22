"""Asset inventory management endpoints (RBAC + tenant scoped)."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import RequirePentesterOrAdmin, RequireTenant
from app.core.enums import AssetCriticality, AssetType
from app.schemas.asset import (
    AssetCreate,
    AssetListResponse,
    AssetRead,
    AssetUpdate,
)
from app.services.asset_service import AssetNotFoundError, AssetService

router = APIRouter(prefix="/assets", tags=["assets"])


def get_asset_service(db: AsyncSession = Depends(get_db)) -> AssetService:
    return AssetService(db)


@router.post(
    "",
    response_model=AssetRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create asset (Admin / Pentester)",
)
async def create_asset(
    payload: AssetCreate,
    tenant: RequireTenant,
    current_user: RequirePentesterOrAdmin,
    service: AssetService = Depends(get_asset_service),
) -> AssetRead:
    org_id = tenant.require_organization_id()
    return await service.create(
        payload, organization_id=org_id, created_by_id=current_user.id
    )


@router.get(
    "",
    response_model=AssetListResponse,
    summary="List assets (authenticated, tenant-scoped)",
)
async def list_assets(
    tenant: RequireTenant,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: str | None = Query(
        None,
        description="Search by name, domain, hostname, cloud id, URL, owner",
    ),
    asset_type: AssetType | None = Query(None),
    criticality: AssetCriticality | None = Query(None),
    environment: str | None = Query(None, max_length=64),
    is_cde_scope: bool | None = Query(
        None, description="Filter PCI-DSS Cardholder Data Environment assets"
    ),
    service: AssetService = Depends(get_asset_service),
) -> AssetListResponse:
    return await service.list(
        page=page,
        page_size=page_size,
        search=search,
        asset_type=asset_type,
        criticality=criticality,
        environment=environment,
        is_cde_scope=is_cde_scope,
        organization_id=None if tenant.cross_tenant else tenant.organization_id,
    )


@router.get(
    "/{asset_id}",
    response_model=AssetRead,
    summary="Get asset by ID (authenticated)",
)
async def get_asset(
    asset_id: uuid.UUID,
    tenant: RequireTenant,
    service: AssetService = Depends(get_asset_service),
) -> AssetRead:
    try:
        return await service.get(
            asset_id,
            organization_id=None if tenant.cross_tenant else tenant.organization_id,
        )
    except AssetNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc


@router.patch(
    "/{asset_id}",
    response_model=AssetRead,
    summary="Update asset (Admin / Pentester)",
)
async def update_asset(
    asset_id: uuid.UUID,
    payload: AssetUpdate,
    tenant: RequireTenant,
    _: RequirePentesterOrAdmin,
    service: AssetService = Depends(get_asset_service),
) -> AssetRead:
    try:
        return await service.update(
            asset_id,
            payload,
            organization_id=None if tenant.cross_tenant else tenant.organization_id,
        )
    except AssetNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc


@router.delete(
    "/{asset_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete asset (Admin / Pentester)",
)
async def delete_asset(
    asset_id: uuid.UUID,
    tenant: RequireTenant,
    _: RequirePentesterOrAdmin,
    service: AssetService = Depends(get_asset_service),
) -> None:
    try:
        await service.delete(
            asset_id,
            organization_id=None if tenant.cross_tenant else tenant.organization_id,
        )
    except AssetNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
