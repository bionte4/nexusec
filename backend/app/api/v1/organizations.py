"""Tenant (organization) management endpoints."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import RequireAdmin, RequireSuperAdmin, RequireTenant
from app.core.enums import UserRole
from app.schemas.organization import (
    OrganizationCreate,
    OrganizationListResponse,
    OrganizationMetrics,
    OrganizationRead,
    OrganizationUpdate,
    WorkspaceTokenResponse,
)
from app.services.organization_service import (
    OrganizationNotFoundError,
    OrganizationService,
    OrganizationValidationError,
)

router = APIRouter(prefix="/organizations", tags=["organizations"])


def get_org_service(db: AsyncSession = Depends(get_db)) -> OrganizationService:
    return OrganizationService(db)


def _ensure_can_view(tenant: RequireTenant, organization_id: uuid.UUID) -> None:
    if not tenant.can_access_org(organization_id):
        raise HTTPException(status_code=403, detail="Cannot access this organization")


@router.post(
    "",
    response_model=OrganizationRead,
    status_code=status.HTTP_201_CREATED,
    summary="Onboard a new tenant (Super Admin)",
)
async def create_organization(
    payload: OrganizationCreate,
    _: RequireSuperAdmin,
    service: OrganizationService = Depends(get_org_service),
) -> OrganizationRead:
    try:
        return await service.create(payload)
    except OrganizationValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get(
    "",
    response_model=OrganizationListResponse,
    summary="List tenants (Super Admin)",
)
async def list_organizations(
    _: RequireSuperAdmin,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: str | None = Query(None),
    is_active: bool | None = Query(None),
    service: OrganizationService = Depends(get_org_service),
) -> OrganizationListResponse:
    return await service.list(page=page, page_size=page_size, search=search, is_active=is_active)


@router.get(
    "/me",
    response_model=OrganizationRead,
    summary="Current user's organization",
)
async def my_organization(
    tenant: RequireTenant,
    service: OrganizationService = Depends(get_org_service),
) -> OrganizationRead:
    org_id = tenant.require_organization_id()
    try:
        return await service.get(org_id)
    except OrganizationNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "/me/metrics",
    response_model=OrganizationMetrics,
    summary="Security metrics for current organization",
)
async def my_organization_metrics(
    tenant: RequireTenant,
    service: OrganizationService = Depends(get_org_service),
) -> OrganizationMetrics:
    org_id = tenant.require_organization_id()
    try:
        return await service.metrics(org_id)
    except OrganizationNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "/{organization_id}",
    response_model=OrganizationRead,
    summary="Get organization (Admin of org or Super Admin)",
)
async def get_organization(
    organization_id: uuid.UUID,
    tenant: RequireTenant,
    current_user: RequireAdmin,
    service: OrganizationService = Depends(get_org_service),
) -> OrganizationRead:
    _ensure_can_view(tenant, organization_id)
    if (
        current_user.role != UserRole.SUPER_ADMIN
        and current_user.organization_id != organization_id
    ):
        raise HTTPException(status_code=403, detail="Cannot access this organization")
    try:
        return await service.get(organization_id)
    except OrganizationNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.patch(
    "/{organization_id}",
    response_model=OrganizationRead,
    summary="Update organization (Super Admin or org Admin)",
)
async def update_organization(
    organization_id: uuid.UUID,
    payload: OrganizationUpdate,
    tenant: RequireTenant,
    current_user: RequireAdmin,
    service: OrganizationService = Depends(get_org_service),
) -> OrganizationRead:
    if current_user.role != UserRole.SUPER_ADMIN:
        if current_user.organization_id != organization_id:
            raise HTTPException(status_code=403, detail="Cannot modify this organization")
        # Org admins cannot deactivate via this path accidentally from another tenant
        _ensure_can_view(tenant, organization_id)
    try:
        return await service.update(organization_id, payload)
    except OrganizationNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "/{organization_id}/metrics",
    response_model=OrganizationMetrics,
    summary="Tenant-specific security metrics",
)
async def organization_metrics(
    organization_id: uuid.UUID,
    tenant: RequireTenant,
    current_user: RequireAdmin,
    service: OrganizationService = Depends(get_org_service),
) -> OrganizationMetrics:
    if (
        current_user.role != UserRole.SUPER_ADMIN
        and current_user.organization_id != organization_id
    ):
        raise HTTPException(status_code=403, detail="Cannot access this organization")
    if not tenant.is_super_admin:
        _ensure_can_view(tenant, organization_id)
    try:
        return await service.metrics(organization_id)
    except OrganizationNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post(
    "/{organization_id}/workspace-token/rotate",
    response_model=WorkspaceTokenResponse,
    summary="Rotate isolated workspace API token (Super Admin or org Admin)",
)
async def rotate_workspace_token(
    organization_id: uuid.UUID,
    current_user: RequireAdmin,
    service: OrganizationService = Depends(get_org_service),
) -> WorkspaceTokenResponse:
    if (
        current_user.role != UserRole.SUPER_ADMIN
        and current_user.organization_id != organization_id
    ):
        raise HTTPException(status_code=403, detail="Cannot rotate token for this organization")
    try:
        return await service.rotate_workspace_token(organization_id)
    except OrganizationNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
