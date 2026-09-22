"""Vulnerability remediation lifecycle endpoints."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import RequireAnyAuthenticated, require_roles
from app.core.enums import FindingStatus, Severity, UserRole
from typing import Annotated
from app.models.user import User
from app.schemas.vulnerability import (
    AssignOwnerRequest,
    VulnerabilityCommentCreate,
    VulnerabilityCommentRead,
    VulnerabilityListResponse,
    VulnerabilityRead,
    VulnerabilityUpdate,
)
from app.services.vulnerability_service import (
    VulnerabilityNotFoundError,
    VulnerabilityService,
    VulnerabilityValidationError,
)

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])

# SOC Analyst+ can update lifecycle; Admin/Pentester also included via RequireSocOrAbove
RequireRemediationWriter = Annotated[
    User,
    Depends(require_roles(UserRole.ADMIN, UserRole.PENTESTER, UserRole.SOC_ANALYST)),
]


def get_vuln_service(db: AsyncSession = Depends(get_db)) -> VulnerabilityService:
    return VulnerabilityService(db)


@router.get(
    "",
    response_model=VulnerabilityListResponse,
    summary="List vulnerabilities (authenticated)",
)
async def list_vulnerabilities(
    _: RequireAnyAuthenticated,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status_filter: FindingStatus | None = Query(None, alias="status"),
    severity: Severity | None = Query(None),
    asset_id: uuid.UUID | None = Query(None),
    owner_id: uuid.UUID | None = Query(None),
    search: str | None = Query(None),
    service: VulnerabilityService = Depends(get_vuln_service),
) -> VulnerabilityListResponse:
    return await service.list(
        page=page,
        page_size=page_size,
        status=status_filter,
        severity=severity,
        asset_id=asset_id,
        owner_id=owner_id,
        search=search,
    )


@router.get(
    "/{vulnerability_id}",
    response_model=VulnerabilityRead,
    summary="Get vulnerability detail with comments",
)
async def get_vulnerability(
    vulnerability_id: uuid.UUID,
    _: RequireAnyAuthenticated,
    service: VulnerabilityService = Depends(get_vuln_service),
) -> VulnerabilityRead:
    try:
        return await service.get(vulnerability_id)
    except VulnerabilityNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.patch(
    "/{vulnerability_id}",
    response_model=VulnerabilityRead,
    summary="Update status / remediation fields (SOC Analyst+)",
)
async def update_vulnerability(
    vulnerability_id: uuid.UUID,
    payload: VulnerabilityUpdate,
    _: RequireRemediationWriter,
    service: VulnerabilityService = Depends(get_vuln_service),
) -> VulnerabilityRead:
    try:
        return await service.update(vulnerability_id, payload)
    except VulnerabilityNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except VulnerabilityValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post(
    "/{vulnerability_id}/assign",
    response_model=VulnerabilityRead,
    summary="Assign remediation owner (SOC Analyst+)",
)
async def assign_owner(
    vulnerability_id: uuid.UUID,
    payload: AssignOwnerRequest,
    _: RequireRemediationWriter,
    service: VulnerabilityService = Depends(get_vuln_service),
) -> VulnerabilityRead:
    try:
        return await service.assign_owner(vulnerability_id, payload)
    except VulnerabilityNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except VulnerabilityValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get(
    "/{vulnerability_id}/comments",
    response_model=list[VulnerabilityCommentRead],
    summary="List remediation notes/comments",
)
async def list_comments(
    vulnerability_id: uuid.UUID,
    _: RequireAnyAuthenticated,
    service: VulnerabilityService = Depends(get_vuln_service),
) -> list[VulnerabilityCommentRead]:
    try:
        return await service.list_comments(vulnerability_id)
    except VulnerabilityNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post(
    "/{vulnerability_id}/comments",
    response_model=VulnerabilityCommentRead,
    status_code=status.HTTP_201_CREATED,
    summary="Add remediation note/comment (SOC Analyst+)",
)
async def add_comment(
    vulnerability_id: uuid.UUID,
    payload: VulnerabilityCommentCreate,
    current_user: RequireRemediationWriter,
    service: VulnerabilityService = Depends(get_vuln_service),
) -> VulnerabilityCommentRead:
    try:
        return await service.add_comment(vulnerability_id, payload, author_id=current_user.id)
    except VulnerabilityNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
