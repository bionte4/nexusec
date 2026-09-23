"""Vulnerability remediation lifecycle endpoints (tenant-scoped)."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import RequireTenant, require_roles
from app.core.enums import FindingStatus, Severity, UserRole
from app.models.user import User
from app.schemas.vulnerability import (
    AIFPAnalysisResponse,
    AIRemediationResponse,
    AssignOwnerRequest,
    VulnerabilityCommentCreate,
    VulnerabilityCommentRead,
    VulnerabilityListResponse,
    VulnerabilityRead,
    VulnerabilityUpdate,
)
from app.services.ai_filter import AIFPAnalysisError
from app.services.ai_remediation import AIRemediationError
from app.services.nist_mapping_service import NISTMappingService
from app.services.vulnerability_service import (
    VulnerabilityNotFoundError,
    VulnerabilityService,
    VulnerabilityValidationError,
)
from pydantic import BaseModel, Field
from typing import Optional

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])

RequireRemediationWriter = Annotated[
    User,
    Depends(
        require_roles(
            UserRole.SUPER_ADMIN,
            UserRole.ADMIN,
            UserRole.PENTESTER,
            UserRole.SOC_ANALYST,
        )
    ),
]


def get_vuln_service(db: AsyncSession = Depends(get_db)) -> VulnerabilityService:
    return VulnerabilityService(db)


def _org_scope(tenant: RequireTenant) -> uuid.UUID | None:
    return None if tenant.cross_tenant else tenant.organization_id


@router.get(
    "",
    response_model=VulnerabilityListResponse,
    summary="List vulnerabilities (authenticated, tenant-scoped)",
)
async def list_vulnerabilities(
    tenant: RequireTenant,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status_filter: FindingStatus | None = Query(None, alias="status"),
    severity: Severity | None = Query(None),
    asset_id: uuid.UUID | None = Query(None),
    scan_id: uuid.UUID | None = Query(None),
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
        scan_id=scan_id,
        owner_id=owner_id,
        search=search,
        organization_id=_org_scope(tenant),
    )


@router.get(
    "/{vulnerability_id}",
    response_model=VulnerabilityRead,
    summary="Get vulnerability detail with comments",
)
async def get_vulnerability(
    vulnerability_id: uuid.UUID,
    tenant: RequireTenant,
    service: VulnerabilityService = Depends(get_vuln_service),
) -> VulnerabilityRead:
    try:
        return await service.get(vulnerability_id, organization_id=_org_scope(tenant))
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
    tenant: RequireTenant,
    _: RequireRemediationWriter,
    service: VulnerabilityService = Depends(get_vuln_service),
) -> VulnerabilityRead:
    try:
        return await service.update(vulnerability_id, payload, organization_id=_org_scope(tenant))
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
    tenant: RequireTenant,
    _: RequireRemediationWriter,
    service: VulnerabilityService = Depends(get_vuln_service),
) -> VulnerabilityRead:
    try:
        return await service.assign_owner(
            vulnerability_id, payload, organization_id=_org_scope(tenant)
        )
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
    tenant: RequireTenant,
    service: VulnerabilityService = Depends(get_vuln_service),
) -> list[VulnerabilityCommentRead]:
    try:
        return await service.list_comments(vulnerability_id, organization_id=_org_scope(tenant))
    except VulnerabilityNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post(
    "/{vulnerability_id}/generate-ai-patch",
    response_model=AIRemediationResponse,
    summary="Generate AI remediation + secure patch and save to remediation field",
)
async def generate_ai_patch(
    vulnerability_id: uuid.UUID,
    tenant: RequireTenant,
    _: RequireRemediationWriter,
    persist: bool = Query(True, description="Persist markdown into vulnerability.remediation"),
    service: VulnerabilityService = Depends(get_vuln_service),
) -> AIRemediationResponse:
    try:
        return await service.generate_ai_patch(
            vulnerability_id,
            organization_id=_org_scope(tenant),
            persist=persist,
        )
    except VulnerabilityNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except AIRemediationError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@router.post(
    "/{vulnerability_id}/analyze-fp",
    response_model=AIFPAnalysisResponse,
    summary="AI false-positive analysis (confidence, FP flag, reasoning)",
)
async def analyze_false_positive(
    vulnerability_id: uuid.UUID,
    tenant: RequireTenant,
    _: RequireRemediationWriter,
    persist: bool = Query(
        True,
        description="Persist evaluation into vulnerability.threat_intel_metadata.ai_fp_analysis",
    ),
    service: VulnerabilityService = Depends(get_vuln_service),
) -> AIFPAnalysisResponse:
    try:
        return await service.analyze_false_positive(
            vulnerability_id,
            organization_id=_org_scope(tenant),
            persist=persist,
        )
    except VulnerabilityNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except AIFPAnalysisError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


class NISTAcceptPayload(BaseModel):
    nist_csf: Optional[list[str]] = None
    nist_800_53: Optional[list[str]] = None


@router.post(
    "/{vulnerability_id}/suggest-nist-controls",
    summary="Suggest NIST CSF / 800-53 controls (heuristic or AI; pending review)",
)
async def suggest_nist_controls(
    vulnerability_id: uuid.UUID,
    tenant: RequireTenant,
    _: RequireRemediationWriter,
    persist: bool = Query(True),
    use_llm: bool = Query(True),
    db: AsyncSession = Depends(get_db),
) -> dict:
    try:
        return await NISTMappingService(db).suggest(
            vulnerability_id,
            organization_id=_org_scope(tenant),
            persist=persist,
            use_llm=use_llm,
        )
    except VulnerabilityNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except AIRemediationError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@router.post(
    "/{vulnerability_id}/accept-nist-controls",
    summary="Accept pending NIST control suggestions into compliance_metadata",
)
async def accept_nist_controls(
    vulnerability_id: uuid.UUID,
    tenant: RequireTenant,
    _: RequireRemediationWriter,
    payload: NISTAcceptPayload | None = None,
    db: AsyncSession = Depends(get_db),
) -> dict:
    body = payload or NISTAcceptPayload()
    try:
        return await NISTMappingService(db).accept(
            vulnerability_id,
            organization_id=_org_scope(tenant),
            nist_csf=body.nist_csf,
            nist_800_53=body.nist_800_53,
        )
    except VulnerabilityNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except AIRemediationError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@router.post(
    "/{vulnerability_id}/comments",
    response_model=VulnerabilityCommentRead,
    status_code=status.HTTP_201_CREATED,
    summary="Add remediation note/comment (SOC Analyst+)",
)
async def add_comment(
    vulnerability_id: uuid.UUID,
    payload: VulnerabilityCommentCreate,
    tenant: RequireTenant,
    current_user: RequireRemediationWriter,
    service: VulnerabilityService = Depends(get_vuln_service),
) -> VulnerabilityCommentRead:
    try:
        return await service.add_comment(
            vulnerability_id,
            payload,
            author_id=current_user.id,
            organization_id=_org_scope(tenant),
        )
    except VulnerabilityNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
