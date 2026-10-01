"""Compliance + engagement report export endpoints (JSON / PDF)."""

from __future__ import annotations

import uuid
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import RequireAdmin, RequireSocOrAbove, RequireTenant
from app.schemas.reports import ComplianceReport, EngagementReport
from app.services.backfill_service import BackfillService
from app.services.compliance_pdf import render_compliance_pdf
from app.services.compliance_report_service import ComplianceReportService
from app.services.engagement_approval_service import (
    EngagementApprovalError,
    EngagementApprovalService,
)
from app.services.engagement_pdf import render_engagement_pdf
from app.services.engagement_report_service import EngagementReportService
from app.services.scan_policy import EngagementExportBlocked

router = APIRouter(prefix="/reports", tags=["reports"])

_REPORT_KINDS = ("iso27001", "pci-dss", "gdpr", "nist-csf")


class EngagementApproveRequest(BaseModel):
    scan_id: Optional[uuid.UUID] = None
    asset_id: Optional[uuid.UUID] = None
    engagement_type: Optional[str] = Field(
        default=None, pattern="^(va|pt|discovery|compliance|custom)$"
    )
    notes: Optional[str] = Field(default=None, max_length=2000)


def get_report_service(db: AsyncSession = Depends(get_db)) -> ComplianceReportService:
    return ComplianceReportService(db)


def get_engagement_service(
    db: AsyncSession = Depends(get_db),
) -> EngagementReportService:
    return EngagementReportService(db)


def get_approval_service(
    db: AsyncSession = Depends(get_db),
) -> EngagementApprovalService:
    return EngagementApprovalService(db)


async def _generate(
    kind: str,
    current_user: RequireSocOrAbove,
    service: ComplianceReportService,
    *,
    asset_id: uuid.UUID | None = None,
    cde_only: bool = True,
) -> ComplianceReport:
    if kind == "iso27001":
        return await service.generate_iso27001(current_user, asset_id=asset_id)
    if kind == "pci-dss":
        return await service.generate_pci_dss(
            current_user, asset_id=asset_id, cde_only=cde_only
        )
    if kind == "gdpr":
        return await service.generate_gdpr(current_user, asset_id=asset_id)
    if kind == "nist-csf":
        return await service.generate_nist_csf(current_user, asset_id=asset_id)
    raise HTTPException(status_code=404, detail=f"Unknown report kind: {kind}")


@router.get(
    "/engagement",
    response_model=EngagementReport,
    summary="VA/PT engagement report (JSON / PDF-ready)",
)
async def engagement_report(
    current_user: RequireSocOrAbove,
    scan_id: uuid.UUID | None = Query(
        None, description="Limit report to findings from this scan"
    ),
    asset_id: uuid.UUID | None = Query(
        None, description="Limit report to findings for this asset"
    ),
    engagement_type: str | None = Query(
        None,
        description="Optional filter: va | pt | discovery | compliance | custom",
        pattern="^(va|pt|discovery|compliance|custom)$",
    ),
    top_n: int = Query(25, ge=1, le=100, description="Top findings listed first"),
    allow_mock: bool = Query(
        False,
        description="Allow lab/synthetic findings (not for client delivery)",
    ),
    delivery: str = Query(
        "draft",
        pattern="^(draft|client)$",
        description="draft = internal; client = requires dual-control approval",
    ),
    service: EngagementReportService = Depends(get_engagement_service),
) -> EngagementReport:
    try:
        return await service.generate(
            current_user,
            scan_id=scan_id,
            asset_id=asset_id,
            engagement_type=engagement_type,
            top_n=top_n,
            allow_mock=allow_mock,
            delivery=delivery,
        )
    except EngagementExportBlocked as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get(
    "/engagement/pdf",
    summary="Download VA/PT engagement report as PDF",
    responses={200: {"content": {"application/pdf": {}}}},
)
async def engagement_report_pdf(
    current_user: RequireSocOrAbove,
    scan_id: uuid.UUID | None = Query(None),
    asset_id: uuid.UUID | None = Query(None),
    engagement_type: str | None = Query(
        None,
        pattern="^(va|pt|discovery|compliance|custom)$",
    ),
    top_n: int = Query(25, ge=1, le=100),
    allow_mock: bool = Query(
        False,
        description="Allow lab/synthetic findings (not for client delivery)",
    ),
    delivery: str = Query(
        "draft",
        pattern="^(draft|client)$",
        description="draft = internal; client = requires dual-control approval",
    ),
    service: EngagementReportService = Depends(get_engagement_service),
) -> Response:
    try:
        report = await service.generate(
            current_user,
            scan_id=scan_id,
            asset_id=asset_id,
            engagement_type=engagement_type,
            top_n=top_n,
            allow_mock=allow_mock,
            delivery=delivery,
        )
    except EngagementExportBlocked as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    pdf_bytes = render_engagement_pdf(report)
    parts = ["nexusec-engagement", report.engagement_type, delivery]
    if scan_id:
        parts.append(f"scan-{str(scan_id)[:8]}")
    if asset_id:
        parts.append(f"asset-{str(asset_id)[:8]}")
    if allow_mock:
        parts.append("lab")
    parts.append(report.metadata.generated_at.date().isoformat())
    filename = "-".join(parts) + ".pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get(
    "/engagement/approval",
    summary="Check dual-control approval status for engagement scope",
)
async def engagement_approval_status(
    current_user: RequireSocOrAbove,
    tenant: RequireTenant,
    scan_id: uuid.UUID | None = Query(None),
    asset_id: uuid.UUID | None = Query(None),
    engagement_type: str | None = Query(
        None, pattern="^(va|pt|discovery|compliance|custom)$"
    ),
    service: EngagementApprovalService = Depends(get_approval_service),
) -> dict[str, Any]:
    org_id = tenant.require_organization_id()
    return await service.status(
        organization_id=org_id,
        scan_id=scan_id,
        asset_id=asset_id,
        engagement_type=engagement_type,
    )


@router.post(
    "/engagement/approve",
    status_code=201,
    summary="Admin/lead dual-control approval for client engagement delivery",
)
async def engagement_approve(
    payload: EngagementApproveRequest,
    current_user: RequireAdmin,
    tenant: RequireTenant,
    service: EngagementApprovalService = Depends(get_approval_service),
) -> dict[str, Any]:
    org_id = tenant.require_organization_id()
    try:
        return await service.approve(
            current_user,
            organization_id=org_id,
            scan_id=payload.scan_id,
            asset_id=payload.asset_id,
            engagement_type=payload.engagement_type,
            notes=payload.notes,
        )
    except EngagementApprovalError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.post(
    "/engagement/revoke-approval",
    summary="Revoke dual-control approval for engagement scope",
)
async def engagement_revoke_approval(
    payload: EngagementApproveRequest,
    current_user: RequireAdmin,
    tenant: RequireTenant,
    service: EngagementApprovalService = Depends(get_approval_service),
) -> dict[str, Any]:
    org_id = tenant.require_organization_id()
    try:
        return await service.revoke(
            current_user,
            organization_id=org_id,
            scan_id=payload.scan_id,
            asset_id=payload.asset_id,
            engagement_type=payload.engagement_type,
        )
    except EngagementApprovalError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get(
    "/iso27001",
    response_model=ComplianceReport,
    summary="ISO 27001 Annex A audit report (JSON / PDF-ready)",
)
async def iso27001_report(
    current_user: RequireSocOrAbove,
    asset_id: uuid.UUID | None = Query(
        None, description="Limit report to findings for this asset"
    ),
    service: ComplianceReportService = Depends(get_report_service),
) -> ComplianceReport:
    return await service.generate_iso27001(current_user, asset_id=asset_id)


@router.get(
    "/pci-dss",
    response_model=ComplianceReport,
    summary="PCI-DSS Req 11 & CDE scope report (JSON / PDF-ready)",
)
async def pci_dss_report(
    current_user: RequireSocOrAbove,
    asset_id: uuid.UUID | None = Query(
        None, description="Limit report to findings for this asset"
    ),
    cde_only: bool = Query(
        True,
        description="Restrict findings to CDE-scoped assets (PCI inventory gate)",
    ),
    service: ComplianceReportService = Depends(get_report_service),
) -> ComplianceReport:
    return await service.generate_pci_dss(
        current_user, asset_id=asset_id, cde_only=cde_only
    )


@router.get(
    "/gdpr",
    response_model=ComplianceReport,
    summary="GDPR PII / data leakage assessment report (JSON / PDF-ready)",
)
async def gdpr_report(
    current_user: RequireSocOrAbove,
    asset_id: uuid.UUID | None = Query(
        None, description="Limit report to findings for this asset"
    ),
    service: ComplianceReportService = Depends(get_report_service),
) -> ComplianceReport:
    return await service.generate_gdpr(current_user, asset_id=asset_id)


@router.get(
    "/nist-csf",
    response_model=ComplianceReport,
    summary="NIST CSF 2.0 / SP 800-53 vulnerability control mapping report",
)
async def nist_csf_report(
    current_user: RequireSocOrAbove,
    asset_id: uuid.UUID | None = Query(
        None, description="Limit report to findings for this asset"
    ),
    service: ComplianceReportService = Depends(get_report_service),
) -> ComplianceReport:
    return await service.generate_nist_csf(current_user, asset_id=asset_id)


@router.get(
    "/{kind}/pdf",
    summary="Download compliance report as PDF",
    responses={200: {"content": {"application/pdf": {}}}},
)
async def compliance_report_pdf(
    kind: str,
    current_user: RequireSocOrAbove,
    asset_id: uuid.UUID | None = Query(
        None, description="Limit report to findings for this asset"
    ),
    cde_only: bool = Query(
        True,
        description="PCI-DSS only: restrict findings to CDE-scoped assets",
    ),
    service: ComplianceReportService = Depends(get_report_service),
) -> Response:
    if kind not in _REPORT_KINDS:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown report kind. Expected one of: {', '.join(_REPORT_KINDS)}",
        )
    report = await _generate(
        kind, current_user, service, asset_id=asset_id, cde_only=cde_only
    )
    pdf_bytes = render_compliance_pdf(report)
    suffix = f"-asset-{str(asset_id)[:8]}" if asset_id else ""
    cde_suffix = "-cde" if kind == "pci-dss" and cde_only else ""
    filename = (
        f"nexusec-{kind}{cde_suffix}{suffix}-"
        f"{report.metadata.generated_at.date().isoformat()}.pdf"
    )
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post(
    "/backfill-metadata",
    summary="Backfill missing NIST tags and remediation SLA due dates (Admin)",
)
async def backfill_metadata(
    tenant: RequireTenant,
    _: RequireAdmin,
    limit: int = Query(500, ge=1, le=5000),
    fill_nist: bool = Query(True),
    fill_sla: bool = Query(True),
    db: AsyncSession = Depends(get_db),
) -> dict:
    org_id = None if tenant.cross_tenant else tenant.organization_id
    return await BackfillService(db).backfill_nist_and_sla(
        organization_id=org_id,
        limit=limit,
        fill_nist=fill_nist,
        fill_sla=fill_sla,
    )


@router.get(
    "",
    summary="List available compliance report types",
)
async def list_report_types(_: RequireSocOrAbove) -> dict[str, list[dict[str, str]]]:
    return {
        "reports": [
            {
                "id": "engagement",
                "path": "/api/v1/reports/engagement",
                "pdf": "/api/v1/reports/engagement/pdf",
                "standard": "NexuSec VA/PT Engagement",
                "query": (
                    "scan_id, asset_id, engagement_type, delivery=draft|client, "
                    "approve via POST /engagement/approve"
                ),
            },
            {
                "id": "iso27001",
                "path": "/api/v1/reports/iso27001",
                "pdf": "/api/v1/reports/iso27001/pdf",
                "standard": "ISO/IEC 27001:2022 Annex A",
                "query": "asset_id (optional UUID)",
            },
            {
                "id": "pci_dss",
                "path": "/api/v1/reports/pci-dss",
                "pdf": "/api/v1/reports/pci-dss/pdf",
                "standard": "PCI DSS v4.0 Requirement 11",
                "query": "asset_id (optional), cde_only=true (default)",
            },
            {
                "id": "gdpr",
                "path": "/api/v1/reports/gdpr",
                "pdf": "/api/v1/reports/gdpr/pdf",
                "standard": "GDPR Arts. 5/25/32/33",
                "query": "asset_id (optional UUID)",
            },
            {
                "id": "nist_csf",
                "path": "/api/v1/reports/nist-csf",
                "pdf": "/api/v1/reports/nist-csf/pdf",
                "standard": "NIST CSF 2.0 + SP 800-53 Rev.5",
                "query": "asset_id (optional UUID)",
            },
        ]
    }
