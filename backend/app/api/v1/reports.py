"""Compliance report export endpoints (ISO 27001, PCI-DSS, GDPR, NIST + PDF)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import RequireAdmin, RequireSocOrAbove, RequireTenant
from app.schemas.reports import ComplianceReport
from app.services.backfill_service import BackfillService
from app.services.compliance_pdf import render_compliance_pdf
from app.services.compliance_report_service import ComplianceReportService

router = APIRouter(prefix="/reports", tags=["reports"])

_REPORT_KINDS = ("iso27001", "pci-dss", "gdpr", "nist-csf")


def get_report_service(db: AsyncSession = Depends(get_db)) -> ComplianceReportService:
    return ComplianceReportService(db)


async def _generate(
    kind: str,
    current_user: RequireSocOrAbove,
    service: ComplianceReportService,
) -> ComplianceReport:
    if kind == "iso27001":
        return await service.generate_iso27001(current_user)
    if kind == "pci-dss":
        return await service.generate_pci_dss(current_user)
    if kind == "gdpr":
        return await service.generate_gdpr(current_user)
    if kind == "nist-csf":
        return await service.generate_nist_csf(current_user)
    raise HTTPException(status_code=404, detail=f"Unknown report kind: {kind}")


@router.get(
    "/iso27001",
    response_model=ComplianceReport,
    summary="ISO 27001 Annex A audit report (JSON / PDF-ready)",
)
async def iso27001_report(
    current_user: RequireSocOrAbove,
    service: ComplianceReportService = Depends(get_report_service),
) -> ComplianceReport:
    return await service.generate_iso27001(current_user)


@router.get(
    "/pci-dss",
    response_model=ComplianceReport,
    summary="PCI-DSS Req 11 & CDE scope report (JSON / PDF-ready)",
)
async def pci_dss_report(
    current_user: RequireSocOrAbove,
    service: ComplianceReportService = Depends(get_report_service),
) -> ComplianceReport:
    return await service.generate_pci_dss(current_user)


@router.get(
    "/gdpr",
    response_model=ComplianceReport,
    summary="GDPR PII / data leakage assessment report (JSON / PDF-ready)",
)
async def gdpr_report(
    current_user: RequireSocOrAbove,
    service: ComplianceReportService = Depends(get_report_service),
) -> ComplianceReport:
    return await service.generate_gdpr(current_user)


@router.get(
    "/nist-csf",
    response_model=ComplianceReport,
    summary="NIST CSF 2.0 / SP 800-53 vulnerability control mapping report",
)
async def nist_csf_report(
    current_user: RequireSocOrAbove,
    service: ComplianceReportService = Depends(get_report_service),
) -> ComplianceReport:
    return await service.generate_nist_csf(current_user)


@router.get(
    "/{kind}/pdf",
    summary="Download compliance report as PDF",
    responses={200: {"content": {"application/pdf": {}}}},
)
async def compliance_report_pdf(
    kind: str,
    current_user: RequireSocOrAbove,
    service: ComplianceReportService = Depends(get_report_service),
) -> Response:
    if kind not in _REPORT_KINDS:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown report kind. Expected one of: {', '.join(_REPORT_KINDS)}",
        )
    report = await _generate(kind, current_user, service)
    pdf_bytes = render_compliance_pdf(report)
    filename = f"nexusec-{kind}-{report.metadata.generated_at.date().isoformat()}.pdf"
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
                "id": "iso27001",
                "path": "/api/v1/reports/iso27001",
                "pdf": "/api/v1/reports/iso27001/pdf",
                "standard": "ISO/IEC 27001:2022 Annex A",
            },
            {
                "id": "pci_dss",
                "path": "/api/v1/reports/pci-dss",
                "pdf": "/api/v1/reports/pci-dss/pdf",
                "standard": "PCI DSS v4.0 Requirement 11",
            },
            {
                "id": "gdpr",
                "path": "/api/v1/reports/gdpr",
                "pdf": "/api/v1/reports/gdpr/pdf",
                "standard": "GDPR Arts. 5/25/32/33",
            },
            {
                "id": "nist_csf",
                "path": "/api/v1/reports/nist-csf",
                "pdf": "/api/v1/reports/nist-csf/pdf",
                "standard": "NIST CSF 2.0 + SP 800-53 Rev.5",
            },
        ]
    }
