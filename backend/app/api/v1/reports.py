"""Compliance report export endpoints (ISO 27001, PCI-DSS, GDPR)."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import RequireSocOrAbove
from app.schemas.reports import ComplianceReport
from app.services.compliance_report_service import ComplianceReportService

router = APIRouter(prefix="/reports", tags=["reports"])


def get_report_service(db: AsyncSession = Depends(get_db)) -> ComplianceReportService:
    return ComplianceReportService(db)


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
    "",
    summary="List available compliance report types",
)
async def list_report_types(_: RequireSocOrAbove) -> dict[str, list[dict[str, str]]]:
    return {
        "reports": [
            {
                "id": "iso27001",
                "path": "/api/v1/reports/iso27001",
                "standard": "ISO/IEC 27001:2022 Annex A",
            },
            {
                "id": "pci_dss",
                "path": "/api/v1/reports/pci-dss",
                "standard": "PCI DSS v4.0 Requirement 11",
            },
            {
                "id": "gdpr",
                "path": "/api/v1/reports/gdpr",
                "standard": "GDPR Arts. 5/25/32/33",
            },
        ]
    }
