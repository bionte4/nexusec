"""Tests for compliance PDF rendering and NIST/SLA backfill."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core.enums import FindingStatus, Severity, UserRole
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.schemas.reports import (
    ComplianceReport,
    ControlBucket,
    ReportFindingRow,
    ReportMetadata,
    ReportSection,
)
from app.services.backfill_service import BackfillService
from app.services.compliance_pdf import render_compliance_pdf


def _sample_report() -> ComplianceReport:
    now = datetime.now(timezone.utc)
    meta = ReportMetadata(
        report_id=uuid.uuid4(),
        report_type="nist_csf",
        title="NIST CSF Test Report",
        standard="NIST CSF 2.0",
        generated_at=now,
        auditor_user_id=uuid.uuid4(),
        auditor_name="Auditor",
        auditor_email="a@example.com",
        auditor_role=UserRole.SOC_ANALYST.value,
        scope_total_assets=2,
        scope_cde_assets=1,
        scope_active_findings=1,
    )
    finding = ReportFindingRow(
        vulnerability_id=uuid.uuid4(),
        title="Open SSH",
        severity=Severity.HIGH,
        status=FindingStatus.OPEN,
        asset_id=uuid.uuid4(),
        asset_name="host-1",
        controls=["ID.RA-01", "RA-5"],
        first_seen_at=now,
        last_seen_at=now,
    )
    return ComplianceReport(
        metadata=meta,
        executive_summary="One active high finding mapped to NIST controls.",
        sections=[
            ReportSection(
                heading="Overview",
                summary="Test section",
                metrics={"active_findings": 1},
            )
        ],
        control_mapping=[
            ControlBucket(
                control_id="ID.RA-01",
                control_title="Risk assessment",
                finding_count=1,
                severity_summary={"high": 1},
                findings=[finding],
            )
        ],
        findings=[finding],
        recommendations=["Patch promptly."],
    )


def test_render_compliance_pdf_produces_pdf_header() -> None:
    pdf = render_compliance_pdf(_sample_report())
    assert pdf[:5] == b"%PDF-"
    assert len(pdf) > 500


@pytest.mark.asyncio
async def test_backfill_fills_nist_and_sla() -> None:
    now = datetime.now(timezone.utc)
    vuln = Vulnerability(
        id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        scan_id=uuid.uuid4(),
        asset_id=uuid.uuid4(),
        fingerprint="fp1",
        title="Open port tcp/22 (ssh)",
        description="SSH exposed",
        severity=Severity.INFO,
        status=FindingStatus.OPEN,
        evidence={},
        mitre_attack_techniques=[],
        compliance_metadata={"iso_27001": ["A.8.8"]},
        raw_source={},
        source_tool="nmap",
        port=22,
        protocol="tcp",
        first_seen_at=now,
        last_seen_at=now,
        created_at=now,
        updated_at=now,
        remediation_due_at=None,
    )
    db = AsyncMock()
    result_mock = MagicMock()
    result_mock.scalars.return_value.all.return_value = [vuln]
    db.execute = AsyncMock(return_value=result_mock)
    db.flush = AsyncMock()

    out = await BackfillService(db).backfill_nist_and_sla(limit=10)
    assert out["nist_updated"] == 1
    assert out["sla_updated"] == 1
    assert vuln.compliance_metadata.get("nist_csf")
    assert vuln.compliance_metadata.get("nist_800_53")
    assert vuln.remediation_due_at is not None
