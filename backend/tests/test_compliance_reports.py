"""Tests for compliance report generation (ISO / PCI / GDPR)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core.enums import AssetCriticality, AssetType, FindingStatus, Severity, UserRole
from app.models.asset import Asset
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.services.compliance_report_service import (
    ComplianceReportService,
    _extract_controls,
    _is_gdpr_risk,
)


def _user() -> User:
    now = datetime.now(timezone.utc)
    return User(
        id=uuid.uuid4(),
        email="auditor@nexusec.local",
        full_name="Audit User",
        hashed_password="x",
        role=UserRole.SOC_ANALYST,
        is_active=True,
        created_at=now,
        updated_at=now,
    )


def _asset(*, cde: bool = False, name: str = "host-1") -> Asset:
    now = datetime.now(timezone.utc)
    return Asset(
        id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        name=name,
        asset_type=AssetType.IP,
        criticality=AssetCriticality.HIGH,
        ip_address="10.0.0.1",
        domain=None,
        cloud_resource_id=None,
        cloud_provider=None,
        is_cde_scope=cde,
        hostname=None,
        url=None,
        environment="prod",
        owner=None,
        description=None,
        tags={},
        metadata_={},
        created_by_id=None,
        created_at=now,
        updated_at=now,
    )


def _vuln(
    asset: Asset,
    *,
    title: str = "Open SSH",
    severity: Severity = Severity.HIGH,
    status: FindingStatus = FindingStatus.OPEN,
    compliance: dict | None = None,
) -> Vulnerability:
    now = datetime.now(timezone.utc)
    v = Vulnerability(
        id=uuid.uuid4(),
        organization_id=asset.organization_id,
        scan_id=uuid.uuid4(),
        asset_id=asset.id,
        fingerprint=uuid.uuid4().hex,
        title=title,
        description="test",
        severity=severity,
        status=status,
        evidence={},
        mitre_attack_techniques=[],
        compliance_metadata=compliance or {"iso_27001": ["A.8.8"], "pci_dss": ["11.3.1"]},
        raw_source={},
        source_tool="nmap",
        first_seen_at=now,
        last_seen_at=now,
        created_at=now,
        updated_at=now,
    )
    v.asset = asset
    return v


def _service_with_data(
    vulns: list[Vulnerability], assets: list[Asset]
) -> ComplianceReportService:
    db = AsyncMock()

    async def _execute(stmt):  # noqa: ANN001
        result = MagicMock()
        # crude: first call vulnerabilities, second assets — based on call order
        if not hasattr(_execute, "n"):
            _execute.n = 0  # type: ignore[attr-defined]
        _execute.n += 1  # type: ignore[attr-defined]
        if _execute.n == 1:  # type: ignore[attr-defined]
            result.scalars.return_value.all.return_value = vulns
        else:
            result.scalars.return_value.all.return_value = assets
        return result

    db.execute = AsyncMock(side_effect=_execute)
    return ComplianceReportService(db)


def test_extract_controls() -> None:
    meta = {"iso_27001": ["A.8.8", "A.8.12"], "pci_dss": ["11.3.1"]}
    assert _extract_controls(meta, "iso_27001") == ["A.8.8", "A.8.12"]
    assert _extract_controls(meta, "pci_dss") == ["11.3.1"]


def test_is_gdpr_risk_flag_and_keywords() -> None:
    asset = _asset()
    flagged = _vuln(asset, compliance={"gdpr_risk_flag": True})
    assert _is_gdpr_risk(flagged, flagged.compliance_metadata) is True
    pii = _vuln(asset, title="PII leakage via API", compliance={})
    assert _is_gdpr_risk(pii, {}) is True


@pytest.mark.asyncio
async def test_iso27001_report_metadata_and_buckets() -> None:
    asset = _asset()
    vulns = [
        _vuln(asset, compliance={"iso_27001": ["A.8.8"]}),
        _vuln(
            asset,
            title="DLP gap",
            severity=Severity.MEDIUM,
            compliance={"iso_27001": ["A.8.12"]},
        ),
    ]
    service = _service_with_data(vulns, [asset])
    report = await service.generate_iso27001(_user())

    assert report.metadata.report_type == "iso27001"
    assert report.metadata.auditor_name == "Audit User"
    assert report.metadata.scope_total_assets == 1
    assert report.metadata.generated_at is not None
    assert report.metadata.export_format == "json_pdf_ready"
    assert len(report.sections) >= 2
    control_ids = {b.control_id for b in report.control_mapping}
    assert "A.8.8" in control_ids
    assert "A.8.12" in control_ids
    assert report.recommendations


@pytest.mark.asyncio
async def test_pci_dss_highlights_cde() -> None:
    cde = _asset(cde=True, name="cde-db")
    other = _asset(cde=False, name="corp-web")
    vulns = [
        _vuln(
            cde,
            title="CDE critical",
            severity=Severity.CRITICAL,
            compliance={"pci_dss": ["11.3.1"]},
        ),
        _vuln(
            other,
            title="Non-CDE low",
            severity=Severity.LOW,
            compliance={"pci_dss": ["11.3.1"]},
        ),
    ]
    service = _service_with_data(vulns, [cde, other])
    report = await service.generate_pci_dss(_user())

    assert report.metadata.report_type == "pci_dss"
    assert report.metadata.scope_cde_assets == 1
    assert report.metadata.standard.startswith("PCI DSS")
    cde_rows = [f for f in report.findings if f.is_cde_scope]
    assert any(f.title == "CDE critical" for f in cde_rows)
    # section table for CDE findings should include the critical item
    cde_table = next(
        t for s in report.sections for t in s.tables if t["name"] == "cde_findings"
    )
    assert any("CDE critical" in row for row in cde_table["rows"])


@pytest.mark.asyncio
async def test_gdpr_filters_to_relevant_findings() -> None:
    asset = _asset()
    vulns = [
        _vuln(
            asset,
            title="PII exposure",
            compliance={"gdpr_risk_flag": True, "gdpr": ["Art.32"]},
        ),
        _vuln(
            asset,
            title="Open port info",
            severity=Severity.INFO,
            compliance={"iso_27001": ["A.8.8"]},
        ),
    ]
    service = _service_with_data(vulns, [asset])
    report = await service.generate_gdpr(_user())

    assert report.metadata.report_type == "gdpr"
    assert len(report.findings) == 1
    assert report.findings[0].title == "PII exposure"
    assert any(b.control_id == "Art.32" for b in report.control_mapping)


@pytest.mark.asyncio
async def test_nist_csf_report_buckets() -> None:
    asset = _asset()
    vulns = [
        _vuln(
            asset,
            title="Open SSH",
            compliance={
                "nist_csf": ["ID.RA-01", "PR.AA-01"],
                "nist_800_53": ["RA-5", "AC-2"],
            },
        ),
        _vuln(
            asset,
            title="Weak TLS",
            severity=Severity.MEDIUM,
            compliance={
                "nist_csf": ["PR.DS-02"],
                "nist_800_53": ["SC-8"],
            },
        ),
    ]
    service = _service_with_data(vulns, [asset])
    report = await service.generate_nist_csf(_user())

    assert report.metadata.report_type == "nist_csf"
    assert "NIST" in report.metadata.standard
    control_ids = {b.control_id for b in report.control_mapping}
    assert "ID.RA-01" in control_ids
    assert "PR.DS-02" in control_ids
    assert len(report.findings) == 2
    assert report.recommendations
