"""Tests for VA/PT engagement report generation."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core.enums import (
    AssetCriticality,
    AssetType,
    FindingStatus,
    ScanStatus,
    ScanType,
    ScannerEngine,
    Severity,
    UserRole,
)
from app.models.asset import Asset
from app.models.scan import Scan
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.services.engagement_pdf import render_engagement_pdf
from app.services.engagement_report_service import EngagementReportService


def _user(org_id: uuid.UUID | None = None) -> User:
    now = datetime.now(timezone.utc)
    return User(
        id=uuid.uuid4(),
        email="pentester@nexusec.local",
        full_name="PT Lead",
        hashed_password="x",
        role=UserRole.PENTESTER,
        organization_id=org_id or uuid.uuid4(),
        is_active=True,
        created_at=now,
        updated_at=now,
    )


def _asset(org_id: uuid.UUID, *, name: str = "web-1") -> Asset:
    now = datetime.now(timezone.utc)
    return Asset(
        id=uuid.uuid4(),
        organization_id=org_id,
        name=name,
        asset_type=AssetType.DOMAIN,
        criticality=AssetCriticality.HIGH,
        ip_address=None,
        domain="example.test",
        cloud_resource_id=None,
        cloud_provider=None,
        is_cde_scope=False,
        hostname=None,
        url="https://example.test",
        environment="staging",
        owner=None,
        description=None,
        tags={},
        metadata_={},
        created_by_id=None,
        created_at=now,
        updated_at=now,
    )


def _scan(org_id: uuid.UUID, assets: list[Asset], *, scan_type: ScanType = ScanType.VA) -> Scan:
    now = datetime.now(timezone.utc)
    scan = Scan(
        id=uuid.uuid4(),
        organization_id=org_id,
        name="VA wave-1",
        scan_type=scan_type,
        engine=ScannerEngine.NUCLEI,
        status=ScanStatus.COMPLETED,
        progress=100.0,
        config={"notes": "Authorized lab only", "roe_acknowledged": True},
        celery_task_id=None,
        error_message=None,
        started_at=now,
        completed_at=now,
        created_by_id=None,
        created_at=now,
        updated_at=now,
    )
    scan.assets = assets
    return scan


def _vuln(
    org_id: uuid.UUID,
    scan: Scan,
    asset: Asset,
    *,
    title: str = "Reflected XSS",
    severity: Severity = Severity.HIGH,
    status: FindingStatus = FindingStatus.OPEN,
    remediation: str | None = "Encode output; enable CSP.",
    last_retest_scan_id: uuid.UUID | None = None,
    evidence: dict | None = None,
) -> Vulnerability:
    now = datetime.now(timezone.utc)
    v = Vulnerability(
        id=uuid.uuid4(),
        organization_id=org_id,
        scan_id=scan.id,
        asset_id=asset.id,
        fingerprint=uuid.uuid4().hex,
        title=title,
        description="test finding",
        severity=severity,
        status=status,
        cwe_id="CWE-79",
        evidence=evidence or {"url": "https://example.test/search?q=1"},
        mitre_attack_techniques=[],
        compliance_metadata={"iso_27001": ["A.8.8"]},
        raw_source={},
        source_tool="nuclei",
        remediation=remediation,
        last_retest_scan_id=last_retest_scan_id,
        first_seen_at=now,
        last_seen_at=now,
        created_at=now,
        updated_at=now,
    )
    v.asset = asset
    return v


def _service(
    scans: list[Scan],
    vulns: list[Vulnerability],
    assets: list[Asset],
) -> EngagementReportService:
    db = AsyncMock()

    async def _execute(stmt):  # noqa: ANN001
        result = MagicMock()
        if not hasattr(_execute, "n"):
            _execute.n = 0  # type: ignore[attr-defined]
        _execute.n += 1  # type: ignore[attr-defined]
        n = _execute.n  # type: ignore[attr-defined]
        # Default: no engagement approval row
        result.scalar_one_or_none.return_value = None
        if n == 1:
            result.scalars.return_value.all.return_value = scans
        elif n == 2:
            result.scalars.return_value.all.return_value = vulns
        else:
            # Extra loads (assets) or approval lookups
            result.scalars.return_value.all.return_value = assets
        return result

    db.execute = AsyncMock(side_effect=_execute)
    return EngagementReportService(db)


@pytest.mark.asyncio
async def test_engagement_report_includes_scope_and_top_findings() -> None:
    user = _user()
    org_id = user.organization_id
    assert org_id is not None
    asset = _asset(org_id)
    scan = _scan(org_id, [asset], scan_type=ScanType.VA)
    vulns = [
        _vuln(org_id, scan, asset, title="SQLi", severity=Severity.CRITICAL),
        _vuln(org_id, scan, asset, title="XSS", severity=Severity.HIGH),
        _vuln(
            org_id,
            scan,
            asset,
            title="Info banner",
            severity=Severity.INFO,
            status=FindingStatus.FALSE_POSITIVE,
            remediation=None,
        ),
    ]
    svc = _service([scan], vulns, [asset])
    report = await svc.generate(user, scan_id=scan.id)

    assert report.engagement_type == "va"
    assert report.metadata.report_type == "engagement"
    assert report.severity_summary["critical"] == 1
    assert report.severity_summary["high"] == 1
    assert report.top_findings[0].severity == Severity.CRITICAL
    assert len(report.scans) == 1
    assert "Authorized lab" in (report.metadata.scope_notes or "")
    assert report.remediation_highlights
    pdf = render_engagement_pdf(report)
    assert pdf[:4] == b"%PDF"


@pytest.mark.asyncio
async def test_engagement_report_pt_recommendations() -> None:
    user = _user()
    org_id = user.organization_id
    assert org_id is not None
    asset = _asset(org_id)
    scan = _scan(org_id, [asset], scan_type=ScanType.PT)
    scan.name = "PT auth wave"
    vulns = [
        _vuln(
            org_id,
            scan,
            asset,
            title="Auth bypass",
            severity=Severity.HIGH,
            status=FindingStatus.CONFIRMED,
        )
    ]
    svc = _service([scan], vulns, [asset])
    report = await svc.generate(user, engagement_type="pt")
    assert report.engagement_type == "pt"
    assert any("manual validation" in r.lower() for r in report.recommendations)
    assert "Penetration Testing" in report.metadata.title


@pytest.mark.asyncio
async def test_engagement_verification_matrix_and_classification() -> None:
    user = _user()
    org_id = user.organization_id
    assert org_id is not None
    asset = _asset(org_id)
    scan = _scan(org_id, [asset], scan_type=ScanType.VA)
    retest_id = uuid.uuid4()
    vulns = [
        _vuln(
            org_id,
            scan,
            asset,
            title="SQLi closed with retest",
            severity=Severity.CRITICAL,
            status=FindingStatus.REMEDIATED,
            last_retest_scan_id=retest_id,
        ),
        _vuln(
            org_id,
            scan,
            asset,
            title="XSS closed without retest",
            severity=Severity.HIGH,
            status=FindingStatus.RESOLVED,
        ),
        _vuln(
            org_id,
            scan,
            asset,
            title="Open High no retest",
            severity=Severity.HIGH,
            status=FindingStatus.OPEN,
        ),
    ]
    svc = _service([scan], vulns, [asset])
    report = await svc.generate(user, scan_id=scan.id)

    assert report.classification.startswith("Internal Draft")
    assert report.limitations.heading.startswith("Limitations")
    assert report.playbook.heading.startswith("PT/VA playbook")
    assert report.verification_matrix
    states = {r.verification_state for r in report.findings}
    assert "closed_with_retest" in states
    assert "closed_without_retest" in states
    assert "unverified" in states
    assert any(r.evidence_excerpt for r in report.findings)
    assert report.retest_summary.metrics.get("closed_without_retest") == 1
    assert any("Verification gaps" in w for w in report.export_warnings)
    pdf = render_engagement_pdf(report)
    assert pdf[:4] == b"%PDF"
    assert len(pdf) > 500
