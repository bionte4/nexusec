"""P3: dual-control approval, playbook checklist, PCI CDE-only."""

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
from app.models.engagement_approval import EngagementApproval
from app.models.scan import Scan
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.services.engagement_approval_service import (
    EngagementApprovalError,
    EngagementApprovalService,
)
from app.services.engagement_pdf import render_engagement_pdf
from app.services.engagement_report_service import EngagementReportService


def _admin(org_id: uuid.UUID) -> User:
    now = datetime.now(timezone.utc)
    return User(
        id=uuid.uuid4(),
        email="lead@nexusec.local",
        full_name="PT Lead",
        hashed_password="x",
        role=UserRole.ADMIN,
        organization_id=org_id,
        is_active=True,
        created_at=now,
        updated_at=now,
    )


def _pentester(org_id: uuid.UUID) -> User:
    now = datetime.now(timezone.utc)
    return User(
        id=uuid.uuid4(),
        email="pt@nexusec.local",
        full_name="Pentester",
        hashed_password="x",
        role=UserRole.PENTESTER,
        organization_id=org_id,
        is_active=True,
        created_at=now,
        updated_at=now,
    )


@pytest.mark.asyncio
async def test_dual_control_approve_requires_admin() -> None:
    org = uuid.uuid4()
    db = AsyncMock()
    db.execute = AsyncMock(
        return_value=MagicMock(scalar_one_or_none=MagicMock(return_value=None))
    )
    svc = EngagementApprovalService(db)
    with pytest.raises(EngagementApprovalError):
        await svc.approve(_pentester(org), organization_id=org)


@pytest.mark.asyncio
async def test_client_delivery_blocked_without_approval() -> None:
    org = uuid.uuid4()
    user = _pentester(org)
    now = datetime.now(timezone.utc)
    asset = Asset(
        id=uuid.uuid4(),
        organization_id=org,
        name="web",
        asset_type=AssetType.DOMAIN,
        criticality=AssetCriticality.HIGH,
        domain="example.test",
        is_cde_scope=False,
        tags={},
        metadata_={},
        created_at=now,
        updated_at=now,
    )
    scan = Scan(
        id=uuid.uuid4(),
        organization_id=org,
        name="VA",
        scan_type=ScanType.VA,
        engine=ScannerEngine.NUCLEI,
        status=ScanStatus.COMPLETED,
        progress=100.0,
        config={"roe_acknowledged": True},
        created_at=now,
        updated_at=now,
    )
    scan.assets = [asset]
    vuln = Vulnerability(
        id=uuid.uuid4(),
        organization_id=org,
        scan_id=scan.id,
        asset_id=asset.id,
        fingerprint=uuid.uuid4().hex,
        title="XSS",
        description="x",
        severity=Severity.HIGH,
        status=FindingStatus.CONFIRMED,
        evidence={},
        mitre_attack_techniques=[],
        compliance_metadata={},
        raw_source={},
        source_tool="nuclei",
        first_seen_at=now,
        last_seen_at=now,
        created_at=now,
        updated_at=now,
    )
    vuln.asset = asset

    db = AsyncMock()
    call_n = {"n": 0}

    async def _execute(stmt):  # noqa: ANN001
        result = MagicMock()
        call_n["n"] += 1
        n = call_n["n"]
        result.scalar_one_or_none.return_value = None
        # Each generate(): scans, vulns, then approval lookup(s)
        phase = ((n - 1) % 3) + 1
        if phase == 1:
            result.scalars.return_value.all.return_value = [scan]
        elif phase == 2:
            result.scalars.return_value.all.return_value = [vuln]
        else:
            result.scalars.return_value.all.return_value = [asset]
        return result

    db.execute = AsyncMock(side_effect=_execute)
    svc = EngagementReportService(db)

    with pytest.raises(ValueError, match="dual-control"):
        await svc.generate(user, scan_id=scan.id, delivery="client")

    report = await svc.generate(user, scan_id=scan.id, delivery="draft")
    assert report.delivery == "draft"
    assert report.classification.startswith("Internal Draft")
    assert report.playbook.heading.startswith("PT/VA playbook")
    assert report.dual_control["approved"] is False
    pdf = render_engagement_pdf(report)
    assert pdf[:4] == b"%PDF"


@pytest.mark.asyncio
async def test_draft_allows_mock_with_warning() -> None:
    """Draft PDF must not hard-block mock jobs; Client PDF still does."""
    from app.services.scan_policy import EngagementExportBlocked, assert_engagement_export_allowed

    org = uuid.uuid4()
    now = datetime.now(timezone.utc)
    scan = Scan(
        id=uuid.uuid4(),
        organization_id=org,
        name="zap mock",
        scan_type=ScanType.VA,
        engine=ScannerEngine.ZAP,
        status=ScanStatus.COMPLETED,
        progress=100.0,
        config={"zap_mode": "mock", "roe_acknowledged": True},
        created_at=now,
        updated_at=now,
    )
    vuln = Vulnerability(
        id=uuid.uuid4(),
        organization_id=org,
        scan_id=scan.id,
        asset_id=uuid.uuid4(),
        fingerprint=uuid.uuid4().hex,
        title="ZAP mock XSS",
        description="synthetic dast",
        severity=Severity.MEDIUM,
        status=FindingStatus.OPEN,
        evidence={"nexusec_mock": True},
        mitre_attack_techniques=[],
        compliance_metadata={},
        raw_source={},
        source_tool="zap",
        first_seen_at=now,
        last_seen_at=now,
        created_at=now,
        updated_at=now,
    )
    with pytest.raises(EngagementExportBlocked):
        assert_engagement_export_allowed([scan], [vuln], allow_mock=False)
    info = assert_engagement_export_allowed([scan], [vuln], allow_mock=True)
    assert info["mock_scan_count"] == 1
    assert info["synthetic_finding_count"] == 1
    assert info.get("warning")


@pytest.mark.asyncio
async def test_assert_client_delivery_with_approval() -> None:
    svc = EngagementApprovalService(AsyncMock())
    approval = EngagementApproval(
        id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        approved_by_id=uuid.uuid4(),
        approved_at=datetime.now(timezone.utc),
    )
    svc.assert_client_delivery_allowed(approval, delivery="client")
    with pytest.raises(EngagementApprovalError):
        svc.assert_client_delivery_allowed(None, delivery="client")
