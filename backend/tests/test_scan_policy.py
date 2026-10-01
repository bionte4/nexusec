"""Tests for RoE / mock engagement export policy gates."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from app.core.config import Settings
from app.core.enums import (
    AssetCriticality,
    AssetType,
    FindingStatus,
    ScanStatus,
    ScanType,
    ScannerEngine,
    Severity,
)
from app.models.asset import Asset
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.services.scan_policy import (
    EngagementExportBlocked,
    assert_engagement_export_allowed,
    assert_roe_for_scan,
    is_mock_scan_config,
    is_synthetic_finding,
)


def test_roe_required_by_default() -> None:
    with pytest.raises(ValueError, match="roe_acknowledged"):
        assert_roe_for_scan({}, settings=Settings(app_env="production"))


def test_roe_ok_when_acknowledged() -> None:
    assert_roe_for_scan(
        {"roe_acknowledged": True},
        settings=Settings(app_env="production"),
    )


def test_lab_mode_only_outside_production() -> None:
    assert_roe_for_scan(
        {"lab_mode": True},
        settings=Settings(app_env="development"),
    )
    with pytest.raises(ValueError, match="roe_acknowledged"):
        assert_roe_for_scan(
            {"lab_mode": True},
            settings=Settings(app_env="production"),
        )


def test_zap_mock_detection() -> None:
    assert is_mock_scan_config(ScannerEngine.ZAP, {"zap_mode": "mock"}) is True
    assert (
        is_mock_scan_config(
            ScannerEngine.ZAP, {"zap_mode": "mock", "report_json": '{"site":[]}'}
        )
        is False
    )
    assert (
        is_mock_scan_config(
            ScannerEngine.ZAP, {"imported": True, "zap_mode": "import"}
        )
        is False
    )
    assert (
        is_mock_scan_config(
            ScannerEngine.OPENVAS, {"imported": True, "openvas_mode": "import"}
        )
        is False
    )


def test_engagement_blocks_synthetic_findings() -> None:
    now = datetime.now(timezone.utc)
    org = uuid.uuid4()
    asset = Asset(
        id=uuid.uuid4(),
        organization_id=org,
        name="lab",
        asset_type=AssetType.DOMAIN,
        criticality=AssetCriticality.MEDIUM,
        domain="lab.test",
        is_cde_scope=False,
        tags={},
        metadata_={},
        created_at=now,
        updated_at=now,
    )
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
        asset_id=asset.id,
        fingerprint="x",
        title="XSS",
        description="nexusec_mock alert",
        severity=Severity.HIGH,
        status=FindingStatus.OPEN,
        evidence={"nexusec_mock": True},
        mitre_attack_techniques=[],
        compliance_metadata={},
        raw_source={},
        first_seen_at=now,
        last_seen_at=now,
        created_at=now,
        updated_at=now,
    )
    assert is_synthetic_finding(vuln) is True
    with pytest.raises(EngagementExportBlocked):
        assert_engagement_export_allowed([scan], [vuln], allow_mock=False)
    info = assert_engagement_export_allowed([scan], [vuln], allow_mock=True)
    assert info["warning"]
    assert info["synthetic_finding_count"] == 1
