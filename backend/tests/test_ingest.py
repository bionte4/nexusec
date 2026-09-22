"""Tests for FindingIngestionService deduplication."""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock

from app.core.enums import FindingStatus, Severity
from app.models.vulnerability import Vulnerability
from app.normalization.ingest import AssetResolver, FindingIngestionService
from app.normalization.schema import NormalizedFinding


def test_ingest_inserts_then_updates_on_duplicate() -> None:
    asset_id = uuid.uuid4()
    scan_id = uuid.uuid4()
    resolver = AssetResolver(by_key={"10.0.0.1": asset_id})

    finding = NormalizedFinding(
        vuln_id="nmap:open:tcp/22/ssh",
        name="Open port tcp/22 (ssh)",
        severity=Severity.INFO,
        port=22,
        protocol="tcp",
        source_tool="nmap",
        target_hint="10.0.0.1",
        iso_27001_clause=["A.8.8"],
        pci_dss_requirement=["11.3.1"],
    )

    session = MagicMock()
    # First call: no existing; second call: existing row
    org_id = uuid.uuid4()
    existing = Vulnerability(
        id=uuid.uuid4(),
        organization_id=org_id,
        scan_id=scan_id,
        asset_id=asset_id,
        fingerprint="deadbeef",
        title="old",
        severity=Severity.INFO,
        status=FindingStatus.REMEDIATED,
        evidence={},
        mitre_attack_techniques=[],
        compliance_metadata={},
        raw_source={},
    )

    execute_result_missing = MagicMock()
    execute_result_missing.scalar_one_or_none.return_value = None
    execute_result_hit = MagicMock()
    execute_result_hit.scalar_one_or_none.return_value = existing
    session.execute.side_effect = [execute_result_missing, execute_result_hit]

    svc = FindingIngestionService(session)
    stats1 = svc.ingest(
        scan_id=scan_id,
        findings=[finding],
        resolver=resolver,
        organization_id=org_id,
    )
    assert stats1.inserted == 1
    assert session.add.call_count == 1

    stats2 = svc.ingest(
        scan_id=uuid.uuid4(),
        findings=[finding],
        resolver=resolver,
        organization_id=org_id,
    )
    assert stats2.updated == 1
    assert existing.status == FindingStatus.REOPENED
    assert existing.title == finding.name


def test_ingest_skips_unmatched_targets() -> None:
    session = MagicMock()
    resolver = AssetResolver(by_key={})
    finding = NormalizedFinding(
        vuln_id="x",
        name="Something",
        source_tool="nmap",
        target_hint="9.9.9.9",
    )
    stats = FindingIngestionService(session).ingest(
        scan_id=uuid.uuid4(),
        findings=[finding],
        resolver=resolver,
        organization_id=uuid.uuid4(),
        default_asset_id=None,
    )
    assert stats.skipped == 1
    assert stats.unmatched_targets == ["9.9.9.9"]
    session.add.assert_not_called()
