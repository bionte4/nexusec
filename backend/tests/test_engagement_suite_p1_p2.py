"""P1/P2 standards: OWASP Top10 DAST suite, PTES/ASVS, SoD."""

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
from app.normalization.parsers.zap_json import ZapJsonParser
from app.services.engagement_approval_service import (
    EngagementApprovalError,
    EngagementApprovalService,
)
from app.services.engagement_pdf import render_engagement_pdf
from app.services.engagement_report_service import EngagementReportService
from app.services.engagement_standards import (
    OWASP_TOP10_2021,
    build_asvs_checklist,
    build_offline_owasp_dast_report,
    build_ptes_checklist,
    map_owasp_category,
)


def test_map_owasp_category_injection() -> None:
    assert map_owasp_category(title="SQL Injection", cwe_id="CWE-89") == "A03:2021"
    assert map_owasp_category(title="SSRF", cwe_id="918") == "A10:2021"
    assert map_owasp_category(explicit="A01:2021") == "A01:2021"


def test_offline_owasp_top10_dast_suite_covers_all_categories() -> None:
    raw = build_offline_owasp_dast_report(["https://app.example.test"], policy="owasp_top10")
    findings = ZapJsonParser().parse(raw)
    assert len(findings) == 10
    cats = {f.owasp_category for f in findings}
    expected = {row["id"] for row in OWASP_TOP10_2021}
    assert cats == expected
    assert all(f.source_tool == "zap" for f in findings)


def test_zap_wrapper_owasp_top10_policy() -> None:
    from workers.tool_wrappers.zap import ZapScanRequest, ZapWrapper

    result = ZapWrapper(mode="mock").run(
        ZapScanRequest(
            targets=["https://app.example.test"],
            mode="mock",
            scan_policy="owasp_top10",
            lab_mode=True,
        )
    )
    findings = ZapJsonParser().parse(result.stdout)
    assert len(findings) == 10


def test_ptes_and_asvs_checklists() -> None:
    now = datetime.now(timezone.utc)
    org = uuid.uuid4()
    scan = Scan(
        id=uuid.uuid4(),
        organization_id=org,
        name="disc",
        scan_type=ScanType.DISCOVERY,
        engine=ScannerEngine.NMAP,
        status=ScanStatus.COMPLETED,
        progress=100.0,
        config={"roe_acknowledged": True, "roe_id": "ROE-2026-001"},
        created_at=now,
        updated_at=now,
    )
    va = Scan(
        id=uuid.uuid4(),
        organization_id=org,
        name="dast",
        scan_type=ScanType.VA,
        engine=ScannerEngine.ZAP,
        status=ScanStatus.COMPLETED,
        progress=100.0,
        config={"zap_mode": "mock", "lab_mode": True, "roe_acknowledged": True},
        created_at=now,
        updated_at=now,
    )
    from app.schemas.reports import EngagementFindingRow

    rows = [
        EngagementFindingRow(
            vulnerability_id=uuid.uuid4(),
            title="SQL Injection",
            severity=Severity.HIGH,
            status=FindingStatus.CONFIRMED,
            asset_id=uuid.uuid4(),
            asset_name="web",
            cwe_id="CWE-89",
            source_tool="zap",
            first_seen_at=now,
            last_seen_at=now,
        )
    ]
    ptes = build_ptes_checklist(
        scans=[scan, va],
        rows=rows,
        eng_type="pt",
        dual_control_approved=False,
        delivery="draft",
        overrides={"ptes.threat_modeling": True},
    )
    assert ptes.metrics["done_count"] >= 4
    assert ptes.metrics["phases"]["ptes.threat_modeling"]["done"] is True
    assert ptes.metrics["phases"]["ptes.exploitation"]["done"] is True

    asvs = build_asvs_checklist(rows=rows, scans=[scan, va])
    assert asvs.metrics["chapters"]["V5"]["done"] is True
    assert "A03:2021" in asvs.metrics["owasp_categories_seen"]


@pytest.mark.asyncio
async def test_sod_blocks_scan_creator_approve() -> None:
    org = uuid.uuid4()
    creator = uuid.uuid4()
    now = datetime.now(timezone.utc)
    admin = User(
        id=creator,
        email="same@nexusec.local",
        full_name="Creator Admin",
        hashed_password="x",
        role=UserRole.ADMIN,
        organization_id=org,
        is_active=True,
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
        config={},
        created_by_id=creator,
        created_at=now,
        updated_at=now,
    )
    db = AsyncMock()
    db.execute = AsyncMock(
        return_value=MagicMock(scalar_one_or_none=MagicMock(return_value=scan))
    )
    svc = EngagementApprovalService(db)
    with pytest.raises(EngagementApprovalError, match="Separation of duties"):
        await svc.approve(admin, organization_id=org, scan_id=scan.id)


@pytest.mark.asyncio
async def test_international_suite_offline_engagement_e2e() -> None:
    """Discovery → VA → offline OWASP DAST → human confirm → SoD → draft/client PDF.

    No external nmap/nuclei/zaproxy/GVM — fixtures + mock DAST suite only.
    """
    org = uuid.uuid4()
    creator = uuid.uuid4()
    approver = uuid.uuid4()
    now = datetime.now(timezone.utc)
    asset = Asset(
        id=uuid.uuid4(),
        organization_id=org,
        name="app",
        asset_type=AssetType.DOMAIN,
        criticality=AssetCriticality.HIGH,
        domain="app.example.test",
        url="https://app.example.test",
        is_cde_scope=False,
        tags={},
        metadata_={},
        created_at=now,
        updated_at=now,
    )
    disc = Scan(
        id=uuid.uuid4(),
        organization_id=org,
        name="Discovery",
        scan_type=ScanType.DISCOVERY,
        engine=ScannerEngine.NMAP,
        status=ScanStatus.COMPLETED,
        progress=100.0,
        config={
            "roe_acknowledged": True,
            "roe_id": "ROE-E2E-001",
            "last_result": {"tool_version": "Nmap version 7.94 (fixture)"},
        },
        created_by_id=creator,
        created_at=now,
        updated_at=now,
    )
    disc.assets = [asset]
    dast_json = build_offline_owasp_dast_report(
        ["https://app.example.test"], policy="owasp_top10"
    )
    dast = Scan(
        id=uuid.uuid4(),
        organization_id=org,
        name="DAST OWASP Top10",
        scan_type=ScanType.PT,
        engine=ScannerEngine.ZAP,
        status=ScanStatus.COMPLETED,
        progress=100.0,
        config={
            "roe_acknowledged": True,
            "roe_id": "ROE-E2E-001",
            "zap_mode": "mock",
            "zap_policy": "owasp_top10",
            "lab_mode": True,
            "ptes_checklist": {"ptes.post_exploitation": False},
            "asvs_checklist": {"V1": True},
            "last_result": {"stdout_json": dast_json},
        },
        created_by_id=creator,
        created_at=now,
        updated_at=now,
    )
    dast.assets = [asset]

    findings_parsed = ZapJsonParser().parse(dast_json)
    vulns: list[Vulnerability] = []
    for i, f in enumerate(findings_parsed):
        status = FindingStatus.CONFIRMED if i < 2 else FindingStatus.OPEN
        v = Vulnerability(
            id=uuid.uuid4(),
            organization_id=org,
            scan_id=dast.id,
            asset_id=asset.id,
            fingerprint=uuid.uuid4().hex,
            title=f.name,
            description=f.description or f.name,
            severity=f.severity,
            status=status,
            cwe_id=f.cwe_id,
            owasp_category=f.owasp_category,
            evidence={"nexusec_mock": True, "suite": "owasp_top10"},
            mitre_attack_techniques=[],
            compliance_metadata={},
            raw_source={},
            source_tool="zap",
            last_retest_scan_id=disc.id if status == FindingStatus.CONFIRMED else None,
            first_seen_at=now,
            last_seen_at=now,
            created_at=now,
            updated_at=now,
        )
        v.asset = asset
        vulns.append(v)

    user = User(
        id=approver,
        email="lead@nexusec.local",
        full_name="Lead Approver",
        hashed_password="x",
        role=UserRole.ADMIN,
        organization_id=org,
        is_active=True,
        created_at=now,
        updated_at=now,
    )

    from app.models.engagement_approval import EngagementApproval

    approval = EngagementApproval(
        id=uuid.uuid4(),
        organization_id=org,
        scan_id=dast.id,
        approved_by_id=approver,
        approved_at=now,
    )

    db = AsyncMock()
    call_n = {"n": 0}

    async def _execute(stmt):  # noqa: ANN001
        result = MagicMock()
        call_n["n"] += 1
        n = call_n["n"]
        # Pattern mirrors engagement generate: scans → vulns → approval
        phase = ((n - 1) % 3) + 1
        if phase == 1:
            result.scalars.return_value.all.return_value = [disc, dast]
            result.scalar_one_or_none.return_value = approval
        elif phase == 2:
            result.scalars.return_value.all.return_value = vulns
            result.scalar_one_or_none.return_value = approval
        else:
            result.scalars.return_value.all.return_value = [asset]
            result.scalar_one_or_none.return_value = approval
        return result

    db.execute = AsyncMock(side_effect=_execute)
    report = await EngagementReportService(db).generate(
        user,
        scan_id=dast.id,
        engagement_type="pt",
        delivery="draft",
        allow_mock=True,
    )
    assert report.ptes_checklist.metrics["standard"] == "PTES"
    assert report.asvs_checklist.metrics["chapters"]["V1"]["done"] is True
    assert report.asvs_checklist.metrics["done_count"] >= 1
    assert any(s.roe_id == "ROE-E2E-001" for s in report.scans)
    assert report.playbook.metrics["pt_validation_done"] is True
    assert report.dual_control["sod"] == "approver_must_differ_from_scan_creator"
    assert "PTES" in report.ptes_checklist.heading
    assert "ASVS" in report.asvs_checklist.heading
    pdf = render_engagement_pdf(report)
    assert pdf[:4] == b"%PDF"
    assert len(pdf) > 1000
