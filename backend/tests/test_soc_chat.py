"""Tests for SOC ChatOps / RAG assistant."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

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
from app.services.soc_chat import (
    RAGContext,
    RetrievalIntent,
    SocChatService,
    classify_intent,
    mock_answer,
)


def test_classify_intent_pci() -> None:
    intent = classify_intent("Which assets currently violate PCI-DSS requirements?")
    assert intent.pci_dss is True
    assert intent.assets is True


def test_classify_intent_critical_week() -> None:
    intent = classify_intent("Summarize critical vulnerabilities this week")
    assert intent.critical is True
    assert intent.this_week is True
    assert intent.vulnerabilities is True


def test_classify_intent_kev() -> None:
    intent = classify_intent("Show KEV actively exploited findings")
    assert intent.kev is True


def test_mock_answer_includes_stats() -> None:
    rag = RAGContext(
        intent=RetrievalIntent(critical=True),
        snippets=["- critical | OpenSSH | asset=gw"],
        stats={
            "active_findings_total": 3,
            "active_findings_by_severity": {"critical": 1, "high": 2},
        },
        sources=[{"type": "vulnerability", "id": "1", "title": "OpenSSH"}],
    )
    answer = mock_answer("Summarize critical vulnerabilities", rag)
    assert "Active findings" in answer
    assert "OpenSSH" in answer
    assert "Recommended actions" in answer


@pytest.mark.asyncio
async def test_chat_mock_provider_with_empty_db() -> None:
    settings = Settings(
        openai_api_key="",
        anthropic_api_key="",
        ai_soc_chat_provider="auto",
    )
    db = AsyncMock()

    # severity count
    sev_result = MagicMock()
    sev_result.all.return_value = [(Severity.CRITICAL, 2), (Severity.HIGH, 1)]

    # vuln list
    vuln_result = MagicMock()
    vuln_result.scalars.return_value.all.return_value = []

    # keyword hits (may or may not be called)
    empty_result = MagicMock()
    empty_result.scalars.return_value.all.return_value = []
    empty_result.all.return_value = []

    db.execute = AsyncMock(side_effect=[sev_result, vuln_result, empty_result, empty_result])

    service = SocChatService(db, organization_id=uuid4(), settings=settings)
    result = await service.chat("Summarize critical vulnerabilities this week")
    assert result.provider == "mock"
    assert result.intent_flags["critical"] is True
    assert result.intent_flags["this_week"] is True
    assert "Active findings" in result.answer
    assert result.stats["active_findings_total"] == 3


@pytest.mark.asyncio
async def test_retrieve_pci_cde_context() -> None:
    settings = Settings(ai_soc_chat_provider="mock")
    org_id = uuid4()
    now = datetime.now(timezone.utc)
    asset = Asset(
        id=uuid4(),
        organization_id=org_id,
        name="pos-db",
        asset_type=AssetType.IP,
        criticality=AssetCriticality.CRITICAL,
        is_cde_scope=True,
        tags={},
        metadata_={},
        created_at=now,
        updated_at=now,
    )
    vuln = Vulnerability(
        id=uuid4(),
        organization_id=org_id,
        scan_id=uuid4(),
        asset_id=asset.id,
        fingerprint="fp1",
        title="Weak TLS on payment DB",
        description="PCI scope",
        severity=Severity.HIGH,
        status=FindingStatus.OPEN,
        evidence={},
        mitre_attack_techniques=[],
        compliance_metadata={"pci_dss": ["Req 11"]},
        raw_source={},
        threat_intel_metadata={},
        first_seen_at=now,
        last_seen_at=now,
        created_at=now,
        updated_at=now,
    )
    vuln.asset = asset

    db = AsyncMock()

    sev_result = MagicMock()
    sev_result.all.return_value = [(Severity.HIGH, 1)]

    cde_count = MagicMock()
    # scalar path used via db.scalar
    db.scalar = AsyncMock(return_value=1)

    cde_vuln_result = MagicMock()
    cde_vuln_result.all.return_value = [(vuln, asset)]

    cde_assets_result = MagicMock()
    cde_assets_result.scalars.return_value.all.return_value = [asset]

    active_vulns = MagicMock()
    active_vulns.scalars.return_value.all.return_value = [vuln]

    keyword = MagicMock()
    keyword.scalars.return_value.all.return_value = []

    db.execute = AsyncMock(
        side_effect=[
            sev_result,
            cde_vuln_result,
            cde_assets_result,
            active_vulns,
            keyword,
        ]
    )

    service = SocChatService(db, organization_id=org_id, settings=settings)
    rag = await service.retrieve("Which assets violate PCI-DSS?")
    assert rag.intent.pci_dss is True
    assert rag.stats.get("cde_assets") == 1
    assert any("CDE" in s or "pos-db" in s for s in rag.snippets)
    assert any(s.get("tag") == "cde" for s in rag.sources)


@pytest.mark.asyncio
async def test_chat_openai_success() -> None:
    settings = Settings(
        ai_soc_chat_provider="openai",
        openai_api_key="sk-test",
        ai_soc_chat_fallback_mock=False,
    )
    db = AsyncMock()
    sev_result = MagicMock()
    sev_result.all.return_value = []
    empty = MagicMock()
    empty.scalars.return_value.all.return_value = []
    empty.all.return_value = []
    db.execute = AsyncMock(return_value=empty)
    # First execute is severity group — need proper all()
    db.execute = AsyncMock(side_effect=[sev_result, empty, empty])

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "choices": [{"message": {"content": "Two critical findings need owners assigned."}}]
    }
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.post = AsyncMock(return_value=mock_resp)

    service = SocChatService(db, organization_id=uuid4(), settings=settings)
    with patch("app.services.soc_chat.httpx.AsyncClient", return_value=mock_client):
        result = await service.chat("Summarize critical vulnerabilities")
    assert result.provider == "openai"
    assert "critical findings" in result.answer.lower()


@pytest.mark.asyncio
async def test_chat_rejects_short_query() -> None:
    settings = Settings(ai_soc_chat_provider="mock")
    service = SocChatService(AsyncMock(), settings=settings)
    with pytest.raises(Exception) as exc:
        await service.chat("hi")
    assert getattr(exc.value, "status_code", None) == 400


@pytest.mark.asyncio
async def test_retrieve_scans() -> None:
    settings = Settings(ai_soc_chat_provider="mock")
    org_id = uuid4()
    now = datetime.now(timezone.utc)
    scan = Scan(
        id=uuid4(),
        organization_id=org_id,
        name="Weekly external",
        scan_type=ScanType.VA,
        engine=ScannerEngine.NEXUSEC,
        status=ScanStatus.COMPLETED,
        progress=1.0,
        config={},
        created_at=now,
        updated_at=now,
    )
    db = AsyncMock()
    sev_result = MagicMock()
    sev_result.all.return_value = []
    assets_empty = MagicMock()
    assets_empty.scalars.return_value.all.return_value = []
    scans_result = MagicMock()
    scans_result.scalars.return_value.all.return_value = [scan]
    db.execute = AsyncMock(
        side_effect=[sev_result, assets_empty, scans_result]
    )

    service = SocChatService(db, organization_id=org_id, settings=settings)
    rag = await service.retrieve("Show recent scans and asset inventory")
    assert rag.intent.scans is True
    assert any("Weekly external" in s for s in rag.snippets)
