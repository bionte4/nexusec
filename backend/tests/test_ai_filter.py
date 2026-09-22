"""Tests for AI false-positive analysis engine."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from app.core.config import Settings
from app.core.enums import AssetCriticality, AssetType, FindingStatus, Severity
from app.models.asset import Asset
from app.models.vulnerability import Vulnerability
from app.services.ai_filter import (
    AIFPAnalysisService,
    FPAnalysisContext,
    _extract_json,
    _normalize_payload,
    extract_banner,
    mock_fp_analysis,
)
from app.services.vulnerability_service import VulnerabilityService


def test_extract_banner_from_evidence() -> None:
    assert extract_banner({"banner": "OpenSSH_8.9"}) == "OpenSSH_8.9"
    assert extract_banner({"service_info": {"product": "nginx/1.24"}}) == "nginx/1.24"
    assert extract_banner({}) is None


def test_extract_json_and_normalize() -> None:
    raw = """```json
{"confidence_score": 0.91, "is_likely_false_positive": true, "reasoning": "Banner mismatch"}
```"""
    data = _normalize_payload(_extract_json(raw))
    assert data["confidence_score"] == 0.91
    assert data["is_likely_false_positive"] is True
    assert "Banner" in data["reasoning"]


def test_normalize_clamps_score() -> None:
    data = _normalize_payload(
        {"confidence_score": 1.5, "is_likely_false_positive": False, "reasoning": "ok"}
    )
    assert data["confidence_score"] == 1.0


def test_mock_fp_info_severity_likely_fp() -> None:
    ctx = FPAnalysisContext(
        title="Possible SSL best practice",
        description="Informational finding",
        cwe_id=None,
        severity=Severity.INFO,
        banner="Apache/2.4",
        port=443,
    )
    result = mock_fp_analysis(ctx)
    assert result.is_likely_false_positive is True
    assert 0.0 <= result.confidence_score <= 1.0
    assert result.provider == "mock"


def test_mock_fp_kev_is_true_positive() -> None:
    ctx = FPAnalysisContext(
        title="Remote code execution",
        description="RCE",
        cwe_id="CWE-94",
        severity=Severity.CRITICAL,
        cve_id="CVE-2024-1234",
        is_actively_exploited=True,
    )
    result = mock_fp_analysis(ctx)
    assert result.is_likely_false_positive is False
    assert result.confidence_score >= 0.8


def test_resolve_provider_auto_mock() -> None:
    settings = Settings(openai_api_key="", anthropic_api_key="", ai_fp_provider="auto")
    assert AIFPAnalysisService(settings).resolve_provider() == "mock"


@pytest.mark.asyncio
async def test_analyze_openai_success() -> None:
    settings = Settings(
        ai_fp_provider="openai",
        openai_api_key="sk-test",
        ai_fp_fallback_mock=False,
    )
    svc = AIFPAnalysisService(settings)
    payload = {
        "choices": [
            {
                "message": {
                    "content": json.dumps(
                        {
                            "confidence_score": 0.82,
                            "is_likely_false_positive": True,
                            "reasoning": "Version string does not match CVE applicability.",
                        }
                    )
                }
            }
        ]
    }
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = payload
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.post = AsyncMock(return_value=mock_resp)

    ctx = FPAnalysisContext(
        title="Outdated OpenSSL",
        description="CVE match",
        cwe_id="CWE-1104",
        severity=Severity.HIGH,
        banner="OpenSSL 3.0.2",
        port=443,
    )
    with patch("app.services.ai_filter.httpx.AsyncClient", return_value=mock_client):
        result = await svc.analyze(ctx)
    assert result.provider == "openai"
    assert result.is_likely_false_positive is True
    assert result.confidence_score == 0.82


@pytest.mark.asyncio
async def test_analyze_falls_back_to_mock_on_error() -> None:
    settings = Settings(
        ai_fp_provider="openai",
        openai_api_key="sk-test",
        ai_fp_fallback_mock=True,
    )
    svc = AIFPAnalysisService(settings)
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.post = AsyncMock(side_effect=RuntimeError("network"))

    ctx = FPAnalysisContext(
        title="XSS",
        description="reflected",
        cwe_id="CWE-79",
        severity=Severity.MEDIUM,
    )
    with patch("app.services.ai_filter.httpx.AsyncClient", return_value=mock_client):
        result = await svc.analyze(ctx)
    assert result.provider == "mock"


@pytest.mark.asyncio
async def test_vulnerability_service_analyze_fp_persists() -> None:
    org_id = uuid4()
    now = datetime.now(timezone.utc)
    asset = Asset(
        id=uuid4(),
        organization_id=org_id,
        name="edge-gw",
        asset_type=AssetType.IP,
        criticality=AssetCriticality.HIGH,
        is_cde_scope=False,
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
        fingerprint="fp-fp",
        title="Possible informational TLS finding",
        description="Best practice only",
        severity=Severity.INFO,
        status=FindingStatus.OPEN,
        port=443,
        protocol="tcp",
        evidence={"banner": "nginx/1.24.0"},
        mitre_attack_techniques=[],
        compliance_metadata={},
        raw_source={},
        threat_intel_metadata={},
        first_seen_at=now,
        last_seen_at=now,
        created_at=now,
        updated_at=now,
    )
    vuln.asset = asset
    vuln.comments = []

    db = AsyncMock()
    result_proxy = MagicMock()
    result_proxy.scalar_one_or_none.return_value = vuln
    db.execute = AsyncMock(return_value=result_proxy)
    db.flush = AsyncMock()
    db.refresh = AsyncMock()

    service = VulnerabilityService(db)
    resp = await service.analyze_false_positive(vuln.id, organization_id=org_id, persist=True)

    assert resp.provider == "mock"
    assert "ai_fp_analysis" in vuln.threat_intel_metadata
    meta = vuln.threat_intel_metadata["ai_fp_analysis"]
    assert "confidence_score" in meta
    assert "is_likely_false_positive" in meta
    assert meta["banner"] == "nginx/1.24.0"
    assert resp.vulnerability_id == vuln.id
    assert 0.0 <= resp.confidence_score <= 1.0
