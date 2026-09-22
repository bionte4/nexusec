"""Tests for AI remediation / OpenAI-compatible patch generator (Prompt 14/17)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from openai import APITimeoutError, RateLimitError

from app.core.config import Settings
from app.core.enums import AssetCriticality, AssetType, FindingStatus, Severity
from app.models.asset import Asset
from app.models.vulnerability import Vulnerability
from app.services.ai_remediation import (
    AIRemediationError,
    AIRemediationService,
    VulnerabilityContext,
    _extract_json,
    format_remediation_markdown,
    generate_ai_remediation_patch,
    mock_remediation,
    resolve_ai_credentials,
)
from app.services.vulnerability_service import VulnerabilityService


def test_extract_json_from_fenced_block() -> None:
    raw = """```json
{"explanation": "a", "remediation_steps": "1.", "patch_example": "code"}
```"""
    data = _extract_json(raw)
    assert data["explanation"] == "a"


def test_mock_remediation_contains_sections() -> None:
    ctx = VulnerabilityContext(
        title="SQL Injection in login",
        description="Unparameterized query",
        cwe_id="CWE-89",
        severity=Severity.CRITICAL,
        asset_type="domain",
        affected_component="auth-service",
    )
    result = mock_remediation(ctx)
    assert "login" in result.explanation.lower() or "SQL Injection" in result.explanation
    assert "1." in result.remediation_steps
    assert result.provider == "mock"
    assert "## Why this vulnerability occurs" in result.markdown


def test_format_markdown() -> None:
    md = format_remediation_markdown(
        {
            "explanation": "Because X",
            "remediation_steps": "1. Fix",
            "patch_example": "secure()",
        },
        provider="groq",
        model="llama-test",
    )
    assert "Because X" in md
    assert "secure()" in md
    assert "groq/llama-test" in md


def test_resolve_ai_credentials_prefers_ai_star() -> None:
    settings = Settings(
        ai_api_key="gsk-test",
        ai_base_url="https://api.groq.com/openai/v1",
        ai_model="llama-3.3-70b-versatile",
        openai_api_key="sk-legacy",
        openai_api_base="https://api.openai.com/v1",
        openai_model="gpt-4o-mini",
    )
    key, base, model = resolve_ai_credentials(settings)
    assert key == "gsk-test"
    assert "groq" in base
    assert model == "llama-3.3-70b-versatile"


def test_resolve_provider_auto_mock() -> None:
    settings = Settings(
        ai_api_key="",
        openai_api_key="",
        anthropic_api_key="",
        ai_remediation_provider="auto",
    )
    assert AIRemediationService(settings).resolve_provider() == "mock"


def test_generate_ai_remediation_patch_mock_without_key() -> None:
    with patch("app.services.ai_remediation.get_settings") as gs:
        gs.return_value = Settings(
            ai_api_key="",
            openai_api_key="",
            ai_remediation_fallback_mock=True,
            ai_remediation_enabled=True,
        )
        md = generate_ai_remediation_patch("CWE-89", "SQL injection in login form")
    assert "## Why this vulnerability occurs" in md
    assert "CWE-89" in md


def test_generate_ai_remediation_patch_openai_sdk() -> None:
    payload = {
        "explanation": "Root cause",
        "remediation_steps": "1. Patch\n2. Retest",
        "patch_example": "SELECT * FROM t WHERE id = :id",
    }
    mock_choice = MagicMock()
    mock_choice.message.content = json.dumps(payload)
    mock_resp = MagicMock()
    mock_resp.choices = [mock_choice]

    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = mock_resp
    mock_client.close = MagicMock()

    with patch("app.services.ai_remediation.get_settings") as gs, patch(
        "app.services.ai_remediation.OpenAI", return_value=mock_client
    ):
        gs.return_value = Settings(
            ai_api_key="gsk-test",
            ai_base_url="https://api.groq.com/openai/v1",
            ai_model="llama-3.3-70b-versatile",
            ai_remediation_fallback_mock=False,
            ai_remediation_enabled=True,
        )
        md = generate_ai_remediation_patch("CWE-89", "Unparameterized query")
    assert "Root cause" in md
    assert "groq" in md.lower() or "llama" in md.lower()


def test_generate_ai_remediation_patch_rate_limit_falls_back() -> None:
    mock_client = MagicMock()
    mock_client.chat.completions.create.side_effect = RateLimitError(
        "rate",
        response=MagicMock(status_code=429, headers={}),
        body=None,
    )
    mock_client.close = MagicMock()

    with patch("app.services.ai_remediation.get_settings") as gs, patch(
        "app.services.ai_remediation.OpenAI", return_value=mock_client
    ):
        gs.return_value = Settings(
            ai_api_key="sk-test",
            ai_base_url="https://api.openai.com/v1",
            ai_remediation_fallback_mock=True,
            ai_remediation_enabled=True,
        )
        md = generate_ai_remediation_patch("CWE-79", "XSS")
    assert "## Why this vulnerability occurs" in md


def test_generate_ai_remediation_patch_timeout_raises_without_fallback() -> None:
    mock_client = MagicMock()
    mock_client.chat.completions.create.side_effect = APITimeoutError(request=MagicMock())
    mock_client.close = MagicMock()

    with patch("app.services.ai_remediation.get_settings") as gs, patch(
        "app.services.ai_remediation.OpenAI", return_value=mock_client
    ):
        gs.return_value = Settings(
            ai_api_key="sk-test",
            ai_remediation_fallback_mock=False,
            ai_remediation_enabled=True,
        )
        with pytest.raises(AIRemediationError) as exc:
            generate_ai_remediation_patch("CWE-79", "XSS")
    assert exc.value.status_code == 504


@pytest.mark.asyncio
async def test_service_generate_uses_async_openai() -> None:
    settings = Settings(
        ai_api_key="sk-test",
        ai_base_url="https://api.openai.com/v1",
        ai_remediation_provider="openai",
        ai_remediation_fallback_mock=False,
        ai_force_json_response=True,
    )
    svc = AIRemediationService(settings)
    payload = {
        "explanation": "Root cause",
        "remediation_steps": "1. Patch\n2. Retest",
        "patch_example": "SELECT * FROM t WHERE id = :id",
    }
    mock_choice = MagicMock()
    mock_choice.message.content = json.dumps(payload)
    mock_resp = MagicMock()
    mock_resp.choices = [mock_choice]

    mock_client = AsyncMock()
    mock_client.chat.completions.create = AsyncMock(return_value=mock_resp)
    mock_client.close = AsyncMock()

    ctx = VulnerabilityContext(
        title="SQLi",
        description="test",
        cwe_id="CWE-89",
        severity=Severity.HIGH,
        asset_type="domain",
    )
    with patch("app.services.ai_remediation.AsyncOpenAI", return_value=mock_client):
        result = await svc.generate(ctx)
    assert result.explanation == "Root cause"
    assert result.provider == "openai"


@pytest.mark.asyncio
async def test_vulnerability_service_generate_ai_patch_persists() -> None:
    org_id = uuid4()
    now = datetime.now(timezone.utc)
    asset = Asset(
        id=uuid4(),
        organization_id=org_id,
        name="api",
        asset_type=AssetType.DOMAIN,
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
        fingerprint="fp",
        title="Open SSH",
        description="Weak ciphers",
        severity=Severity.HIGH,
        status=FindingStatus.OPEN,
        cwe_id="CWE-326",
        evidence={},
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
    mock_md = format_remediation_markdown(
        {
            "explanation": "Weak SSH ciphers",
            "remediation_steps": "1. Disable weak ciphers",
            "patch_example": "Ciphers aes256-gcm@openssh.com",
        },
        provider="mock",
        model="template-v1",
    )
    with patch(
        "app.services.vulnerability_service.generate_ai_remediation_patch_async",
        new=AsyncMock(return_value=mock_md),
    ):
        resp = await service.generate_ai_patch(vuln.id, organization_id=org_id, persist=True)

    assert vuln.remediation is not None
    assert "Remediation steps" in vuln.remediation
    assert "ai_remediation" in vuln.threat_intel_metadata
    assert resp.vulnerability_id == vuln.id
    assert "Weak SSH" in resp.explanation
