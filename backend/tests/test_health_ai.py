"""Health AI readiness + connection test (no live network required)."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from app.core.config import Settings
from app.services.health_service import HealthService


def test_check_ai_degraded_without_key() -> None:
    svc = HealthService(
        Settings(
            ai_api_key="",
            openai_api_key="",
            anthropic_api_key="",
            ai_remediation_fallback_mock=True,
        )
    )
    result = asyncio.get_event_loop().run_until_complete(svc.check_ai())
    assert result.status == "degraded"
    assert result.meta["ai_api_key_set"] is False
    assert result.meta["recommended_provider"] == "groq"


def test_test_ai_connection_without_key() -> None:
    svc = HealthService(
        Settings(ai_api_key="", openai_api_key="", anthropic_api_key="")
    )
    out = asyncio.get_event_loop().run_until_complete(svc.test_ai_connection())
    assert out["ok"] is False
    assert out["status"] == "unavailable"
    assert "No LLM API key" in out["detail"]


def test_test_ai_connection_success() -> None:
    mock_choice = MagicMock()
    mock_choice.message.content = "OK"
    mock_resp = MagicMock()
    mock_resp.choices = [mock_choice]
    mock_client = MagicMock()
    mock_client.chat.completions.create = AsyncMock(return_value=mock_resp)

    svc = HealthService(
        Settings(
            ai_api_key="gsk-test",
            ai_base_url="https://api.groq.com/openai/v1",
            ai_model="llama-3.3-70b-versatile",
        )
    )
    with patch(
        "app.services.ai_remediation.build_async_openai_client",
        return_value=mock_client,
    ):
        out = asyncio.get_event_loop().run_until_complete(svc.test_ai_connection())
    assert out["ok"] is True
    assert out["status"] == "ok"
    assert out["provider_hint"] == "groq"
    assert out["model"] == "llama-3.3-70b-versatile"
    assert out["latency_ms"] is not None
