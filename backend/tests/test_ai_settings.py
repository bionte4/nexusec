"""Unit tests for platform AI settings cache / masking."""

from __future__ import annotations

from app.services.ai_settings_service import (
    clear_cached_ai_settings,
    get_cached_ai_settings,
    mask_api_key,
    public_ai_settings_view,
    resolve_effective_ai_credentials,
    set_cached_ai_settings,
)
from app.core.config import Settings


def setup_function() -> None:
    clear_cached_ai_settings()


def teardown_function() -> None:
    clear_cached_ai_settings()


def test_normalize_base_url_fixes_console() -> None:
    from app.services.ai_settings_service import normalize_base_url

    assert (
        normalize_base_url("https://console.groq.com/keys")
        == "https://api.groq.com/openai/v1"
    )
    assert (
        normalize_base_url("https://api.groq.com/openai/v1")
        == "https://api.groq.com/openai/v1"
    )


def test_resolve_prefers_cache_over_env() -> None:
    set_cached_ai_settings(
        {
            "api_key": "gsk_from_db",
            "base_url": "https://api.groq.com/openai/v1",
            "model": "llama-3.3-70b-versatile",
        }
    )
    settings = Settings(
        ai_api_key="env-key",
        ai_base_url="https://api.openai.com/v1",
        ai_model="gpt-4o-mini",
    )
    key, base, model = resolve_effective_ai_credentials(settings)
    assert key == "gsk_from_db"
    assert "groq.com" in base
    assert model == "llama-3.3-70b-versatile"


def test_public_view_never_exposes_raw_key() -> None:
    set_cached_ai_settings({"api_key": "gsk_secrettoken1234", "base_url": "", "model": ""})
    view = public_ai_settings_view(
        settings=Settings(ai_api_key="", openai_api_key="", ai_base_url="", ai_model="")
    )
    assert view["api_key_set"] is True
    assert "secrettoken" not in view["api_key_masked"]
    assert view["source"] == "database"
    assert get_cached_ai_settings()["api_key"] == "gsk_secrettoken1234"
