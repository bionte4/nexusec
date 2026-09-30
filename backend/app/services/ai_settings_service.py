"""Platform AI LLM settings — Postgres + Redis shared cache (multi-worker safe).

UI Admin can save api_key / base_url / model without editing .env.
Env vars remain the fallback when DB value is empty.
"""

from __future__ import annotations

import json
import logging
import threading
from typing import Any, Optional
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.models.platform_setting import PlatformSetting

logger = logging.getLogger(__name__)

AI_SETTINGS_KEY = "ai_llm"
REDIS_CACHE_KEY = "nexusec:platform:ai_llm"

_lock = threading.RLock()
_cache: Optional[dict[str, Any]] = None

# Sentinel: client sent masked value — keep existing secret
_MASK_PLACEHOLDER = "••••"

# Common mistake: pasting the Groq console page instead of the OpenAI-compatible API base
_GROQ_API_BASE = "https://api.groq.com/openai/v1"
_BAD_GROQ_HOSTS = {"console.groq.com", "groq.com", "www.groq.com"}


def mask_api_key(api_key: str) -> str:
    key = (api_key or "").strip()
    if not key:
        return ""
    if len(key) <= 8:
        return _MASK_PLACEHOLDER * 2
    return f"{key[:4]}{_MASK_PLACEHOLDER}{key[-4:]}"


def normalize_base_url(base_url: str) -> str:
    """Fix common paste mistakes (console URL → API base)."""
    raw = (base_url or "").strip().rstrip("/")
    if not raw:
        return ""
    try:
        parsed = urlparse(raw if "://" in raw else f"https://{raw}")
        host = (parsed.hostname or "").lower()
        if host in _BAD_GROQ_HOSTS or "console.groq.com" in raw.lower():
            return _GROQ_API_BASE
        # Groq API root without /openai/v1
        if host == "api.groq.com" and not parsed.path.rstrip("/").endswith("/openai/v1"):
            return _GROQ_API_BASE
    except Exception:
        pass
    return raw


def _normalize(raw: Optional[dict[str, Any]]) -> dict[str, Any]:
    data = dict(raw or {})
    return {
        "api_key": str(data.get("api_key") or "").strip(),
        "base_url": normalize_base_url(str(data.get("base_url") or "")),
        "model": str(data.get("model") or "").strip(),
        "enabled": bool(data.get("enabled", True)),
    }


def _publish_redis(data: dict[str, Any]) -> None:
    try:
        import redis

        settings = get_settings()
        client = redis.Redis.from_url(settings.redis_url, decode_responses=True, socket_timeout=2)
        client.set(REDIS_CACHE_KEY, json.dumps(data))
        client.close()
    except Exception as exc:
        logger.debug("AI settings Redis publish skipped: %s", exc)


def _read_redis() -> Optional[dict[str, Any]]:
    try:
        import redis

        settings = get_settings()
        client = redis.Redis.from_url(settings.redis_url, decode_responses=True, socket_timeout=2)
        raw = client.get(REDIS_CACHE_KEY)
        client.close()
        if not raw:
            return None
        data = json.loads(raw)
        if isinstance(data, dict):
            return _normalize(data)
    except Exception as exc:
        logger.debug("AI settings Redis read skipped: %s", exc)
    return None


def get_cached_ai_settings() -> dict[str, Any]:
    """Process cache, then Redis (shared across uvicorn workers)."""
    global _cache
    with _lock:
        if _cache is not None:
            return _normalize(_cache)
    shared = _read_redis()
    if shared is not None:
        with _lock:
            _cache = shared
        return shared
    return _normalize({})


def set_cached_ai_settings(data: dict[str, Any]) -> dict[str, Any]:
    normalized = _normalize(data)
    with _lock:
        global _cache
        _cache = normalized
    _publish_redis(normalized)
    return normalized


def clear_cached_ai_settings() -> None:
    with _lock:
        global _cache
        _cache = None
    try:
        import redis

        settings = get_settings()
        client = redis.Redis.from_url(settings.redis_url, decode_responses=True, socket_timeout=2)
        client.delete(REDIS_CACHE_KEY)
        client.close()
    except Exception:
        pass


def public_ai_settings_view(
    stored: Optional[dict[str, Any]] = None,
    *,
    settings: Optional[Settings] = None,
) -> dict[str, Any]:
    """Masked view for Admin UI — never returns raw api_key."""
    settings = settings or get_settings()
    stored_n = _normalize(stored if stored is not None else get_cached_ai_settings())
    env_key = (settings.ai_api_key or settings.openai_api_key or "").strip()
    env_base = normalize_base_url(settings.ai_base_url or settings.openai_api_base or "")
    env_model = (settings.ai_model or settings.openai_model or "").strip()

    effective_key = stored_n["api_key"] or env_key
    effective_base = stored_n["base_url"] or env_base or "https://api.openai.com/v1"
    effective_model = stored_n["model"] or env_model or "gpt-4o-mini"
    if stored_n["api_key"] or stored_n["base_url"] or stored_n["model"]:
        source = "database"
    elif env_key:
        source = "env"
    else:
        source = "none"

    return {
        "api_key_set": bool(effective_key),
        "api_key_masked": mask_api_key(effective_key) if effective_key else "",
        "base_url": effective_base,
        "model": effective_model,
        "enabled": stored_n["enabled"],
        "source": source,
        "env_fallback_available": bool(env_key),
        "recommended": {
            "provider": "groq",
            "base_url": _GROQ_API_BASE,
            "model": "openai/gpt-oss-20b",
        },
    }


async def load_ai_settings(db: AsyncSession) -> dict[str, Any]:
    row = (
        await db.execute(
            select(PlatformSetting).where(PlatformSetting.key == AI_SETTINGS_KEY)
        )
    ).scalar_one_or_none()
    data = _normalize(row.value if row else {})
    set_cached_ai_settings(data)
    return data


async def save_ai_settings(
    db: AsyncSession,
    *,
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    model: Optional[str] = None,
    enabled: Optional[bool] = None,
    clear_api_key: bool = False,
) -> dict[str, Any]:
    row = (
        await db.execute(
            select(PlatformSetting).where(PlatformSetting.key == AI_SETTINGS_KEY)
        )
    ).scalar_one_or_none()
    current = _normalize(row.value if row else {})

    if clear_api_key:
        current["api_key"] = ""
    elif api_key is not None:
        candidate = str(api_key).strip()
        # Ignore blank or masked placeholders so Save without retyping key works
        if candidate and _MASK_PLACEHOLDER not in candidate:
            current["api_key"] = candidate

    if base_url is not None:
        current["base_url"] = normalize_base_url(str(base_url).strip())
    if model is not None:
        current["model"] = str(model).strip()
    if enabled is not None:
        current["enabled"] = bool(enabled)

    if row is None:
        row = PlatformSetting(key=AI_SETTINGS_KEY, value=current)
        db.add(row)
    else:
        row.value = current
    await db.flush()
    await db.refresh(row)
    set_cached_ai_settings(current)
    logger.info(
        "Platform AI settings saved (key_set=%s, base_url=%s, model=%s)",
        bool(current["api_key"]),
        current["base_url"] or "(env)",
        current["model"] or "(env)",
    )
    return current


def resolve_effective_ai_credentials(
    settings: Optional[Settings] = None,
) -> tuple[str, str, str]:
    """Prefer DB/Redis cache over env. Returns (api_key, base_url, model)."""
    settings = settings or get_settings()
    stored = get_cached_ai_settings()
    api_key = (stored.get("api_key") or settings.ai_api_key or settings.openai_api_key or "").strip()
    base_url = normalize_base_url(
        stored.get("base_url") or settings.ai_base_url or settings.openai_api_base or ""
    )
    if not base_url:
        base_url = "https://api.openai.com/v1"
    model = (stored.get("model") or settings.ai_model or settings.openai_model or "gpt-4o-mini").strip()
    return api_key, base_url.rstrip("/"), model
