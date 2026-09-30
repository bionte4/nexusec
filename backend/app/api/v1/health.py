"""Health and readiness endpoints (Prompt 13)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field
from typing import Optional

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import RequireAdmin
from app.services.ai_settings_service import (
    load_ai_settings,
    public_ai_settings_view,
    save_ai_settings,
)
from app.services.health_service import HealthService, WorkerMonitorService

router = APIRouter(tags=["health"])


def get_health_service() -> HealthService:
    return HealthService()


def get_worker_monitor() -> WorkerMonitorService:
    return WorkerMonitorService()


class AISettingsUpdate(BaseModel):
    api_key: Optional[str] = Field(
        default=None,
        description="LLM API key (leave blank or masked to keep existing)",
    )
    base_url: Optional[str] = Field(default=None, description="OpenAI-compatible base URL")
    model: Optional[str] = Field(default=None, description="Model id")
    enabled: Optional[bool] = None
    clear_api_key: bool = False


@router.get("/health", summary="Liveness probe")
async def health_live(
    service: HealthService = Depends(get_health_service),
) -> dict[str, Any]:
    return await service.liveness()


@router.get("/health/live", summary="Liveness probe (alias)")
async def health_live_alias(
    service: HealthService = Depends(get_health_service),
) -> dict[str, Any]:
    return await service.liveness()


@router.get("/health/ready", summary="Readiness probe (Postgres + Redis)")
async def health_ready(
    response: Response,
    db: AsyncSession = Depends(get_db),
    service: HealthService = Depends(get_health_service),
) -> dict[str, Any]:
    payload = await service.readiness(db)
    if payload["status"] != "ok":
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return payload


@router.get("/health/detailed", summary="Full dependency health (Admin)")
async def health_detailed(
    response: Response,
    _: RequireAdmin,
    db: AsyncSession = Depends(get_db),
    service: HealthService = Depends(get_health_service),
) -> dict[str, Any]:
    payload = await service.detailed(db)
    # 503 only when core data plane is down — Celery/Docker may be degraded in API image.
    core = payload.get("checks") or {}
    core_bad = any(
        (core.get(name) or {}).get("status") == "unavailable"
        for name in ("postgres", "redis")
    )
    if core_bad:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return payload


@router.post(
    "/health/ai/test",
    summary="Test LLM API connection (Admin) — live ping, no secrets returned",
)
async def health_ai_test(
    _: RequireAdmin,
    db: AsyncSession = Depends(get_db),
    service: HealthService = Depends(get_health_service),
) -> dict[str, Any]:
    return await service.test_ai_connection(db)


@router.get(
    "/health/ai/settings",
    summary="Get platform AI LLM settings (Admin, api_key masked)",
)
async def get_ai_settings(
    _: RequireAdmin,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    stored = await load_ai_settings(db)
    return public_ai_settings_view(stored)


@router.patch(
    "/health/ai/settings",
    summary="Save platform AI LLM settings (Admin) — persists in DB, no .env edit",
)
async def patch_ai_settings(
    payload: AISettingsUpdate,
    _: RequireAdmin,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    data = payload.model_dump(exclude_unset=True)
    clear = bool(data.pop("clear_api_key", False))
    stored = await save_ai_settings(
        db,
        api_key=data.get("api_key"),
        base_url=data.get("base_url"),
        model=data.get("model"),
        enabled=data.get("enabled"),
        clear_api_key=clear,
    )
    await db.commit()
    return public_ai_settings_view(stored)


@router.get(
    "/health/workers",
    summary="Worker node / scanner hang monitor (Admin)",
)
async def health_workers(
    _: RequireAdmin,
    db: AsyncSession = Depends(get_db),
    monitor: WorkerMonitorService = Depends(get_worker_monitor),
) -> dict[str, Any]:
    payload = await monitor.status(db)
    try:
        from app.core.metrics import (
            record_hung_scans,
            record_tool_availability,
            record_worker_count,
        )

        record_worker_count(int(payload.get("celery", {}).get("worker_count") or 0))
        record_hung_scans(int(payload.get("hung_scans", {}).get("hung_count") or 0))
        for tool, info in (payload.get("tools") or {}).items():
            record_tool_availability(tool, bool(info.get("available")))
    except Exception:
        pass
    return payload
