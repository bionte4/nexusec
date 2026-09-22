"""Health and readiness endpoints (Prompt 13)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import RequireAdmin
from app.services.health_service import HealthService, WorkerMonitorService

router = APIRouter(tags=["health"])


def get_health_service() -> HealthService:
    return HealthService()


def get_worker_monitor() -> WorkerMonitorService:
    return WorkerMonitorService()


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
    if payload["status"] == "unavailable":
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return payload


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
