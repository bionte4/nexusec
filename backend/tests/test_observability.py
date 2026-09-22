"""Tests for health checks and observability helpers."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from app.core.enums import ScanStatus, ScannerEngine
from app.services.health_service import CheckResult, HealthService, WorkerMonitorService, _overall


def test_overall_status() -> None:
    assert _overall([CheckResult("a", "ok"), CheckResult("b", "ok")]) == "ok"
    assert _overall([CheckResult("a", "ok"), CheckResult("b", "degraded")]) == "degraded"
    assert (
        _overall([CheckResult("a", "degraded"), CheckResult("b", "unavailable")]) == "unavailable"
    )


@pytest.mark.asyncio
async def test_liveness() -> None:
    payload = await HealthService().liveness()
    assert payload["status"] == "ok"
    assert payload["service"] == "nexusec-api"


@pytest.mark.asyncio
async def test_check_postgres_ok() -> None:
    db = AsyncMock()
    db.execute = AsyncMock(return_value=None)
    result = await HealthService().check_postgres(db)
    assert result.status == "ok"
    assert result.latency_ms is not None


@pytest.mark.asyncio
async def test_check_postgres_failure() -> None:
    db = AsyncMock()
    db.execute = AsyncMock(side_effect=RuntimeError("boom"))
    result = await HealthService().check_postgres(db)
    assert result.status == "unavailable"


@pytest.mark.asyncio
async def test_check_redis_ok() -> None:
    fake = AsyncMock()
    fake.ping = AsyncMock(return_value=True)
    fake.aclose = AsyncMock()
    with patch("app.services.health_service.aioredis.from_url", return_value=fake):
        result = await HealthService().check_redis()
    assert result.status == "ok"


@pytest.mark.asyncio
async def test_check_celery_no_workers() -> None:
    with patch(
        "app.services.health_service.asyncio.to_thread",
        new=AsyncMock(return_value={"ping": {}, "stats": {}, "active": {}}),
    ):
        result = await HealthService().check_celery()
    assert result.status == "degraded"
    assert result.meta["workers"] == []


@pytest.mark.asyncio
async def test_check_docker_cli_ok() -> None:
    with patch(
        "app.services.health_service.asyncio.to_thread",
        new=AsyncMock(return_value=(True, "24.0.0")),
    ):
        result = await HealthService().check_docker()
    assert result.status == "ok"
    assert result.meta["version"] == "24.0.0"


@pytest.mark.asyncio
async def test_hung_scans_detects_old_running() -> None:
    now = datetime.now(timezone.utc)
    scan = MagicMock()
    scan.id = uuid4()
    scan.name = "stuck-nmap"
    scan.engine = ScannerEngine.NMAP
    scan.status = ScanStatus.RUNNING
    scan.celery_task_id = "abc"
    scan.started_at = now - timedelta(hours=2)
    scan.updated_at = now - timedelta(hours=2)
    scan.created_at = now - timedelta(hours=3)

    db = AsyncMock()
    db.scalars = AsyncMock(return_value=MagicMock(all=MagicMock(return_value=[scan])))

    monitor = WorkerMonitorService()
    # threshold default 45 min
    result = await monitor.hung_scans(db)
    assert result["hung_count"] == 1
    assert result["hung_scans"][0]["name"] == "stuck-nmap"


@pytest.mark.asyncio
async def test_tool_availability() -> None:
    with patch("app.services.health_service.shutil.which", side_effect=lambda n: f"/usr/bin/{n}"):
        tools = await WorkerMonitorService().tool_availability()
    assert tools["nmap"]["available"] is True
    assert tools["nuclei"]["available"] is True


@pytest.mark.asyncio
async def test_health_live_endpoint(client) -> None:
    resp = await client.get("/api/v1/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_root_health_endpoint(client) -> None:
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
