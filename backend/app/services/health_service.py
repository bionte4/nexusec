"""Platform health checks — Postgres, Redis, Celery, Docker sandbox."""

from __future__ import annotations

import asyncio
import logging
import shutil
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import redis.asyncio as aioredis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.database import engine
from app.core.enums import ScanStatus

logger = logging.getLogger(__name__)


@dataclass
class CheckResult:
    name: str
    status: str  # ok | degraded | unavailable
    latency_ms: Optional[float] = None
    detail: Optional[str] = None
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"status": self.status}
        if self.latency_ms is not None:
            payload["latency_ms"] = round(self.latency_ms, 2)
        if self.detail:
            payload["detail"] = self.detail
        if self.meta:
            payload["meta"] = self.meta
        return payload


def _overall(checks: list[CheckResult]) -> str:
    statuses = {c.status for c in checks}
    if "unavailable" in statuses:
        return "unavailable"
    if "degraded" in statuses:
        return "degraded"
    return "ok"


class HealthService:
    def __init__(self, settings: Optional[Settings] = None) -> None:
        self.settings = settings or get_settings()

    async def check_postgres(self, db: Optional[AsyncSession] = None) -> CheckResult:
        started = time.perf_counter()
        try:
            if db is not None:
                await db.execute(text("SELECT 1"))
            else:
                async with engine.connect() as conn:
                    await conn.execute(text("SELECT 1"))
            return CheckResult(
                name="postgres",
                status="ok",
                latency_ms=(time.perf_counter() - started) * 1000,
            )
        except Exception as exc:
            logger.warning("Postgres health check failed: %s", exc)
            return CheckResult(
                name="postgres",
                status="unavailable",
                latency_ms=(time.perf_counter() - started) * 1000,
                detail=str(exc.__class__.__name__),
            )

    async def check_redis(self) -> CheckResult:
        started = time.perf_counter()
        client: Optional[aioredis.Redis] = None
        try:
            client = aioredis.from_url(
                self.settings.redis_url,
                socket_connect_timeout=self.settings.health_check_timeout_seconds,
                socket_timeout=self.settings.health_check_timeout_seconds,
            )
            pong = await client.ping()
            if not pong:
                return CheckResult(
                    name="redis",
                    status="unavailable",
                    latency_ms=(time.perf_counter() - started) * 1000,
                    detail="PING did not return True",
                )
            return CheckResult(
                name="redis",
                status="ok",
                latency_ms=(time.perf_counter() - started) * 1000,
            )
        except Exception as exc:
            logger.warning("Redis health check failed: %s", exc)
            return CheckResult(
                name="redis",
                status="unavailable",
                latency_ms=(time.perf_counter() - started) * 1000,
                detail=str(exc.__class__.__name__),
            )
        finally:
            if client is not None:
                await client.aclose()

    async def check_celery(self) -> CheckResult:
        """Ping Celery workers via control.inspect (runs in thread pool)."""
        started = time.perf_counter()
        timeout = self.settings.health_check_timeout_seconds

        def _inspect() -> dict[str, Any]:
            import sys
            from pathlib import Path

            # Prefer /app (compose image layout), then repo root for local runs.
            here = Path(__file__).resolve()
            candidates = [here.parents[3], here.parents[2], Path("/app")]
            for root in candidates:
                if (root / "workers").is_dir() and str(root) not in sys.path:
                    sys.path.insert(0, str(root))
            from workers.celery_app import celery_app

            # Single ping only — stats/active multiply the inspect timeout budget.
            inspector = celery_app.control.inspect(timeout=max(timeout, 2.0))
            ping = inspector.ping() or {}
            return {"ping": ping}

        try:
            data = await asyncio.wait_for(
                asyncio.to_thread(_inspect),
                timeout=max(timeout, 2.0) + 2.0,
            )
            workers = list((data.get("ping") or {}).keys())
            if not workers:
                return CheckResult(
                    name="celery",
                    status="degraded",
                    latency_ms=(time.perf_counter() - started) * 1000,
                    detail="No workers responded to ping",
                    meta={"workers": []},
                )
            return CheckResult(
                name="celery",
                status="ok",
                latency_ms=(time.perf_counter() - started) * 1000,
                meta={
                    "workers": workers,
                    "worker_count": len(workers),
                },
            )
        except Exception as exc:
            logger.warning("Celery health check failed: %s", exc)
            return CheckResult(
                name="celery",
                status="degraded",
                latency_ms=(time.perf_counter() - started) * 1000,
                detail=str(exc.__class__.__name__),
            )

    async def check_docker(self) -> CheckResult:
        """Detect Docker sandbox daemon via socket and/or CLI."""
        started = time.perf_counter()
        sock_path = Path(self.settings.docker_socket_path)
        socket_ok = sock_path.exists()

        def _docker_info() -> tuple[bool, str]:
            docker_bin = shutil.which("docker")
            if not docker_bin:
                return False, "docker CLI not found"
            import subprocess

            try:
                proc = subprocess.run(
                    [docker_bin, "info", "--format", "{{.ServerVersion}}"],
                    capture_output=True,
                    text=True,
                    timeout=self.settings.health_check_timeout_seconds,
                    check=False,
                )
                if proc.returncode != 0:
                    return False, (proc.stderr or proc.stdout or "docker info failed")[:200]
                version = (proc.stdout or "").strip() or "unknown"
                return True, version
            except Exception as exc:
                return False, str(exc.__class__.__name__)

        try:
            cli_ok, detail = await asyncio.to_thread(_docker_info)
        except Exception as exc:
            cli_ok, detail = False, str(exc.__class__.__name__)

        latency = (time.perf_counter() - started) * 1000
        if cli_ok:
            return CheckResult(
                name="docker",
                status="ok",
                latency_ms=latency,
                meta={"socket": str(sock_path), "socket_present": socket_ok, "version": detail},
            )
        # API image intentionally has no Docker CLI/socket; scanners run in scanner-worker.
        return CheckResult(
            name="docker",
            status="degraded",
            latency_ms=latency,
            detail=detail or "Docker not available in API container (expected)",
            meta={
                "socket": str(sock_path),
                "socket_present": socket_ok,
                "note": "Sandbox Docker is provided by the scanner-worker service",
            },
        )

    async def liveness(self) -> dict[str, Any]:
        return {
            "status": "ok",
            "service": "nexusec-api",
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

    async def readiness(self, db: Optional[AsyncSession] = None) -> dict[str, Any]:
        postgres, redis_check = await asyncio.gather(
            self.check_postgres(db),
            self.check_redis(),
        )
        checks = [postgres, redis_check]
        status = _overall(checks)
        return {
            "status": status,
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "checks": {c.name: c.to_dict() for c in checks},
        }

    async def detailed(self, db: Optional[AsyncSession] = None) -> dict[str, Any]:
        postgres, redis_check, celery, docker = await asyncio.gather(
            self.check_postgres(db),
            self.check_redis(),
            self.check_celery(),
            self.check_docker(),
        )
        checks = [postgres, redis_check, celery, docker]
        return {
            "status": _overall(checks),
            "service": "nexusec-api",
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "checks": {c.name: c.to_dict() for c in checks},
        }


class WorkerMonitorService:
    """Track Celery worker nodes and hung/failing scanner tasks."""

    def __init__(self, settings: Optional[Settings] = None) -> None:
        self.settings = settings or get_settings()

    async def tool_availability(self) -> dict[str, Any]:
        def _which() -> dict[str, Any]:
            tools = {}
            for name in ("nmap", "nuclei"):
                path = shutil.which(name)
                tools[name] = {
                    "available": path is not None,
                    "path": path,
                }
            # OpenVAS connector works in mock mode without a local binary
            import os

            openvas_mode = (os.getenv("OPENVAS_MODE") or "mock").lower()
            gvm = shutil.which("gvm-cli")
            tools["openvas"] = {
                "available": openvas_mode == "mock" or gvm is not None,
                "path": gvm,
                "mode": openvas_mode,
            }
            return tools

        return await asyncio.to_thread(_which)

    async def celery_workers(self) -> dict[str, Any]:
        timeout = self.settings.health_check_timeout_seconds

        def _inspect() -> dict[str, Any]:
            import sys
            from pathlib import Path

            root = Path(__file__).resolve().parents[3]
            if str(root) not in sys.path:
                sys.path.insert(0, str(root))
            from workers.celery_app import celery_app

            inspector = celery_app.control.inspect(timeout=timeout)
            ping = inspector.ping() or {}
            stats = inspector.stats() or {}
            active = inspector.active() or {}
            reserved = inspector.reserved() or {}
            registered = inspector.registered() or {}
            return {
                "ping": ping,
                "stats": stats,
                "active": active,
                "reserved": reserved,
                "registered": registered,
            }

        try:
            raw = await asyncio.wait_for(asyncio.to_thread(_inspect), timeout=timeout + 1)
        except Exception as exc:
            return {
                "status": "unavailable",
                "detail": str(exc.__class__.__name__),
                "workers": [],
            }

        workers: list[dict[str, Any]] = []
        for name in sorted((raw.get("ping") or {}).keys()):
            st = (raw.get("stats") or {}).get(name) or {}
            active_list = (raw.get("active") or {}).get(name) or []
            reserved_list = (raw.get("reserved") or {}).get(name) or []
            pool = st.get("pool") or {}
            workers.append(
                {
                    "name": name,
                    "status": "online",
                    "active_tasks": len(active_list),
                    "reserved_tasks": len(reserved_list),
                    "pool_max_concurrency": pool.get("max-concurrency"),
                    "total_tasks": (st.get("total") or {}),
                    "registered_sample": list((raw.get("registered") or {}).get(name) or [])[:15],
                    "active": [
                        {
                            "id": t.get("id"),
                            "name": t.get("name"),
                            "args": t.get("args"),
                            "time_start": t.get("time_start"),
                        }
                        for t in active_list
                    ],
                }
            )

        status = "ok" if workers else "degraded"
        return {"status": status, "worker_count": len(workers), "workers": workers}

    async def hung_scans(self, db: AsyncSession) -> dict[str, Any]:
        """Find scans stuck in running/queued beyond the configured threshold."""
        from sqlalchemy import select

        from app.models.scan import Scan

        threshold_min = self.settings.worker_hang_threshold_minutes
        cutoff = datetime.now(timezone.utc).timestamp() - (threshold_min * 60)
        cutoff_dt = datetime.fromtimestamp(cutoff, tz=timezone.utc)

        stmt = (
            select(Scan)
            .where(
                Scan.status.in_([ScanStatus.RUNNING, ScanStatus.QUEUED]),
            )
            .order_by(Scan.updated_at.asc())
            .limit(100)
        )
        rows = list((await db.scalars(stmt)).all())
        hung = []
        for scan in rows:
            ref = scan.started_at or scan.updated_at or scan.created_at
            if ref is None:
                continue
            if ref.tzinfo is None:
                ref = ref.replace(tzinfo=timezone.utc)
            if ref <= cutoff_dt:
                age_min = (datetime.now(timezone.utc) - ref).total_seconds() / 60.0
                hung.append(
                    {
                        "scan_id": str(scan.id),
                        "name": scan.name,
                        "engine": (
                            scan.engine.value if hasattr(scan.engine, "value") else str(scan.engine)
                        ),
                        "status": (
                            scan.status.value if hasattr(scan.status, "value") else str(scan.status)
                        ),
                        "celery_task_id": scan.celery_task_id,
                        "age_minutes": round(age_min, 1),
                        "started_at": ref.isoformat(),
                    }
                )
        return {
            "threshold_minutes": threshold_min,
            "hung_count": len(hung),
            "hung_scans": hung,
        }

    async def status(self, db: AsyncSession) -> dict[str, Any]:
        workers, tools, hung = await asyncio.gather(
            self.celery_workers(),
            self.tool_availability(),
            self.hung_scans(db),
        )
        overall = "ok"
        if workers.get("status") == "unavailable" or hung["hung_count"] > 0:
            overall = "degraded"
        if workers.get("status") == "unavailable" and hung["hung_count"] > 0:
            overall = "unavailable"
        return {
            "status": overall,
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "celery": workers,
            "tools": tools,
            "hung_scans": hung,
        }


def tcp_reachable(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False
