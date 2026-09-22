"""Prometheus metrics for NexuSec API and scan workload."""

from __future__ import annotations

import logging

from prometheus_client import Counter, Gauge
from prometheus_fastapi_instrumentator import Instrumentator, metrics
from sqlalchemy import func, select

logger = logging.getLogger(__name__)

ACTIVE_SCANS = Gauge(
    "nexusec_active_scans",
    "Number of scans currently queued or running",
    ["status"],
)

SCANS_TOTAL = Counter(
    "nexusec_scans_total",
    "Total scans observed by status transitions (best-effort)",
    ["status", "engine"],
)

WORKER_NODES = Gauge(
    "nexusec_celery_workers",
    "Celery workers that responded to the last health inspect",
)

HUNG_SCANS = Gauge(
    "nexusec_hung_scans",
    "Scans exceeding the hang threshold while queued/running",
)

TOOL_AVAILABLE = Gauge(
    "nexusec_scanner_tool_available",
    "Whether a scanner binary is available on the API host (1/0)",
    ["tool"],
)

REQUEST_EXCEPTIONS = Counter(
    "nexusec_unhandled_exceptions_total",
    "Unhandled application exceptions observed by middleware hooks",
)


def build_instrumentator() -> Instrumentator:
    """Configure prometheus-fastapi-instrumentator with latency/error defaults."""
    instrumentator = Instrumentator(
        should_group_status_codes=True,
        should_ignore_untemplated=True,
        should_respect_env_var=True,
        should_instrument_requests_inprogress=True,
        excluded_handlers=[
            "/metrics",
            "/health",
            "/api/v1/health",
            "/api/v1/health/live",
            "/api/v1/health/ready",
            "/docs",
            "/redoc",
            "/openapi.json",
        ],
        inprogress_name="nexusec_http_requests_inprogress",
        inprogress_labels=True,
    )
    instrumentator.add(
        metrics.default(
            metric_namespace="nexusec",
            metric_subsystem="http",
        )
    )
    instrumentator.add(
        metrics.latency(
            metric_namespace="nexusec",
            metric_subsystem="http",
            buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
        )
    )
    return instrumentator


async def refresh_scan_gauges(db_session_factory=None) -> None:
    """Refresh active-scan gauges from PostgreSQL (best-effort)."""
    try:
        from app.core.database import AsyncSessionLocal
        from app.core.enums import ScanStatus
        from app.models.scan import Scan

        factory = db_session_factory or AsyncSessionLocal
        async with factory() as session:
            stmt = (
                select(Scan.status, func.count())
                .where(Scan.status.in_([ScanStatus.QUEUED, ScanStatus.RUNNING]))
                .group_by(Scan.status)
            )
            rows = (await session.execute(stmt)).all()
            counts = {ScanStatus.QUEUED.value: 0, ScanStatus.RUNNING.value: 0}
            for status, count in rows:
                key = status.value if hasattr(status, "value") else str(status)
                counts[key] = int(count)
            ACTIVE_SCANS.labels(status="queued").set(counts.get("queued", 0))
            ACTIVE_SCANS.labels(status="running").set(counts.get("running", 0))
    except Exception:
        logger.debug("refresh_scan_gauges skipped", exc_info=True)


def record_worker_count(count: int) -> None:
    WORKER_NODES.set(max(0, count))


def record_hung_scans(count: int) -> None:
    HUNG_SCANS.set(max(0, count))


def record_tool_availability(tool: str, available: bool) -> None:
    TOOL_AVAILABLE.labels(tool=tool).set(1 if available else 0)
