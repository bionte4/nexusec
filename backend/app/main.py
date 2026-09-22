"""NexuSec FastAPI application entrypoint."""

from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.router import api_router
from app.core.config import get_settings
from app.core.metrics import build_instrumentator, refresh_scan_gauges
from app.middleware.audit import AuditTrailMiddleware
from app.services.health_service import HealthService

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # Warm custom gauges once at startup (best-effort)
    try:
        await refresh_scan_gauges()
    except Exception:
        pass
    yield


app = FastAPI(
    title=settings.app_name,
    description=(
        "VA/PT & SOC Orchestration Platform — scan orchestration, "
        "normalized findings, and compliance mapping."
    ),
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# Middleware order: last added runs first on request.
app.add_middleware(AuditTrailMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix=settings.api_v1_prefix)


# Top-level /health for kube/docker probes (mirrors API liveness)
@app.get("/health")
async def root_health() -> dict:
    return await HealthService().liveness()


@app.get("/")
async def root() -> dict[str, str]:
    return {
        "name": settings.app_name,
        "version": "0.1.0",
        "docs": "/docs",
        "metrics": "/metrics" if settings.prometheus_metrics_enabled else "",
        "health": "/health",
    }


if settings.prometheus_metrics_enabled:
    instrumentator = build_instrumentator()
    instrumentator.instrument(app).expose(app, endpoint="/metrics", include_in_schema=True)
