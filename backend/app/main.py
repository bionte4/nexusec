"""NexuSec FastAPI application entrypoint."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.router import api_router
from app.core.config import get_settings
from app.middleware.audit import AuditTrailMiddleware

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    description=(
        "VA/PT & SOC Orchestration Platform — scan orchestration, "
        "normalized findings, and compliance mapping."
    ),
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
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


@app.get("/")
async def root() -> dict[str, str]:
    return {
        "name": settings.app_name,
        "version": "0.1.0",
        "docs": "/docs",
    }
