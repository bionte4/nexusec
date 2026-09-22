"""Aggregate API v1 routers."""

from fastapi import APIRouter

from app.api.v1 import (
    assets,
    auth,
    dashboard,
    health,
    integrations,
    normalize,
    organizations,
    reports,
    scans,
    scanner,
    soc,
    threat_intel,
    vulnerabilities,
)

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(organizations.router)
api_router.include_router(assets.router)
api_router.include_router(scans.router)
api_router.include_router(scanner.router)
api_router.include_router(normalize.router)
api_router.include_router(dashboard.router)
api_router.include_router(vulnerabilities.router)
api_router.include_router(reports.router)
api_router.include_router(integrations.router)
api_router.include_router(threat_intel.router)
api_router.include_router(soc.router)
