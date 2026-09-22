"""SOC dashboard metrics endpoints (tenant-scoped)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import RequireTenant
from app.schemas.vulnerability import (
    AssetRiskSummary,
    DashboardOverview,
    SeverityCount,
    TrendPoint,
)
from app.services.dashboard_service import DashboardService

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


def get_dashboard_service(
    tenant: RequireTenant,
    db: AsyncSession = Depends(get_db),
) -> DashboardService:
    org_id = None if tenant.cross_tenant else tenant.organization_id
    return DashboardService(db, organization_id=org_id)


@router.get(
    "/overview",
    response_model=DashboardOverview,
    summary="SOC dashboard overview (tenant-scoped)",
)
async def dashboard_overview(
    trend_days: int = Query(30, ge=7, le=90),
    service: DashboardService = Depends(get_dashboard_service),
) -> DashboardOverview:
    return await service.overview(trend_days=trend_days)


@router.get(
    "/severity",
    response_model=SeverityCount,
    summary="Active vulnerabilities by severity",
)
async def dashboard_severity(
    service: DashboardService = Depends(get_dashboard_service),
) -> SeverityCount:
    return await service.active_by_severity()


@router.get(
    "/asset-risk",
    response_model=list[AssetRiskSummary],
    summary="Asset risk posture summary",
)
async def dashboard_asset_risk(
    limit: int = Query(50, ge=1, le=200),
    service: DashboardService = Depends(get_dashboard_service),
) -> list[AssetRiskSummary]:
    return await service.asset_risk_posture(limit=limit)


@router.get(
    "/trends",
    response_model=list[TrendPoint],
    summary="Open vs resolved vulnerability trend",
)
async def dashboard_trends(
    days: int = Query(30, ge=7, le=90),
    service: DashboardService = Depends(get_dashboard_service),
) -> list[TrendPoint]:
    return await service.trend(days=days)
