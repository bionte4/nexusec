"""SOC dashboard aggregation queries."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import Select, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.types import Date

from app.core.enums import (
    ACTIVE_FINDING_STATUSES,
    DASHBOARD_SEVERITIES,
    RESOLVED_FINDING_STATUSES,
    FindingStatus,
    Severity,
)
from app.models.asset import Asset
from app.models.vulnerability import Vulnerability
from app.schemas.vulnerability import (
    AssetRiskSummary,
    DashboardOverview,
    SeverityCount,
    TrendPoint,
)

_RISK_WEIGHTS = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 5.0,
    Severity.MEDIUM: 2.0,
    Severity.LOW: 1.0,
    Severity.INFO: 0.1,
    Severity.UNKNOWN: 0.5,
}


class DashboardService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def overview(self, *, trend_days: int = 30) -> DashboardOverview:
        trend_days = min(max(trend_days, 7), 90)
        active_by_severity = await self.active_by_severity()
        status_breakdown = await self.status_breakdown()
        asset_risk = await self.asset_risk_posture(limit=50)
        trend = await self.trend(days=trend_days)

        total_assets = int(await self.db.scalar(select(func.count()).select_from(Asset)) or 0)
        assets_with_active = int(
            await self.db.scalar(
                select(func.count(func.distinct(Vulnerability.asset_id))).where(
                    Vulnerability.status.in_(tuple(ACTIVE_FINDING_STATUSES))
                )
            )
            or 0
        )

        return DashboardOverview(
            generated_at=datetime.now(timezone.utc),
            active_by_severity=active_by_severity,
            status_breakdown=status_breakdown,
            total_assets=total_assets,
            assets_with_active_findings=assets_with_active,
            asset_risk_posture=asset_risk,
            trend=trend,
        )

    async def active_by_severity(self) -> SeverityCount:
        stmt = (
            select(Vulnerability.severity, func.count())
            .where(Vulnerability.status.in_(tuple(ACTIVE_FINDING_STATUSES)))
            .group_by(Vulnerability.severity)
        )
        rows = (await self.db.execute(stmt)).all()
        counts = {sev.value: 0 for sev in Severity}
        for severity, count in rows:
            counts[severity.value if isinstance(severity, Severity) else str(severity)] = int(count)
        total = sum(counts[s.value] for s in DASHBOARD_SEVERITIES)
        return SeverityCount(
            critical=counts["critical"],
            high=counts["high"],
            medium=counts["medium"],
            low=counts["low"],
            info=counts["info"],
            unknown=counts["unknown"],
            total=total + counts["info"] + counts["unknown"],
        )

    async def status_breakdown(self) -> dict[str, int]:
        stmt = select(Vulnerability.status, func.count()).group_by(Vulnerability.status)
        rows = (await self.db.execute(stmt)).all()
        return {
            (status.value if isinstance(status, FindingStatus) else str(status)): int(count)
            for status, count in rows
        }

    async def asset_risk_posture(self, *, limit: int = 50) -> list[AssetRiskSummary]:
        active = tuple(ACTIVE_FINDING_STATUSES)
        stmt: Select[tuple] = (
            select(
                Asset.id,
                Asset.name,
                Asset.asset_type,
                Asset.is_cde_scope,
                Asset.criticality,
                Vulnerability.severity,
                func.count().label("cnt"),
            )
            .join(Vulnerability, Vulnerability.asset_id == Asset.id)
            .where(Vulnerability.status.in_(active))
            .group_by(
                Asset.id,
                Asset.name,
                Asset.asset_type,
                Asset.is_cde_scope,
                Asset.criticality,
                Vulnerability.severity,
            )
        )
        rows = (await self.db.execute(stmt)).all()

        by_asset: dict[UUID, AssetRiskSummary] = {}
        for asset_id, name, asset_type, is_cde, criticality, severity, cnt in rows:
            summary = by_asset.get(asset_id)
            if summary is None:
                summary = AssetRiskSummary(
                    asset_id=asset_id,
                    asset_name=name,
                    asset_type=(
                        asset_type.value if hasattr(asset_type, "value") else str(asset_type)
                    ),
                    is_cde_scope=bool(is_cde),
                    criticality=(
                        criticality.value if hasattr(criticality, "value") else str(criticality)
                    ),
                )
                by_asset[asset_id] = summary

            sev = severity if isinstance(severity, Severity) else Severity(str(severity))
            count = int(cnt)
            if sev == Severity.CRITICAL:
                summary.active_critical += count
            elif sev == Severity.HIGH:
                summary.active_high += count
            elif sev == Severity.MEDIUM:
                summary.active_medium += count
            elif sev == Severity.LOW:
                summary.active_low += count
            summary.active_total += count
            summary.risk_score += _RISK_WEIGHTS.get(sev, 0.5) * count

        ranked = sorted(
            by_asset.values(),
            key=lambda s: (s.risk_score, s.active_critical, s.active_high),
            reverse=True,
        )
        return ranked[:limit]

    async def trend(self, *, days: int = 30) -> list[TrendPoint]:
        """
        Daily counts of newly opened vs newly resolved findings.

        Open proxy: first_seen_at date
        Resolved proxy: status_changed_at (fallback updated_at) for resolved statuses
        """
        since = datetime.now(timezone.utc) - timedelta(days=days)

        open_stmt = (
            select(
                cast(Vulnerability.first_seen_at, Date).label("day"),
                func.count().label("cnt"),
            )
            .where(Vulnerability.first_seen_at >= since)
            .group_by("day")
            .order_by("day")
        )
        open_rows = {row.day: int(row.cnt) for row in (await self.db.execute(open_stmt)).all()}

        resolved_ts = func.coalesce(Vulnerability.status_changed_at, Vulnerability.updated_at)
        resolved_stmt = (
            select(
                cast(resolved_ts, Date).label("day"),
                func.count().label("cnt"),
            )
            .where(
                Vulnerability.status.in_(tuple(RESOLVED_FINDING_STATUSES)),
                resolved_ts >= since,
            )
            .group_by("day")
            .order_by("day")
        )
        resolved_rows = {
            row.day: int(row.cnt) for row in (await self.db.execute(resolved_stmt)).all()
        }

        points: list[TrendPoint] = []
        for offset in range(days, -1, -1):
            day = (datetime.now(timezone.utc) - timedelta(days=offset)).date()
            points.append(
                TrendPoint(
                    day=day,
                    open_count=open_rows.get(day, 0),
                    resolved_count=resolved_rows.get(day, 0),
                )
            )
        return points
