"""CRUD for recurring scan schedules."""

from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from uuid import UUID

from sqlalchemy import Select, delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.enums import ScannerEngine
from app.models.asset import Asset
from app.models.scan_schedule import ScanSchedule, ScanScheduleAsset
from app.schemas.scan_schedule import (
    ScanScheduleCreate,
    ScanScheduleListResponse,
    ScanScheduleRead,
    ScanScheduleUpdate,
)
from app.services.scan_service import ScanService, ScanValidationError


class ScanScheduleNotFoundError(Exception):
    pass


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _to_read(schedule: ScanSchedule) -> ScanScheduleRead:
    asset_ids = [a.id for a in (schedule.assets or [])]
    data = ScanScheduleRead.model_validate(schedule)
    return data.model_copy(update={"asset_ids": asset_ids})


class ScanScheduleService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def create(
        self,
        payload: ScanScheduleCreate,
        *,
        organization_id: UUID,
        created_by_id: Optional[UUID] = None,
    ) -> ScanScheduleRead:
        assets = await self._load_assets(payload.asset_ids, organization_id=organization_id)
        if len(assets) != len(set(payload.asset_ids)):
            raise ScanValidationError("One or more asset_ids were not found")
        if payload.engine not in {
            ScannerEngine.NMAP,
            ScannerEngine.NEXUSEC,
            ScannerEngine.NUCLEI,
        }:
            raise ScanValidationError(
                f"Engine '{payload.engine.value}' is not schedulable yet"
            )
        ScanService._ensure_scan_targets(assets, engine=payload.engine)

        now = _utcnow()
        next_run = now if payload.run_immediately else now + timedelta(
            minutes=payload.interval_minutes
        )

        schedule = ScanSchedule(
            organization_id=organization_id,
            name=payload.name,
            scan_type=payload.scan_type,
            engine=payload.engine,
            config=payload.config or {},
            interval_minutes=payload.interval_minutes,
            enabled=payload.enabled,
            next_run_at=next_run,
            created_by_id=created_by_id,
        )
        self.db.add(schedule)
        await self.db.flush()

        for asset in assets:
            self.db.add(ScanScheduleAsset(schedule_id=schedule.id, asset_id=asset.id))
        await self.db.flush()

        schedule = await self._get(schedule.id, organization_id=organization_id)
        return _to_read(schedule)

    async def update(
        self,
        schedule_id: UUID,
        payload: ScanScheduleUpdate,
        *,
        organization_id: Optional[UUID] = None,
    ) -> ScanScheduleRead:
        schedule = await self._get(schedule_id, organization_id=organization_id)
        data = payload.model_dump(exclude_unset=True)
        asset_ids = data.pop("asset_ids", None)

        if "engine" in data and data["engine"] not in {
            ScannerEngine.NMAP,
            ScannerEngine.NEXUSEC,
            ScannerEngine.NUCLEI,
        }:
            raise ScanValidationError(
                f"Engine '{data['engine'].value}' is not schedulable yet"
            )

        interval_changed = False
        if "interval_minutes" in data and data["interval_minutes"] != schedule.interval_minutes:
            interval_changed = True

        for key, value in data.items():
            setattr(schedule, key, value)

        if asset_ids is not None:
            assets = await self._load_assets(
                asset_ids, organization_id=schedule.organization_id
            )
            if len(assets) != len(set(asset_ids)):
                raise ScanValidationError("One or more asset_ids were not found")
            ScanService._ensure_scan_targets(assets, engine=schedule.engine)
            await self.db.execute(
                delete(ScanScheduleAsset).where(
                    ScanScheduleAsset.schedule_id == schedule.id
                )
            )
            for asset in assets:
                self.db.add(
                    ScanScheduleAsset(schedule_id=schedule.id, asset_id=asset.id)
                )

        if interval_changed and schedule.enabled:
            schedule.next_run_at = _utcnow() + timedelta(minutes=schedule.interval_minutes)

        if data.get("enabled") is True and schedule.next_run_at < _utcnow():
            schedule.next_run_at = _utcnow()

        await self.db.flush()
        schedule = await self._get(schedule.id, organization_id=organization_id)
        return _to_read(schedule)

    async def delete(
        self, schedule_id: UUID, *, organization_id: Optional[UUID] = None
    ) -> None:
        schedule = await self._get(schedule_id, organization_id=organization_id)
        await self.db.delete(schedule)
        await self.db.flush()

    async def get(
        self, schedule_id: UUID, *, organization_id: Optional[UUID] = None
    ) -> ScanScheduleRead:
        return _to_read(await self._get(schedule_id, organization_id=organization_id))

    async def list(
        self,
        *,
        page: int = 1,
        page_size: int = 20,
        organization_id: Optional[UUID] = None,
        enabled: Optional[bool] = None,
    ) -> ScanScheduleListResponse:
        page = max(page, 1)
        page_size = min(max(page_size, 1), 100)
        filters: list[Any] = []
        if organization_id is not None:
            filters.append(ScanSchedule.organization_id == organization_id)
        if enabled is not None:
            filters.append(ScanSchedule.enabled == enabled)

        count_stmt = select(func.count()).select_from(ScanSchedule)
        if filters:
            count_stmt = count_stmt.where(*filters)
        total = int(await self.db.scalar(count_stmt) or 0)

        stmt: Select[tuple[ScanSchedule]] = (
            select(ScanSchedule)
            .options(selectinload(ScanSchedule.assets))
            .order_by(ScanSchedule.next_run_at.asc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        if filters:
            stmt = stmt.where(*filters)

        rows = (await self.db.execute(stmt)).scalars().all()
        pages = math.ceil(total / page_size) if total else 0
        return ScanScheduleListResponse(
            items=[_to_read(s) for s in rows],
            total=total,
            page=page,
            page_size=page_size,
            pages=pages,
        )

    async def _get(
        self, schedule_id: UUID, *, organization_id: Optional[UUID] = None
    ) -> ScanSchedule:
        stmt = (
            select(ScanSchedule)
            .options(selectinload(ScanSchedule.assets))
            .where(ScanSchedule.id == schedule_id)
        )
        if organization_id is not None:
            stmt = stmt.where(ScanSchedule.organization_id == organization_id)
        schedule = (await self.db.execute(stmt)).scalar_one_or_none()
        if schedule is None:
            raise ScanScheduleNotFoundError(f"Schedule {schedule_id} not found")
        return schedule

    async def _load_assets(
        self, asset_ids: list[UUID], *, organization_id: UUID
    ) -> list[Asset]:
        stmt = select(Asset).where(
            Asset.id.in_(asset_ids),
            Asset.organization_id == organization_id,
        )
        return list((await self.db.execute(stmt)).scalars().all())
