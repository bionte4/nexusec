"""Scan orchestration service — create jobs and enqueue Celery workers."""

from __future__ import annotations

import math
import sys
from pathlib import Path
from typing import Any, Optional
from uuid import UUID

from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import get_settings
from app.core.enums import ScanStatus, ScannerEngine
from app.models.asset import Asset
from app.models.scan import Scan, ScanAsset
from app.schemas.scan import ScanCreate, ScanListResponse, ScanRead
from app.services.audit_service import AuditService
from app.services.scan_policy import assert_production_scanner_config, assert_roe_for_scan

# Allow importing Celery tasks from /workers
_ROOT = Path(__file__).resolve().parents[3]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


class ScanNotFoundError(Exception):
    pass


class ScanValidationError(Exception):
    pass


def _to_read(scan: Scan) -> ScanRead:
    from workers.tool_wrappers.auth_headers import redact_auth_in_config

    asset_ids = [a.id for a in (scan.assets or [])]
    data = ScanRead.model_validate(scan)
    safe_config = redact_auth_in_config(dict(data.config or {}))
    return data.model_copy(update={"asset_ids": asset_ids, "config": safe_config})


class ScanService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def create(
        self,
        payload: ScanCreate,
        *,
        organization_id: UUID,
        created_by_id: Optional[UUID] = None,
    ) -> tuple[ScanRead, Optional[str]]:
        assets = await self._load_assets(payload.asset_ids, organization_id=organization_id)
        if len(assets) != len(set(payload.asset_ids)):
            raise ScanValidationError("One or more asset_ids were not found")

        if payload.engine in {
            ScannerEngine.NMAP,
            ScannerEngine.NEXUSEC,
            ScannerEngine.NUCLEI,
            ScannerEngine.OPENVAS,
            ScannerEngine.ZAP,
            ScannerEngine.OSINT,
        }:
            self._ensure_scan_targets(assets, engine=payload.engine)
            try:
                assert_roe_for_scan(payload.config or {}, settings=get_settings())
            except ValueError as exc:
                raise ScanValidationError(str(exc)) from exc

        scan = Scan(
            organization_id=organization_id,
            name=payload.name,
            scan_type=payload.scan_type,
            engine=payload.engine,
            status=ScanStatus.PENDING,
            progress=0.0,
            config=payload.config or {},
            created_by_id=created_by_id,
        )
        self.db.add(scan)
        await self.db.flush()

        for asset in assets:
            self.db.add(ScanAsset(scan_id=scan.id, asset_id=asset.id))
        await self.db.flush()

        task_id: Optional[str] = None
        if payload.start_immediately:
            # enqueue() commits so Celery workers see the row before .delay()
            task_id = await self.enqueue(
                scan.id, engine=payload.engine, actor_id=created_by_id
            )

        await self.db.refresh(scan, attribute_names=["assets"])
        # reload with assets
        scan = await self._get_scan(scan.id)
        return _to_read(scan), task_id

    async def enqueue(
        self,
        scan_id: UUID,
        *,
        engine: Optional[ScannerEngine] = None,
        actor_id: Optional[UUID] = None,
    ) -> str:
        scan = await self._get_scan(scan_id)
        eng = engine or scan.engine
        try:
            assert_roe_for_scan(
                scan.config if isinstance(scan.config, dict) else {},
                settings=get_settings(),
            )
            assert_production_scanner_config(
                eng,
                scan.config if isinstance(scan.config, dict) else {},
                settings=get_settings(),
            )
        except ValueError as exc:
            raise ScanValidationError(str(exc)) from exc

        # Critical: commit before broker publish. Otherwise an idle scanner-worker
        # can claim the task before Postgres has the Scan row → "scan not found"
        # and the UI stays QUEUED forever.
        await self.db.commit()

        if eng == ScannerEngine.NMAP:
            from workers.tasks import run_nmap_scan

            async_result = run_nmap_scan.delay(str(scan_id))
        elif eng == ScannerEngine.NEXUSEC:
            from workers.tasks import run_nexusec_scan

            async_result = run_nexusec_scan.delay(str(scan_id))
        elif eng == ScannerEngine.NUCLEI:
            from workers.tasks import run_nuclei_scan

            async_result = run_nuclei_scan.delay(str(scan_id))
        elif eng == ScannerEngine.OPENVAS:
            from workers.tasks import run_openvas_scan

            async_result = run_openvas_scan.delay(str(scan_id))
        elif eng == ScannerEngine.ZAP:
            from workers.tasks import run_zap_scan

            async_result = run_zap_scan.delay(str(scan_id))
        elif eng == ScannerEngine.OSINT:
            from workers.tasks import run_osint_scan

            async_result = run_osint_scan.delay(str(scan_id))
        else:
            raise ScanValidationError(
                f"Engine '{eng.value}' cannot be live-queued "
                "(supported workers: nmap, nuclei, nexusec, openvas, zap, osint; "
                "use POST /api/v1/scans/import-report for sarif/generic/trivy/burp/nessus)"
            )

        scan.status = ScanStatus.QUEUED
        scan.celery_task_id = async_result.id
        await self.db.flush()
        try:
            await AuditService(self.db).record(
                action="scan.enqueue",
                resource_type="scans",
                resource_id=str(scan.id),
                actor_id=actor_id or scan.created_by_id,
                organization_id=scan.organization_id,
                details={
                    "engine": eng.value,
                    "scan_type": scan.scan_type.value
                    if hasattr(scan.scan_type, "value")
                    else str(scan.scan_type),
                    "celery_task_id": async_result.id,
                    "roe_acknowledged": bool(
                        isinstance(scan.config, dict)
                        and scan.config.get("roe_acknowledged") is True
                    ),
                    "lab_mode": bool(
                        isinstance(scan.config, dict) and scan.config.get("lab_mode") is True
                    ),
                },
                status_code=202,
            )
        except Exception:
            # Never block enqueue on audit failure
            pass
        return async_result.id

    async def get(self, scan_id: UUID, *, organization_id: Optional[UUID] = None) -> ScanRead:
        scan = await self._get_scan(scan_id, organization_id=organization_id)
        return _to_read(scan)

    async def list(
        self,
        *,
        page: int = 1,
        page_size: int = 20,
        status: Optional[ScanStatus] = None,
        engine: Optional[ScannerEngine] = None,
        organization_id: Optional[UUID] = None,
    ) -> ScanListResponse:
        page = max(page, 1)
        page_size = min(max(page_size, 1), 100)
        filters: list[Any] = []
        if organization_id is not None:
            filters.append(Scan.organization_id == organization_id)
        if status is not None:
            filters.append(Scan.status == status)
        if engine is not None:
            filters.append(Scan.engine == engine)

        count_stmt = select(func.count()).select_from(Scan)
        if filters:
            count_stmt = count_stmt.where(*filters)
        total = int(await self.db.scalar(count_stmt) or 0)

        stmt: Select[tuple[Scan]] = (
            select(Scan)
            .options(selectinload(Scan.assets))
            .order_by(Scan.created_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        if filters:
            stmt = stmt.where(*filters)

        rows = (await self.db.execute(stmt)).scalars().all()
        pages = math.ceil(total / page_size) if total else 0
        return ScanListResponse(
            items=[_to_read(s) for s in rows],
            total=total,
            page=page,
            page_size=page_size,
            pages=pages,
        )

    async def _get_scan(
        self, scan_id: UUID, *, organization_id: Optional[UUID] = None
    ) -> Scan:
        stmt = select(Scan).options(selectinload(Scan.assets)).where(Scan.id == scan_id)
        if organization_id is not None:
            stmt = stmt.where(Scan.organization_id == organization_id)
        scan = (await self.db.execute(stmt)).scalar_one_or_none()
        if scan is None:
            raise ScanNotFoundError(f"Scan {scan_id} not found")
        return scan

    async def _load_assets(
        self, asset_ids: list[UUID], *, organization_id: UUID
    ) -> list[Asset]:
        stmt = select(Asset).where(
            Asset.id.in_(asset_ids),
            Asset.organization_id == organization_id,
        )
        return list((await self.db.execute(stmt)).scalars().all())

    @staticmethod
    def _ensure_scan_targets(assets: list[Asset], *, engine: ScannerEngine) -> None:
        from app.core.enums import AssetType

        for asset in assets:
            if engine == ScannerEngine.NUCLEI or engine == ScannerEngine.ZAP:
                if (asset.url or "").strip():
                    continue
            if engine == ScannerEngine.OSINT:
                if asset.domain or asset.hostname or (asset.url or "").strip():
                    continue
                raise ScanValidationError(
                    f"Asset {asset.id} needs a domain/hostname/URL for OSINT"
                )
            if asset.asset_type == AssetType.IP and asset.ip_address:
                continue
            if asset.asset_type == AssetType.DOMAIN and asset.domain:
                continue
            if asset.ip_address or asset.domain or asset.hostname:
                continue
            raise ScanValidationError(
                f"Asset {asset.id} has no IP/domain/URL suitable for {engine.value}"
            )
