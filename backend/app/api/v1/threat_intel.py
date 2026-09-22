"""Threat intelligence endpoints — CISA KEV / NVD enrichment status."""

from __future__ import annotations

import math
import sys
from pathlib import Path

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.core.deps import RequireAdmin, RequireAnyAuthenticated
from app.core.enums import ACTIVE_FINDING_STATUSES
from app.models.vulnerability import Vulnerability
from app.schemas.threat_intel import (
    ActivelyExploitedItem,
    ActivelyExploitedListResponse,
    ThreatIntelStatusResponse,
    ThreatIntelSyncRequest,
    ThreatIntelSyncResponse,
)
from app.services.threat_intel import ThreatIntelService

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from workers.db import session_scope  # noqa: E402

router = APIRouter(prefix="/threat-intel", tags=["threat-intel"])


@router.get(
    "/status",
    response_model=ThreatIntelStatusResponse,
    summary="Threat intelligence enrichment status",
)
async def threat_intel_status(_: RequireAnyAuthenticated) -> ThreatIntelStatusResponse:
    settings = get_settings()
    with session_scope() as session:
        summary = ThreatIntelService(session).status_summary()
    return ThreatIntelStatusResponse(
        kev_catalog_entries=summary["kev_catalog_entries"],
        cves_with_public_exploit=summary["cves_with_public_exploit"],
        actively_exploited_open_findings=summary["actively_exploited_open_findings"],
        last_sync_runs=summary["last_sync_runs"],
        kev_catalog_url=settings.kev_catalog_url,
        sync_enabled=settings.threat_intel_sync_enabled,
    )


@router.get(
    "/actively-exploited",
    response_model=ActivelyExploitedListResponse,
    summary="Vulnerabilities under active exploitation (CISA KEV)",
)
async def list_actively_exploited(
    _: RequireAnyAuthenticated,
    db: AsyncSession = Depends(get_db),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    include_resolved: bool = Query(False),
) -> ActivelyExploitedListResponse:
    filters = [Vulnerability.is_actively_exploited.is_(True)]
    if not include_resolved:
        filters.append(Vulnerability.status.in_(list(ACTIVE_FINDING_STATUSES)))

    total = (await db.scalar(select(func.count()).select_from(Vulnerability).where(*filters))) or 0
    pages = max(1, math.ceil(total / page_size)) if total else 0
    offset = (page - 1) * page_size
    stmt = (
        select(Vulnerability)
        .where(*filters)
        .order_by(
            Vulnerability.threat_risk_score.desc().nullslast(),
            Vulnerability.updated_at.desc(),
        )
        .offset(offset)
        .limit(page_size)
    )
    rows = list((await db.scalars(stmt)).all())
    return ActivelyExploitedListResponse(
        items=[ActivelyExploitedItem.model_validate(r) for r in rows],
        total=int(total),
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.post(
    "/sync",
    response_model=ThreatIntelSyncResponse,
    summary="Trigger KEV sync and/or vulnerability enrichment (Admin)",
)
async def trigger_threat_intel_sync(
    payload: ThreatIntelSyncRequest,
    _: RequireAdmin,
) -> ThreatIntelSyncResponse:
    from workers.threat_intel_tasks import enrich_vulnerabilities_task, sync_kev_catalog_task

    task_ids: list[str] = []
    kev_result = None
    enrich_result = None

    if payload.sync_kev:
        async_result = sync_kev_catalog_task.delay()
        task_ids.append(async_result.id)
        kev_result = {"queued": True, "task_id": async_result.id}

    if payload.enrich:
        async_result = enrich_vulnerabilities_task.delay(
            limit=payload.enrich_limit,
            fetch_nvd=payload.fetch_nvd,
        )
        task_ids.append(async_result.id)
        enrich_result = {"queued": True, "task_id": async_result.id}

    return ThreatIntelSyncResponse(kev=kev_result, enrich=enrich_result, task_ids=task_ids)
