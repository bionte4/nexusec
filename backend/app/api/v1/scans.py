"""Scan job endpoints — create and enqueue Celery workers (tenant-scoped)."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import RequirePentesterOrAdmin, RequireTenant
from app.core.enums import ScanStatus, ScannerEngine
from app.schemas.scan import (
    ScanCreate,
    ScanEnqueueResponse,
    ScanListResponse,
    ScanRead,
)
from app.services.scan_diff_service import ScanDiffError, ScanDiffService
from app.services.scan_discovery_service import ScanDiscoveryError, ScanDiscoveryService
from app.services.scan_service import (
    ScanNotFoundError,
    ScanService,
    ScanValidationError,
)
from pydantic import BaseModel, Field
from typing import Any, Optional

router = APIRouter(prefix="/scans", tags=["scans"])


def get_scan_service(db: AsyncSession = Depends(get_db)) -> ScanService:
    return ScanService(db)


def _org_scope(tenant: RequireTenant) -> uuid.UUID | None:
    return None if tenant.cross_tenant else tenant.organization_id


@router.post(
    "",
    response_model=ScanEnqueueResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create scan and optionally enqueue Celery worker (Admin/Pentester)",
)
async def create_scan(
    payload: ScanCreate,
    tenant: RequireTenant,
    current_user: RequirePentesterOrAdmin,
    service: ScanService = Depends(get_scan_service),
) -> ScanEnqueueResponse:
    org_id = tenant.require_organization_id()
    try:
        scan, task_id = await service.create(
            payload, organization_id=org_id, created_by_id=current_user.id
        )
    except ScanValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    message = f"Scan queued (task={task_id})" if task_id else "Scan created (not started)"
    return ScanEnqueueResponse(scan=scan, celery_task_id=task_id, message=message)


@router.post(
    "/{scan_id}/start",
    response_model=ScanEnqueueResponse,
    summary="Enqueue an existing scan job",
)
async def start_scan(
    scan_id: uuid.UUID,
    tenant: RequireTenant,
    _: RequirePentesterOrAdmin,
    service: ScanService = Depends(get_scan_service),
) -> ScanEnqueueResponse:
    org = _org_scope(tenant)
    try:
        # Ensure scan is visible in tenant before enqueue
        await service.get(scan_id, organization_id=org)
        task_id = await service.enqueue(scan_id)
        scan = await service.get(scan_id, organization_id=org)
    except ScanNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ScanValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return ScanEnqueueResponse(
        scan=scan,
        celery_task_id=task_id,
        message=f"Scan queued (task={task_id})",
    )


@router.get(
    "",
    response_model=ScanListResponse,
    summary="List scans",
)
async def list_scans(
    tenant: RequireTenant,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status_filter: ScanStatus | None = Query(None, alias="status"),
    engine: ScannerEngine | None = Query(None),
    service: ScanService = Depends(get_scan_service),
) -> ScanListResponse:
    return await service.list(
        page=page,
        page_size=page_size,
        status=status_filter,
        engine=engine,
        organization_id=_org_scope(tenant),
    )


@router.get(
    "/{scan_id}",
    response_model=ScanRead,
    summary="Get scan by ID",
)
async def get_scan(
    scan_id: uuid.UUID,
    tenant: RequireTenant,
    service: ScanService = Depends(get_scan_service),
) -> ScanRead:
    try:
        return await service.get(scan_id, organization_id=_org_scope(tenant))
    except ScanNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.get(
    "/{scan_id}/evidence",
    summary="Get scan evidence / raw last_result summary",
)
async def get_scan_evidence(
    scan_id: uuid.UUID,
    tenant: RequireTenant,
    service: ScanService = Depends(get_scan_service),
) -> dict[str, Any]:
    try:
        scan = await service.get(scan_id, organization_id=_org_scope(tenant))
    except ScanNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    result = (scan.config or {}).get("last_result") or {}
    if not isinstance(result, dict):
        result = {}

    stdout = (
        result.get("stdout_xml")
        or result.get("stdout_jsonl")
        or result.get("stdout")
        or ""
    )
    if not isinstance(stdout, str):
        stdout = str(stdout)
    stderr = result.get("stderr") or ""
    if not isinstance(stderr, str):
        stderr = str(stderr)

    max_preview = 20_000
    return {
        "scan_id": str(scan.id),
        "status": scan.status,
        "progress": scan.progress,
        "error_message": scan.error_message,
        "engine": scan.engine,
        "command": result.get("command"),
        "returncode": result.get("returncode"),
        "truncated": bool(result.get("truncated")),
        "finished_at": result.get("finished_at"),
        "ingest": result.get("ingest"),
        "stderr": stderr[:10_000],
        "stdout_preview": stdout[:max_preview],
        "stdout_truncated": len(stdout) > max_preview,
        "stdout_chars": len(stdout),
    }


@router.get(
    "/{scan_id}/diff",
    summary="Diff findings vs baseline scan (re-parse last_result)",
)
async def diff_scan(
    scan_id: uuid.UUID,
    tenant: RequireTenant,
    baseline_scan_id: uuid.UUID | None = Query(None),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    try:
        return await ScanDiffService(db).diff(
            scan_id,
            baseline_scan_id=baseline_scan_id,
            organization_id=_org_scope(tenant),
        )
    except ScanNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ScanDiffError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.get(
    "/{scan_id}/compare-engines",
    summary="Compare latest nmap/nuclei/nexusec/openvas scans on the same asset(s)",
)
async def compare_engines(
    scan_id: uuid.UUID,
    tenant: RequireTenant,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    try:
        return await ScanDiffService(db).compare_engines(
            scan_id,
            organization_id=_org_scope(tenant),
        )
    except ScanNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ScanDiffError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


class DiscoverAcceptHost(BaseModel):
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    name: Optional[str] = None
    criticality: Optional[str] = None


class DiscoverAcceptRequest(BaseModel):
    hosts: list[DiscoverAcceptHost] = Field(min_length=1)


@router.get(
    "/{scan_id}/discovered-hosts",
    summary="List hosts discovered in an nmap scan XML",
)
async def list_discovered_hosts(
    scan_id: uuid.UUID,
    tenant: RequireTenant,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    try:
        return await ScanDiscoveryService(db).discovered_hosts(
            scan_id, organization_id=_org_scope(tenant)
        )
    except ScanNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ScanDiscoveryError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post(
    "/{scan_id}/discovered-hosts/accept",
    summary="Register selected discovered hosts as assets",
)
async def accept_discovered_hosts(
    scan_id: uuid.UUID,
    payload: DiscoverAcceptRequest,
    tenant: RequireTenant,
    current_user: RequirePentesterOrAdmin,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    org_id = tenant.require_organization_id()
    try:
        return await ScanDiscoveryService(db).accept_hosts(
            scan_id,
            [h.model_dump(exclude_none=True) for h in payload.hosts],
            organization_id=org_id,
            created_by_id=current_user.id,
        )
    except ScanNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except (ScanDiscoveryError, ScanValidationError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
