"""Endpoints to preview / run vulnerability normalization."""

from __future__ import annotations

import uuid
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import RequirePentesterOrAdmin
from app.core.enums import ScannerEngine
from app.services.normalization_service import (
    NormalizationError,
    NormalizationService,
    normalize_scan_raw_result,
)

router = APIRouter(prefix="/normalize", tags=["normalization"])


class NormalizePreviewRequest(BaseModel):
    engine: ScannerEngine = ScannerEngine.NMAP
    raw: str = Field(min_length=1, description="Raw scanner XML/JSON output")


class NormalizeScanRequest(BaseModel):
    engine: Optional[ScannerEngine] = None
    raw: Optional[str] = Field(
        default=None,
        description="Optional raw override; defaults to scan.config.last_result",
    )


@router.post(
    "/preview",
    summary="Parse raw scanner output into unified findings (no DB write)",
)
async def preview_normalization(
    payload: NormalizePreviewRequest,
    _: RequirePentesterOrAdmin,
) -> dict[str, Any]:
    service = NormalizationService()
    try:
        findings = service.parse(payload.engine, payload.raw, enrich=True)
    except (NormalizationError, ValueError, TypeError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return {
        "engine": payload.engine.value,
        "count": len(findings),
        "findings": [f.model_dump(mode="json") for f in findings],
    }


@router.post(
    "/scans/{scan_id}",
    summary="Normalize stored/raw scan output and ingest (deduped by asset)",
)
async def normalize_and_ingest_scan(
    scan_id: uuid.UUID,
    payload: NormalizeScanRequest,
    _: RequirePentesterOrAdmin,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    try:
        return await normalize_scan_raw_result(
            db,
            scan_id,
            raw=payload.raw,
            engine=payload.engine,
        )
    except NormalizationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
