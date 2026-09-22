"""API helpers for the custom NexuSec asyncio scanner engine."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.core.deps import RequirePentesterOrAdmin
from app.normalization.schema import NormalizedFinding

ROOT = Path(__file__).resolve().parents[3]
SCANNER_PATH = ROOT / "scanners" / "python"
if str(SCANNER_PATH) not in sys.path:
    sys.path.insert(0, str(SCANNER_PATH))

router = APIRouter(prefix="/scanner", tags=["scanner"])


class CustomScanRequest(BaseModel):
    targets: list[str] = Field(min_length=1)
    ports: Optional[list[int]] = None
    exclusions: list[str] = Field(default_factory=list)
    rate_per_second: float = Field(default=25.0, gt=0, le=500)
    max_concurrent_probes: int = Field(default=50, ge=1, le=500)
    connect_timeout: float = Field(default=1.5, gt=0, le=30)
    grab_banner: bool = True
    dry_run: bool = Field(
        default=False,
        description="If true, only validate config/exclusions without probing",
    )


@router.post(
    "/run",
    summary="Run custom NexuSec asyncio scanner (sync preview / lab use)",
)
async def run_custom_scanner(
    payload: CustomScanRequest,
    _: RequirePentesterOrAdmin,
) -> dict[str, Any]:
    from nexusec_scanner import ExclusionList, ScanConfig, run_scan_sync
    from nexusec_scanner import DEFAULT_PORTS
    from workers.tool_wrappers.validators import TargetValidationError, validate_targets

    try:
        targets = validate_targets(payload.targets)
    except TargetValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    exclusions = ExclusionList.from_entries(payload.exclusions)
    if payload.dry_run:
        excluded = [t for t in targets if exclusions.is_excluded(t)]
        scanned = [t for t in targets if t not in excluded]
        return {
            "dry_run": True,
            "targets_scanned": scanned,
            "targets_excluded": excluded,
            "ports": payload.ports or list(DEFAULT_PORTS),
        }

    config = ScanConfig(
        ports=payload.ports or list(DEFAULT_PORTS),
        connect_timeout=payload.connect_timeout,
        grab_banner=payload.grab_banner,
        max_concurrent_probes=payload.max_concurrent_probes,
        rate_per_second=payload.rate_per_second,
        exclusions=exclusions,
    )
    try:
        report = run_scan_sync(targets, config=config)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)
        ) from exc

    # Validate findings against unified schema
    normalized = [NormalizedFinding.model_validate(f) for f in report.findings]
    return {
        "stats": report.stats,
        "targets_excluded": report.targets_excluded,
        "targets_circuit_open": report.targets_circuit_open,
        "findings": [f.model_dump(mode="json") for f in normalized],
    }
