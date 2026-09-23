"""Compare two scans by re-parsing last_result fingerprints."""

from __future__ import annotations

from typing import Any, Optional
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.enums import ScanStatus
from app.models.scan import Scan, ScanAsset
from app.models.vulnerability import Vulnerability
from app.services.scan_result_utils import fingerprint_map, last_result
from app.services.scan_service import ScanNotFoundError


class ScanDiffError(Exception):
    pass


class ScanDiffService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def diff(
        self,
        scan_id: UUID,
        *,
        baseline_scan_id: Optional[UUID] = None,
        organization_id: Optional[UUID] = None,
    ) -> dict[str, Any]:
        scan = await self._get_scan(scan_id, organization_id=organization_id)
        if not last_result(scan):
            raise ScanDiffError("Current scan has no last_result to compare")

        baseline = None
        if baseline_scan_id is not None:
            baseline = await self._get_scan(
                baseline_scan_id, organization_id=organization_id
            )
        else:
            baseline = await self._previous_completed(scan, organization_id=organization_id)

        if baseline is None:
            raise ScanDiffError("No baseline scan found for comparison")
        if not last_result(baseline):
            raise ScanDiffError("Baseline scan has no last_result to compare")
        if baseline.organization_id != scan.organization_id:
            raise ScanDiffError("Baseline scan is outside organization scope")

        current_map = fingerprint_map(scan)
        baseline_map = fingerprint_map(baseline)

        new_keys = set(current_map) - set(baseline_map)
        resolved_keys = set(baseline_map) - set(current_map)
        unchanged = set(current_map) & set(baseline_map)

        # Resolve current DB vulnerability ids for new findings when possible
        fps = list(new_keys | resolved_keys | unchanged)
        vuln_by_fp: dict[str, UUID] = {}
        if fps:
            stmt = select(Vulnerability.fingerprint, Vulnerability.id).where(
                Vulnerability.organization_id == scan.organization_id,
                Vulnerability.fingerprint.in_(fps),
            )
            for fp, vid in (await self.db.execute(stmt)).all():
                vuln_by_fp[fp] = vid

        def row(fp: str, finding, *, include_vuln: bool) -> dict[str, Any]:
            item: dict[str, Any] = {
                "fingerprint": fp,
                "title": finding.name,
                "severity": finding.severity.value
                if hasattr(finding.severity, "value")
                else str(finding.severity),
                "target_hint": finding.target_hint,
                "port": finding.port,
            }
            if include_vuln and fp in vuln_by_fp:
                item["vulnerability_id"] = str(vuln_by_fp[fp])
            return item

        new_items = [row(k, current_map[k], include_vuln=True) for k in sorted(new_keys)]
        resolved_items = [
            row(k, baseline_map[k], include_vuln=False) for k in sorted(resolved_keys)
        ]

        return {
            "scan_id": str(scan.id),
            "baseline_scan_id": str(baseline.id),
            "engine": scan.engine.value,
            "method": "reparse_last_result",
            "new": new_items,
            "resolved": resolved_items,
            "unchanged_count": len(unchanged),
            "counts": {
                "new": len(new_items),
                "resolved": len(resolved_items),
                "unchanged": len(unchanged),
            },
        }

    async def _get_scan(
        self, scan_id: UUID, *, organization_id: Optional[UUID]
    ) -> Scan:
        stmt = (
            select(Scan)
            .options(selectinload(Scan.assets))
            .where(Scan.id == scan_id)
        )
        if organization_id is not None:
            stmt = stmt.where(Scan.organization_id == organization_id)
        scan = (await self.db.execute(stmt)).scalar_one_or_none()
        if scan is None:
            raise ScanNotFoundError(f"Scan {scan_id} not found")
        return scan

    async def _previous_completed(
        self, scan: Scan, *, organization_id: Optional[UUID]
    ) -> Optional[Scan]:
        asset_ids = [a.id for a in (scan.assets or [])]
        if not asset_ids:
            return None

        # Scans sharing at least one asset + same engine, completed before this one
        stmt = (
            select(Scan)
            .join(ScanAsset, ScanAsset.scan_id == Scan.id)
            .options(selectinload(Scan.assets))
            .where(
                Scan.organization_id == scan.organization_id,
                Scan.engine == scan.engine,
                Scan.status == ScanStatus.COMPLETED,
                Scan.id != scan.id,
                ScanAsset.asset_id.in_(asset_ids),
            )
            .order_by(Scan.completed_at.desc().nullslast(), Scan.created_at.desc())
            .limit(1)
        )
        if organization_id is not None:
            stmt = stmt.where(Scan.organization_id == organization_id)
        return (await self.db.execute(stmt)).scalar_one_or_none()
