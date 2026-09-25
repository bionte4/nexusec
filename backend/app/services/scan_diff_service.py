"""Compare two scans by re-parsing last_result fingerprints.

Also supports cross-engine comparison for scans that share assets
(nmap / nuclei / nexusec / openvas).
"""

from __future__ import annotations

import re
from typing import Any, Optional
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.enums import ScanStatus, ScannerEngine
from app.models.scan import Scan, ScanAsset
from app.models.vulnerability import Vulnerability
from app.normalization.schema import NormalizedFinding
from app.services.scan_result_utils import findings_from_scan, fingerprint_map, last_result
from app.services.scan_service import ScanNotFoundError

_COMPARE_ENGINES = (
    ScannerEngine.NMAP,
    ScannerEngine.NUCLEI,
    ScannerEngine.NEXUSEC,
    ScannerEngine.OPENVAS,
)


class ScanDiffError(Exception):
    pass


def soft_match_key(finding: NormalizedFinding) -> str:
    """Cross-engine match key: prefer CVE, else port+protocol+normalized title."""
    if finding.cve_id:
        return f"cve:{finding.cve_id.upper()}"
    port = finding.port if finding.port is not None else "-"
    proto = (finding.protocol or "").lower() or "-"
    title = re.sub(r"\s+", " ", (finding.name or "").strip().lower())[:80]
    return f"loc:{port}/{proto}:{title}"


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

    async def compare_engines(
        self,
        scan_id: UUID,
        *,
        organization_id: Optional[UUID] = None,
    ) -> dict[str, Any]:
        """Compare latest completed scans per engine that share assets with this scan."""
        anchor = await self._get_scan(scan_id, organization_id=organization_id)
        asset_ids = [a.id for a in (anchor.assets or [])]
        if not asset_ids:
            raise ScanDiffError("Scan has no linked assets for engine comparison")

        engines_payload: dict[str, Any] = {}
        key_to_engines: dict[str, set[str]] = {}
        key_samples: dict[str, dict[str, Any]] = {}

        for engine in _COMPARE_ENGINES:
            peer = await self._latest_completed_for_engine(
                organization_id=anchor.organization_id,
                engine=engine,
                asset_ids=asset_ids,
            )
            if peer is None or not last_result(peer):
                engines_payload[engine.value] = {
                    "scan_id": None,
                    "status": "missing",
                    "finding_count": 0,
                    "findings": [],
                }
                continue

            findings = findings_from_scan(peer)
            items: list[dict[str, Any]] = []
            for finding in findings:
                key = soft_match_key(finding)
                sev = (
                    finding.severity.value
                    if hasattr(finding.severity, "value")
                    else str(finding.severity)
                )
                row = {
                    "match_key": key,
                    "title": finding.name,
                    "severity": sev,
                    "cve_id": finding.cve_id,
                    "port": finding.port,
                    "protocol": finding.protocol,
                    "source_tool": finding.source_tool,
                    "target_hint": finding.target_hint,
                }
                items.append(row)
                key_to_engines.setdefault(key, set()).add(engine.value)
                key_samples.setdefault(key, row)

            engines_payload[engine.value] = {
                "scan_id": str(peer.id),
                "name": peer.name,
                "status": peer.status.value
                if hasattr(peer.status, "value")
                else str(peer.status),
                "completed_at": peer.completed_at.isoformat()
                if peer.completed_at
                else None,
                "finding_count": len(items),
                "findings": items[:50],
            }

        present = [
            eng
            for eng, payload in engines_payload.items()
            if payload.get("scan_id") is not None
        ]
        if len(present) < 2:
            raise ScanDiffError(
                "Need at least two completed scans (nmap/nuclei/nexusec/openvas) "
                "on the same asset(s) to compare engines"
            )

        shared = sorted(k for k, engs in key_to_engines.items() if len(engs) >= 2)
        unique_by_engine: dict[str, list[dict[str, Any]]] = {e: [] for e in present}
        for key, engs in key_to_engines.items():
            if len(engs) != 1:
                continue
            only = next(iter(engs))
            if only in unique_by_engine:
                unique_by_engine[only].append(key_samples[key])

        return {
            "anchor_scan_id": str(anchor.id),
            "asset_ids": [str(a) for a in asset_ids],
            "method": "soft_match_cve_or_port_title",
            "engines_compared": present,
            "engines": engines_payload,
            "shared": [
                {
                    **key_samples[k],
                    "engines": sorted(key_to_engines[k]),
                }
                for k in shared[:40]
            ],
            "unique_by_engine": {
                eng: items[:20] for eng, items in unique_by_engine.items()
            },
            "counts": {
                "engines_with_scans": len(present),
                "shared_keys": len(shared),
                "unique": {eng: len(items) for eng, items in unique_by_engine.items()},
                "per_engine": {
                    eng: engines_payload[eng]["finding_count"] for eng in present
                },
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

    async def _latest_completed_for_engine(
        self,
        *,
        organization_id: UUID,
        engine: ScannerEngine,
        asset_ids: list[UUID],
    ) -> Optional[Scan]:
        stmt = (
            select(Scan)
            .join(ScanAsset, ScanAsset.scan_id == Scan.id)
            .options(selectinload(Scan.assets))
            .where(
                Scan.organization_id == organization_id,
                Scan.engine == engine,
                Scan.status == ScanStatus.COMPLETED,
                ScanAsset.asset_id.in_(asset_ids),
            )
            .order_by(Scan.completed_at.desc().nullslast(), Scan.created_at.desc())
            .limit(1)
        )
        return (await self.db.execute(stmt)).scalar_one_or_none()
