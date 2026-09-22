"""Service facade to normalize raw scanner payloads (API / workers)."""

from __future__ import annotations

from typing import Any, Optional, Union
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, selectinload
from sqlalchemy import select

from app.core.enums import ScannerEngine
from app.models.scan import Scan
from app.normalization import (
    AssetResolver,
    FindingIngestionService,
    IngestStats,
    build_default_registry,
)
from app.normalization.base import RawInput
from app.normalization.compliance import enrich_compliance
from app.normalization.schema import NormalizedFinding


class NormalizationError(Exception):
    pass


class NormalizationService:
    """Parse raw tool output into NormalizedFinding and optionally ingest."""

    def __init__(self) -> None:
        self.registry = build_default_registry()

    def parse(
        self,
        engine: Union[ScannerEngine, str],
        raw: RawInput,
        *,
        enrich: bool = True,
    ) -> list[NormalizedFinding]:
        name = engine.value if isinstance(engine, ScannerEngine) else str(engine)
        try:
            parser = self.registry.get(name)
        except KeyError as exc:
            raise NormalizationError(f"Unsupported parser engine: {name}") from exc
        findings = parser.parse(raw)
        if enrich:
            findings = [enrich_compliance(f) for f in findings]
        return findings

    def ingest_sync(
        self,
        session: Session,
        *,
        scan: Scan,
        engine: Union[ScannerEngine, str],
        raw: RawInput,
    ) -> IngestStats:
        findings = self.parse(engine, raw, enrich=True)
        resolver = AssetResolver.from_assets(list(scan.assets))
        default_asset = scan.assets[0].id if scan.assets else None
        return FindingIngestionService(session).ingest(
            scan_id=scan.id,
            findings=findings,
            resolver=resolver,
            default_asset_id=default_asset,
        )


async def normalize_scan_raw_result(
    db: AsyncSession,
    scan_id: UUID,
    *,
    raw: Optional[RawInput] = None,
    engine: Optional[ScannerEngine] = None,
) -> dict[str, Any]:
    """
    Async helper for API: load scan, parse stored/provided raw, ingest via sync bridge.

    For simplicity, parsing is CPU-bound XML/JSON and runs in-process; DB writes use
    the async session by converting findings manually when needed.
    """
    stmt = select(Scan).options(selectinload(Scan.assets)).where(Scan.id == scan_id)
    scan = (await db.execute(stmt)).scalar_one_or_none()
    if scan is None:
        raise NormalizationError(f"Scan {scan_id} not found")

    eng = engine or scan.engine
    payload = raw
    if payload is None:
        last = (scan.config or {}).get("last_result") or {}
        payload = last.get("stdout_xml") or last.get("stdout") or last.get("raw")
    if not payload:
        raise NormalizationError("No raw scanner output available to normalize")

    service = NormalizationService()
    findings = service.parse(eng, payload, enrich=True)
    resolver = AssetResolver.from_assets(list(scan.assets))
    default_asset = scan.assets[0].id if scan.assets else None

    # Use a nested sync-style ingest against async session is awkward;
    # reuse FindingIngestionService patterns via explicit ORM adds on async session.
    from datetime import datetime, timezone

    from app.core.enums import FindingStatus
    from app.models.vulnerability import Vulnerability
    from app.normalization.fingerprint import compute_fingerprint

    stats = IngestStats()
    now = datetime.now(timezone.utc)

    for finding in findings:
        asset_id = resolver.resolve(finding.target_hint, fallback=default_asset)
        if asset_id is None:
            stats.skipped += 1
            if finding.target_hint:
                stats.unmatched_targets.append(finding.target_hint)
            continue

        fingerprint = compute_fingerprint(finding, asset_key=str(asset_id))
        existing = (
            await db.execute(
                select(Vulnerability).where(
                    Vulnerability.asset_id == asset_id,
                    Vulnerability.fingerprint == fingerprint,
                )
            )
        ).scalar_one_or_none()

        if existing is None:
            db.add(
                Vulnerability(
                    scan_id=scan.id,
                    asset_id=asset_id,
                    fingerprint=fingerprint,
                    title=finding.name,
                    description=finding.description,
                    severity=finding.severity,
                    status=FindingStatus.OPEN,
                    cve_id=finding.cve_id,
                    cwe_id=finding.cwe_id,
                    cvss_score=finding.cvss_score,
                    cvss_vector=finding.cvss_vector,
                    affected_component=finding.affected_component,
                    port=finding.port,
                    protocol=finding.protocol,
                    evidence=finding.evidence,
                    remediation=finding.remediation_steps,
                    owasp_category=finding.owasp_category,
                    mitre_attack_techniques=finding.mitre_tactics,
                    compliance_metadata=finding.compliance_metadata(),
                    raw_source=finding.raw_source,
                    source_tool=finding.source_tool,
                    first_seen_at=now,
                    last_seen_at=now,
                )
            )
            stats.inserted += 1
        else:
            existing.scan_id = scan.id
            existing.last_seen_at = now
            existing.title = finding.name
            existing.description = finding.description
            existing.severity = finding.severity
            existing.evidence = finding.evidence
            existing.compliance_metadata = finding.compliance_metadata()
            existing.raw_source = finding.raw_source
            if existing.status in {
                FindingStatus.REMEDIATED,
                FindingStatus.RESOLVED,
            }:
                existing.status = FindingStatus.REOPENED
            stats.updated += 1

    await db.flush()
    return {
        "scan_id": str(scan_id),
        "findings_parsed": len(findings),
        "inserted": stats.inserted,
        "updated": stats.updated,
        "skipped": stats.skipped,
        "unmatched_targets": stats.unmatched_targets[:20],
        "sample": [f.model_dump(mode="json") for f in findings[:5]],
    }
