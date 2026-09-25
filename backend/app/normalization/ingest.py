"""Ingest normalized findings into PostgreSQL with asset-level dedup."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional, Protocol
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.enums import FindingStatus
from app.services.sla import compute_remediation_due_at
from app.models.asset import Asset
from app.models.vulnerability import Vulnerability
from app.normalization.compliance import enrich_compliance
from app.normalization.fingerprint import compute_fingerprint
from app.normalization.schema import NormalizedFinding


class SupportsScalar(Protocol):
    def scalar_one_or_none(self) -> Any: ...


@dataclass
class IngestStats:
    inserted: int = 0
    updated: int = 0
    skipped: int = 0
    unmatched_targets: list[str] = field(default_factory=list)


@dataclass
class AssetResolver:
    """Map scanner target hints (IP / domain / hostname) → asset UUID."""

    by_key: dict[str, UUID]

    @classmethod
    def from_assets(cls, assets: list[Asset]) -> AssetResolver:
        mapping: dict[str, UUID] = {}
        for asset in assets:
            if asset.ip_address:
                mapping[str(asset.ip_address).lower()] = asset.id
            if asset.domain:
                mapping[asset.domain.lower()] = asset.id
            if asset.hostname:
                mapping[asset.hostname.lower()] = asset.id
            mapping[str(asset.id)] = asset.id
        return cls(by_key=mapping)

    def resolve(self, hint: Optional[str], *, fallback: Optional[UUID] = None) -> Optional[UUID]:
        if hint:
            key = hint.strip().lower()
            if key in self.by_key:
                return self.by_key[key]
            # strip brackets / ports
            if key.startswith("[") and "]" in key:
                key = key[1 : key.index("]")]
                if key in self.by_key:
                    return self.by_key[key]
            if ":" in key and key.count(":") == 1:
                host = key.split(":", 1)[0]
                if host in self.by_key:
                    return self.by_key[host]
        return fallback


class FindingIngestionService:
    """
    Persist normalized findings.

    Dedup key: unique (asset_id, fingerprint). Re-seeing a finding updates
    ``last_seen_at`` and refreshes evidence / scan linkage instead of inserting.
    """

    def __init__(self, session: Session) -> None:
        self.session = session

    def ingest(
        self,
        *,
        scan_id: UUID,
        findings: list[NormalizedFinding],
        resolver: AssetResolver,
        organization_id: UUID,
        default_asset_id: Optional[UUID] = None,
        enrich: bool = True,
    ) -> IngestStats:
        stats = IngestStats()
        now = datetime.now(timezone.utc)

        for raw_finding in findings:
            finding = enrich_compliance(raw_finding) if enrich else raw_finding
            asset_id = resolver.resolve(finding.target_hint, fallback=default_asset_id)
            if asset_id is None:
                stats.skipped += 1
                if finding.target_hint:
                    stats.unmatched_targets.append(finding.target_hint)
                continue

            fingerprint = compute_fingerprint(finding, asset_key=str(asset_id))

            existing = self.session.execute(
                select(Vulnerability).where(
                    Vulnerability.asset_id == asset_id,
                    Vulnerability.fingerprint == fingerprint,
                )
            ).scalar_one_or_none()

            if existing is None:
                row = Vulnerability(
                    organization_id=organization_id,
                    scan_id=scan_id,
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
                    remediation_due_at=compute_remediation_due_at(finding.severity, from_time=now),
                )
                self.session.add(row)
                stats.inserted += 1
            else:
                existing.scan_id = scan_id
                existing.last_seen_at = now
                existing.title = finding.name
                existing.description = finding.description
                existing.severity = finding.severity
                existing.cve_id = finding.cve_id
                existing.cwe_id = finding.cwe_id
                existing.cvss_score = finding.cvss_score
                existing.cvss_vector = finding.cvss_vector
                existing.affected_component = finding.affected_component
                existing.port = finding.port
                existing.protocol = finding.protocol
                existing.evidence = finding.evidence
                existing.remediation = finding.remediation_steps
                existing.mitre_attack_techniques = finding.mitre_tactics
                existing.compliance_metadata = finding.compliance_metadata()
                existing.raw_source = finding.raw_source
                existing.source_tool = finding.source_tool
                # Do not reopen false positives automatically
                if existing.status in {
                    FindingStatus.REMEDIATED,
                    FindingStatus.RESOLVED,
                }:
                    existing.status = FindingStatus.REOPENED
                self.session.add(existing)
                stats.updated += 1

        self.session.flush()
        return stats
