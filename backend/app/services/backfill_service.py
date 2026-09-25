"""One-shot backfill for NIST compliance tags and remediation SLA due dates."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import ACTIVE_FINDING_STATUSES, Severity
from app.models.vulnerability import Vulnerability
from app.normalization.compliance import enrich_compliance
from app.normalization.schema import NormalizedFinding
from app.services.sla import compute_remediation_due_at


class BackfillService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def backfill_nist_and_sla(
        self,
        *,
        organization_id: Optional[UUID] = None,
        limit: int = 500,
        fill_nist: bool = True,
        fill_sla: bool = True,
    ) -> dict[str, Any]:
        stmt = select(Vulnerability).order_by(Vulnerability.created_at.asc()).limit(limit)
        if organization_id is not None:
            stmt = stmt.where(Vulnerability.organization_id == organization_id)
        vulns = list((await self.db.execute(stmt)).scalars().all())

        nist_updated = 0
        sla_updated = 0
        for vuln in vulns:
            changed = False
            if fill_nist:
                meta = dict(vuln.compliance_metadata or {})
                csf = list(meta.get("nist_csf") or [])
                sp = list(meta.get("nist_800_53") or [])
                if not csf or not sp:
                    seed = NormalizedFinding(
                        vuln_id=(vuln.fingerprint or "backfill")[:64],
                        name=vuln.title,
                        description=vuln.description,
                        severity=vuln.severity
                        if isinstance(vuln.severity, Severity)
                        else Severity.UNKNOWN,
                        cwe_id=vuln.cwe_id,
                        cve_id=vuln.cve_id,
                        port=vuln.port,
                        protocol=vuln.protocol,
                        affected_component=vuln.affected_component,
                        source_tool=vuln.source_tool or "unknown",
                        iso_27001_clause=list(meta.get("iso_27001") or []),
                        pci_dss_requirement=list(meta.get("pci_dss") or []),
                        gdpr_risk_flag=bool(meta.get("gdpr_risk_flag")),
                        nist_csf=csf,
                        nist_800_53=sp,
                    )
                    enriched = enrich_compliance(seed)
                    if not csf and enriched.nist_csf:
                        meta["nist_csf"] = list(enriched.nist_csf)
                        changed = True
                    if not sp and enriched.nist_800_53:
                        meta["nist_800_53"] = list(enriched.nist_800_53)
                        changed = True
                    if changed:
                        # Preserve existing ISO/PCI/GDPR; only fill NIST gaps
                        vuln.compliance_metadata = meta
                        nist_updated += 1

            if (
                fill_sla
                and vuln.remediation_due_at is None
                and vuln.status in ACTIVE_FINDING_STATUSES
            ):
                vuln.remediation_due_at = compute_remediation_due_at(
                    vuln.severity
                    if isinstance(vuln.severity, Severity)
                    else Severity.UNKNOWN,
                    from_time=vuln.first_seen_at or datetime.now(timezone.utc),
                )
                sla_updated += 1
                changed = True

            if changed:
                await self.db.flush()

        return {
            "status": "success",
            "scanned": len(vulns),
            "nist_updated": nist_updated,
            "sla_updated": sla_updated,
            "limit": limit,
        }
