"""VA/PT engagement report generation (client-facing summary)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.enums import (
    ACTIVE_FINDING_STATUSES,
    FindingStatus,
    ScanType,
    Severity,
    UserRole,
)
from app.models.asset import Asset
from app.models.scan import Scan
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.schemas.reports import (
    EngagementFindingRow,
    EngagementReport,
    EngagementScanInfo,
    ReportMetadata,
    ReportSection,
)
from app.services.audit_service import AuditService
from app.services.scan_policy import assert_engagement_export_allowed

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
    Severity.UNKNOWN: 5,
}

_METHODOLOGY: dict[str, str] = {
    "nmap": "Network discovery and service fingerprinting (Nmap).",
    "nuclei": "Template-driven vulnerability detection (ProjectDiscovery Nuclei).",
    "openvas": "Authenticated/unauthenticated vulnerability assessment (OpenVAS/GVM).",
    "zap": "Dynamic application security testing baseline (OWASP ZAP).",
    "nexusec": "NexuSec platform checks and normalized ingestion pipeline.",
    "other": "External scanner output imported and normalized into NexuSec.",
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _severity_counts(rows: list[EngagementFindingRow]) -> dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    for r in rows:
        counts[r.severity.value] += 1
    return counts


def _status_counts(rows: list[EngagementFindingRow]) -> dict[str, int]:
    counts = {s.value: 0 for s in FindingStatus}
    for r in rows:
        counts[r.status.value] += 1
    return counts


def _excerpt(text: Optional[str], *, limit: int = 280) -> Optional[str]:
    if not text:
        return None
    cleaned = " ".join(text.split())
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: limit - 1] + "…"


def _roe_from_config(config: dict[str, Any] | None) -> Optional[str]:
    if not isinstance(config, dict):
        return None
    for key in ("roe_notes", "notes", "window", "roe"):
        val = config.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    if config.get("roe_acknowledged") is True:
        return "RoE acknowledged for authenticated checks."
    return None


class EngagementReportService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def generate(
        self,
        auditor: User,
        *,
        scan_id: Optional[uuid.UUID] = None,
        asset_id: Optional[uuid.UUID] = None,
        engagement_type: Optional[str] = None,
        top_n: int = 25,
        allow_mock: bool = False,
    ) -> EngagementReport:
        org_id = auditor.organization_id
        if org_id is None and auditor.role != UserRole.SUPER_ADMIN:
            raise ValueError(
                "Organization scope required for engagement export "
                "(user has no organization_id)"
            )
        scans, vulns, assets = await self._load_scope(
            organization_id=org_id,
            scan_id=scan_id,
            asset_id=asset_id,
            engagement_type=engagement_type,
        )
        mock_policy = assert_engagement_export_allowed(
            scans, vulns, allow_mock=allow_mock
        )
        export_warnings: list[str] = []
        if mock_policy.get("warning"):
            export_warnings.append(str(mock_policy["warning"]))

        rows = self._to_rows(vulns)
        rows_sorted = sorted(
            rows,
            key=lambda r: (
                _SEVERITY_ORDER.get(r.severity, 99),
                r.status not in ACTIVE_FINDING_STATUSES,
                r.title.lower(),
            ),
        )
        active = [r for r in rows if r.status in ACTIVE_FINDING_STATUSES]
        eng_type = self._resolve_engagement_type(scans, engagement_type)
        scan_infos = [self._scan_info(s) for s in scans]
        engines = sorted(
            {
                (s.engine.value if hasattr(s.engine, "value") else str(s.engine))
                for s in scans
            }
        )
        types = sorted(
            {
                (s.scan_type.value if hasattr(s.scan_type, "value") else str(s.scan_type))
                for s in scans
            }
        )

        severity_summary = _severity_counts(rows)
        status_summary = _status_counts(rows)
        with_remediation = sum(1 for r in rows if r.remediation_excerpt)
        with_retest = sum(1 for r in rows if r.last_retest_scan_id)

        title = self._title(eng_type, scan_infos, asset_id, assets)
        meta = ReportMetadata(
            report_id=uuid.uuid4(),
            report_type="engagement",
            title=title,
            standard="NexuSec VA/PT Engagement",
            generated_at=_utcnow(),
            auditor_user_id=auditor.id,
            auditor_name=auditor.full_name,
            auditor_email=auditor.email,
            auditor_role=auditor.role.value,
            scope_total_assets=len(assets),
            scope_cde_assets=sum(1 for a in assets if a.is_cde_scope),
            scope_active_findings=len(active),
            scope_notes=self._scope_notes(
                scans=scans,
                assets=assets,
                scan_id=scan_id,
                asset_id=asset_id,
                engagement_type=eng_type,
            ),
            scope_asset_id=asset_id,
            scope_asset_name=assets[0].name if asset_id and assets else None,
            export_format="json_pdf_ready",
        )

        exec_summary = (
            f"{eng_type.upper()} engagement report covering {len(assets)} asset(s) and "
            f"{len(rows)} finding(s) ({len(active)} active). "
            f"Severity — critical: {severity_summary.get('critical', 0)}, "
            f"high: {severity_summary.get('high', 0)}, "
            f"medium: {severity_summary.get('medium', 0)}. "
            f"Remediation drafts present on {with_remediation} finding(s); "
            f"retest linked on {with_retest}."
        )

        scope_section = ReportSection(
            heading="Engagement scope",
            summary=(
                f"Scans in scope: {len(scans)} ({', '.join(types) or 'n/a'}). "
                f"Engines: {', '.join(engines) or 'n/a'}."
            ),
            metrics={
                "assets": len(assets),
                "cde_assets": sum(1 for a in assets if a.is_cde_scope),
                "scans": len(scans),
                "findings_total": len(rows),
                "findings_active": len(active),
                "engagement_type": eng_type,
            },
            tables=[
                {
                    "name": "assets",
                    "columns": ["name", "type", "cde", "environment"],
                    "rows": [
                        [
                            a.name,
                            a.asset_type.value
                            if hasattr(a.asset_type, "value")
                            else str(a.asset_type),
                            "yes" if a.is_cde_scope else "no",
                            a.environment or "—",
                        ]
                        for a in assets[:50]
                    ],
                }
            ],
            narrative=(
                "Only assets registered under an authorized RoE should appear in this scope. "
                "Confirm written authorization before distributing this report."
            ),
        )

        methodology_lines = [
            _METHODOLOGY.get(e, _METHODOLOGY["other"]) for e in engines
        ] or [
            "Findings were ingested via NexuSec normalization from authorized scanner outputs."
        ]
        if eng_type == "pt":
            methodology_lines.append(
                "Penetration testing validation (exploit confirmation) is performed by "
                "authorized pentesters; NexuSec records status, evidence notes, and retest results."
            )
        else:
            methodology_lines.append(
                "Vulnerability assessment focuses on discovery and detection; "
                "full exploitation is out of scope unless engagement_type=pt."
            )

        methodology = ReportSection(
            heading="Methodology",
            summary="Assessment approach derived from scanners and engagement type in scope.",
            metrics={"engines": engines, "scan_types": types},
            narrative=" ".join(methodology_lines),
        )

        retest_section = ReportSection(
            heading="Retest & verification",
            summary=(
                f"{with_retest} finding(s) have a linked retest scan. "
                f"{status_summary.get('remediated', 0)} marked remediated; "
                f"{status_summary.get('resolved', 0)} resolved; "
                f"{status_summary.get('false_positive', 0)} false positive."
            ),
            metrics={
                "with_retest_link": with_retest,
                "remediated": status_summary.get("remediated", 0),
                "resolved": status_summary.get("resolved", 0),
                "false_positive": status_summary.get("false_positive", 0),
                "accepted_risk": status_summary.get("accepted_risk", 0),
            },
            narrative=(
                "Retest evidence should be reviewed before closing Critical/High items. "
                "Auto-retest may run when status moves to remediated/resolved if enabled."
            ),
        )

        remediation_highlights: list[str] = []
        for r in rows_sorted:
            if r.remediation_excerpt and r.severity in {
                Severity.CRITICAL,
                Severity.HIGH,
            }:
                remediation_highlights.append(
                    f"[{r.severity.value}] {r.title}: {r.remediation_excerpt}"
                )
            if len(remediation_highlights) >= 8:
                break
        if not remediation_highlights and with_remediation:
            remediation_highlights.append(
                f"{with_remediation} finding(s) include remediation guidance — "
                "review in platform detail pages."
            )

        recommendations = [
            "Prioritize Critical and High active findings with owners and SLA due dates.",
            "Validate false-positive dispositions with evidence before client delivery.",
            "Attach RoE and authorization letters when sharing this report externally.",
            "Re-scan remediated assets and confirm findings close via retest links.",
        ]
        if eng_type == "pt":
            recommendations.insert(
                0,
                "Document manual validation steps and proof-of-concept notes "
                "for confirmed PT findings.",
            )

        disclaimer = (
            "This report is generated from NexuSec orchestration data. "
            "Human review is required before client delivery. "
            "Only authorized targets under a written Rules of Engagement (RoE) may be assessed."
        )
        if export_warnings:
            disclaimer += " WARNING: This export was generated with allow_mock=true and may include lab/synthetic findings — not for client delivery."

        report = EngagementReport(
            metadata=meta,
            engagement_type=eng_type,
            executive_summary=exec_summary,
            scope=scope_section,
            methodology=methodology,
            severity_summary=severity_summary,
            status_summary=status_summary,
            scans=scan_infos,
            top_findings=rows_sorted[: max(1, min(top_n, 100))],
            findings=rows_sorted,
            remediation_highlights=remediation_highlights,
            retest_summary=retest_section,
            recommendations=recommendations,
            disclaimer=disclaimer,
            export_warnings=export_warnings,
            mock_policy=mock_policy,
        )
        try:
            await AuditService(self.db).record(
                action="report.engagement.export",
                resource_type="reports",
                resource_id=str(meta.report_id),
                actor_id=auditor.id,
                organization_id=org_id,
                details={
                    "engagement_type": eng_type,
                    "scan_id": str(scan_id) if scan_id else None,
                    "asset_id": str(asset_id) if asset_id else None,
                    "findings": len(rows),
                    "allow_mock": allow_mock,
                    "mock_scan_count": mock_policy.get("mock_scan_count"),
                    "synthetic_finding_count": mock_policy.get("synthetic_finding_count"),
                },
                status_code=200,
            )
        except Exception:
            pass
        return report

    async def _load_scope(
        self,
        *,
        organization_id: Optional[uuid.UUID],
        scan_id: Optional[uuid.UUID],
        asset_id: Optional[uuid.UUID],
        engagement_type: Optional[str],
    ) -> tuple[list[Scan], list[Vulnerability], list[Asset]]:
        scan_stmt = select(Scan).options(selectinload(Scan.assets))
        if organization_id is not None:
            scan_stmt = scan_stmt.where(Scan.organization_id == organization_id)
        if scan_id is not None:
            scan_stmt = scan_stmt.where(Scan.id == scan_id)
        elif engagement_type in {"va", "pt", "discovery", "compliance", "custom"}:
            scan_stmt = scan_stmt.where(Scan.scan_type == ScanType(engagement_type))

        scans = list((await self.db.execute(scan_stmt)).scalars().all())
        if scan_id is not None and not scans:
            return [], [], []

        scan_ids = {s.id for s in scans}
        vuln_stmt = select(Vulnerability).options(selectinload(Vulnerability.asset))
        if organization_id is not None:
            vuln_stmt = vuln_stmt.where(Vulnerability.organization_id == organization_id)
        if scan_id is not None:
            vuln_stmt = vuln_stmt.where(Vulnerability.scan_id == scan_id)
        elif scan_ids and engagement_type in {
            "va",
            "pt",
            "discovery",
            "compliance",
            "custom",
        }:
            vuln_stmt = vuln_stmt.where(Vulnerability.scan_id.in_(scan_ids))
        if asset_id is not None:
            vuln_stmt = vuln_stmt.where(Vulnerability.asset_id == asset_id)

        vulns = list((await self.db.execute(vuln_stmt)).scalars().all())

        if not scans and vulns:
            related_ids = {v.scan_id for v in vulns}
            extra = (
                select(Scan)
                .options(selectinload(Scan.assets))
                .where(Scan.id.in_(related_ids))
            )
            if organization_id is not None:
                extra = extra.where(Scan.organization_id == organization_id)
            scans = list((await self.db.execute(extra)).scalars().all())

        asset_map: dict[uuid.UUID, Asset] = {}
        for s in scans:
            for a in s.assets or []:
                asset_map[a.id] = a
        for v in vulns:
            if v.asset is not None:
                asset_map[v.asset.id] = v.asset
        if asset_id is not None and asset_id not in asset_map:
            asset_q = select(Asset).where(Asset.id == asset_id)
            if organization_id is not None:
                asset_q = asset_q.where(Asset.organization_id == organization_id)
            found = (await self.db.execute(asset_q)).scalar_one_or_none()
            if found is not None:
                asset_map[found.id] = found

        return scans, vulns, list(asset_map.values())

    def _to_rows(self, vulns: list[Vulnerability]) -> list[EngagementFindingRow]:
        rows: list[EngagementFindingRow] = []
        for v in vulns:
            asset = v.asset
            rows.append(
                EngagementFindingRow(
                    vulnerability_id=v.id,
                    title=v.title,
                    severity=v.severity,
                    status=v.status,
                    asset_id=v.asset_id,
                    asset_name=asset.name if asset is not None else str(v.asset_id),
                    cve_id=v.cve_id,
                    cwe_id=v.cwe_id,
                    cvss_score=v.cvss_score,
                    source_tool=v.source_tool,
                    port=v.port,
                    remediation_excerpt=_excerpt(v.remediation),
                    remediation_owner_label=v.remediation_owner_label,
                    last_retest_scan_id=v.last_retest_scan_id,
                    first_seen_at=v.first_seen_at,
                    last_seen_at=v.last_seen_at,
                )
            )
        return rows

    @staticmethod
    def _scan_info(scan: Scan) -> EngagementScanInfo:
        return EngagementScanInfo(
            scan_id=scan.id,
            name=scan.name,
            scan_type=scan.scan_type.value
            if hasattr(scan.scan_type, "value")
            else str(scan.scan_type),
            engine=scan.engine.value
            if hasattr(scan.engine, "value")
            else str(scan.engine),
            status=scan.status.value
            if hasattr(scan.status, "value")
            else str(scan.status),
            started_at=scan.started_at,
            completed_at=scan.completed_at,
            asset_names=[a.name for a in (scan.assets or [])],
            roe_notes=_roe_from_config(
                scan.config if isinstance(scan.config, dict) else None
            ),
        )

    @staticmethod
    def _resolve_engagement_type(
        scans: list[Scan],
        requested: Optional[str],
    ) -> str:
        if requested in {"va", "pt", "discovery", "compliance", "custom"}:
            return requested
        types = {
            (s.scan_type.value if hasattr(s.scan_type, "value") else str(s.scan_type))
            for s in scans
        }
        if types == {"pt"}:
            return "pt"
        if types == {"va"}:
            return "va"
        if types == {"discovery"}:
            return "discovery"
        if len(types) > 1:
            return "mixed"
        if len(types) == 1:
            return next(iter(types))
        return "custom"

    @staticmethod
    def _title(
        eng_type: str,
        scans: list[EngagementScanInfo],
        asset_id: Optional[uuid.UUID],
        assets: list[Asset],
    ) -> str:
        label = {
            "va": "Vulnerability Assessment",
            "pt": "Penetration Testing",
            "discovery": "Discovery",
            "mixed": "VA/PT",
            "compliance": "Compliance Assessment",
            "custom": "Security Assessment",
        }.get(eng_type, "Security Assessment")
        if len(scans) == 1:
            return f"{label} Report — {scans[0].name}"
        if asset_id and assets:
            return f"{label} Report — {assets[0].name}"
        return f"{label} Engagement Report"

    @staticmethod
    def _scope_notes(
        *,
        scans: list[Scan],
        assets: list[Asset],
        scan_id: Optional[uuid.UUID],
        asset_id: Optional[uuid.UUID],
        engagement_type: str,
    ) -> str:
        parts = [f"Engagement type: {engagement_type}."]
        if scan_id:
            parts.append(f"Scoped to scan_id={scan_id}.")
        if asset_id:
            name = assets[0].name if assets else str(asset_id)
            parts.append(f"Scoped to asset '{name}' ({asset_id}).")
        roe_bits = []
        for s in scans:
            note = _roe_from_config(s.config if isinstance(s.config, dict) else None)
            if note:
                roe_bits.append(f"{s.name}: {note}")
        if roe_bits:
            parts.append("RoE/notes — " + "; ".join(roe_bits[:5]))
        return " ".join(parts)
