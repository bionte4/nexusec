"""Compliance & audit-ready report generation (ISO 27001, PCI-DSS, GDPR)."""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.enums import (
    ACTIVE_FINDING_STATUSES,
    Severity,
)
from app.models.asset import Asset
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.schemas.reports import (
    ComplianceReport,
    ControlBucket,
    ReportFindingRow,
    ReportMetadata,
    ReportSection,
)

# Human-readable titles for common Annex A / PCI references
_ISO_CONTROL_TITLES: dict[str, str] = {
    "A.8.8": "Management of technical vulnerabilities",
    "A.8.9": "Configuration management",
    "A.8.12": "Data leakage prevention",
    "A.8.20": "Networks security",
    "A.8.21": "Security of network services",
    "A.12.6.1": "Management of technical vulnerabilities (legacy)",
    "A.5.1": "Policies for information security",
}

_PCI_CONTROL_TITLES: dict[str, str] = {
    "11.3.1": "Internal vulnerability scans",
    "11.3.2": "External vulnerability scans",
    "11.2": "Network vulnerability assessments",
    "6.2.4": "Address common coding vulnerabilities",
    "6.3": "Security vulnerabilities identification",
    "1.2": "Network security controls",
    "3.4": "Protect stored account data",
}

_NIST_CSF_TITLES: dict[str, str] = {
    "ID.RA-01": "Asset vulnerabilities are identified and recorded",
    "ID.RA-02": "Cyber threat intelligence is received",
    "PR.AA-01": "Identities and credentials are managed",
    "PR.PS-01": "Configuration management practices are established",
    "PR.PS-02": "Software is maintained and updated",
    "PR.IR-01": "Networks and environments are protected",
    "PR.DS-01": "Data-at-rest is protected",
    "PR.DS-02": "Data-in-transit is protected",
    "DE.CM-01": "Networks and network services are monitored",
    "RS.MI-01": "Incidents are contained",
}

_NIST_800_53_TITLES: dict[str, str] = {
    "RA-5": "Vulnerability Monitoring and Scanning",
    "SI-2": "Flaw Remediation",
    "SI-4": "System Monitoring",
    "SI-10": "Information Input Validation",
    "CM-6": "Configuration Settings",
    "CM-7": "Least Functionality",
    "AC-2": "Account Management",
    "AC-3": "Access Enforcement",
    "IA-2": "Identification and Authentication",
    "SC-7": "Boundary Protection",
    "SC-8": "Transmission Confidentiality and Integrity",
    "SC-12": "Cryptographic Key Establishment and Management",
    "SC-13": "Cryptographic Protection",
    "MP-6": "Media Sanitization",
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _severity_summary(findings: Iterable[ReportFindingRow]) -> dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    return counts


def _extract_controls(meta: dict[str, Any], *keys: str) -> list[str]:
    controls: list[str] = []
    for key in keys:
        value = meta.get(key) or []
        if isinstance(value, str):
            controls.append(value)
        elif isinstance(value, list):
            controls.extend(str(v) for v in value if v)
    # de-dupe preserve order
    seen: set[str] = set()
    out: list[str] = []
    for c in controls:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def _is_gdpr_risk(vuln: Vulnerability, meta: dict[str, Any]) -> bool:
    if meta.get("gdpr_risk_flag") is True:
        return True
    gdpr = meta.get("gdpr") or []
    if gdpr:
        return True
    blob = f"{vuln.title} {vuln.description or ''}".lower()
    keywords = ("pii", "personal data", "gdpr", "email leak", "password", "ssn", "leakage")
    return any(k in blob for k in keywords)


class ComplianceReportService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def generate_iso27001(self, auditor: User) -> ComplianceReport:
        vulns, assets = await self._load_scope()
        rows = self._to_rows(vulns, control_keys=("iso_27001", "iso27001"))
        buckets = self._bucket_by_control(
            rows,
            titles=_ISO_CONTROL_TITLES,
            default_control="A.8.8",
            default_title=_ISO_CONTROL_TITLES["A.8.8"],
        )
        active = [r for r in rows if r.status in ACTIVE_FINDING_STATUSES]
        meta = self._metadata(
            auditor,
            report_type="iso27001",
            title="ISO 27001 Annex A — Technical Vulnerability Audit Report",
            standard="ISO/IEC 27001:2022 Annex A",
            assets=assets,
            active_count=len(active),
            scope_notes="Findings mapped to Annex A technical controls (emphasis A.8.8).",
        )
        sections = [
            ReportSection(
                heading="Executive overview",
                summary=(
                    f"Mapped {len(rows)} findings across {len(buckets)} Annex A controls. "
                    f"{len(active)} remain active in scope."
                ),
                metrics={
                    "controls_covered": len(buckets),
                    "active_findings": len(active),
                    "severity": _severity_summary(active),
                },
            ),
            ReportSection(
                heading="Annex A control coverage",
                summary="Finding distribution by ISO 27001 Annex A control reference.",
                tables=[
                    {
                        "name": "control_coverage",
                        "columns": [
                            "control_id",
                            "control_title",
                            "finding_count",
                            "critical",
                            "high",
                        ],
                        "rows": [
                            [
                                b.control_id,
                                b.control_title,
                                b.finding_count,
                                b.severity_summary.get("critical", 0),
                                b.severity_summary.get("high", 0),
                            ]
                            for b in buckets
                        ],
                    }
                ],
                narrative=(
                    "Auditors should verify evidence of vulnerability management procedures "
                    "under A.8.8 and confirm remediation SLAs for high/critical items."
                ),
            ),
        ]
        return ComplianceReport(
            metadata=meta,
            executive_summary=sections[0].summary,
            sections=sections,
            control_mapping=buckets,
            findings=rows,
            recommendations=[
                "Prioritize Critical/High findings mapped to A.8.8 within defined SLA.",
                "Document compensating controls where remediation is deferred.",
                "Retain scan evidence and remediation tickets for audit sampling.",
            ],
        )

    async def generate_pci_dss(self, auditor: User) -> ComplianceReport:
        vulns, assets = await self._load_scope()
        cde_asset_ids = {a.id for a in assets if a.is_cde_scope}
        # PCI focus: Req 11 + anything on CDE assets
        rows_all = self._to_rows(vulns, control_keys=("pci_dss", "pci"))
        rows = [
            r
            for r in rows_all
            if r.is_cde_scope
            or any(c.startswith("11.") or c.startswith("6.") for c in r.controls)
            or not r.controls  # include untagged but will default to 11.3.1 in buckets
        ]
        # Prefer CDE findings first; if empty, use all with PCI default mapping
        if not any(r.is_cde_scope for r in rows):
            rows = rows_all

        buckets = self._bucket_by_control(
            rows,
            titles=_PCI_CONTROL_TITLES,
            default_control="11.3.1",
            default_title=_PCI_CONTROL_TITLES["11.3.1"],
        )
        active = [r for r in rows if r.status in ACTIVE_FINDING_STATUSES]
        cde_active = [r for r in active if r.is_cde_scope]
        meta = self._metadata(
            auditor,
            report_type="pci_dss",
            title="PCI-DSS Req 11 — Vulnerability Assessment & CDE Scope Report",
            standard="PCI DSS v4.0 Requirement 11",
            assets=assets,
            active_count=len(active),
            scope_notes=(
                f"CDE assets in inventory: {len(cde_asset_ids)}. "
                "Focus on Req 11 vulnerability scanning and CDE exposure."
            ),
        )
        sections = [
            ReportSection(
                heading="Req 11 posture",
                summary=(
                    f"{len(active)} active findings in PCI-relevant scope; "
                    f"{len(cde_active)} on CDE-flagged assets."
                ),
                metrics={
                    "cde_assets": len(cde_asset_ids),
                    "cde_active_findings": len(cde_active),
                    "req_11_controls": len([b for b in buckets if b.control_id.startswith("11.")]),
                    "severity": _severity_summary(active),
                },
            ),
            ReportSection(
                heading="CDE asset findings",
                summary="Active findings on Cardholder Data Environment assets.",
                tables=[
                    {
                        "name": "cde_findings",
                        "columns": [
                            "vulnerability_id",
                            "asset_name",
                            "severity",
                            "status",
                            "title",
                        ],
                        "rows": [
                            [
                                str(r.vulnerability_id),
                                r.asset_name,
                                r.severity.value,
                                r.status.value,
                                r.title,
                            ]
                            for r in cde_active
                        ],
                    }
                ],
                narrative=(
                    "PCI DSS Req 11.3 requires authenticated internal vulnerability scans "
                    "and remediation of high-risk issues in the CDE."
                ),
            ),
        ]
        return ComplianceReport(
            metadata=meta,
            executive_summary=sections[0].summary,
            sections=sections,
            control_mapping=buckets,
            findings=rows,
            recommendations=[
                "Ensure quarterly internal scans cover all CDE and connected systems (11.3.1).",
                "Track remediation of Critical/High on CDE to closure before ASV cycles.",
                "Confirm scan authentication and coverage evidence for QSA sampling.",
            ],
        )

    async def generate_gdpr(self, auditor: User) -> ComplianceReport:
        vulns, assets = await self._load_scope()
        gdpr_vulns = [v for v in vulns if _is_gdpr_risk(v, v.compliance_metadata or {})]
        rows = self._to_rows(gdpr_vulns, control_keys=("gdpr", "iso_27001"))
        # Bucket by GDPR article tags when present, else Art.32
        for row in rows:
            if not row.controls:
                row.controls = ["Art.32"]
        buckets = self._bucket_by_control(
            rows,
            titles={
                "Art.32": "Security of processing",
                "Art.33": "Notification of personal data breach",
                "Art.25": "Data protection by design and by default",
                "Art.5": "Principles relating to processing",
            },
            default_control="Art.32",
            default_title="Security of processing",
        )
        active = [r for r in rows if r.status in ACTIVE_FINDING_STATUSES]
        meta = self._metadata(
            auditor,
            report_type="gdpr",
            title="GDPR Assessment — Data Leakage & PII Exposure Report",
            standard="GDPR (EU) 2016/679 — Arts. 5, 25, 32, 33",
            assets=assets,
            active_count=len(active),
            scope_notes=(
                "Includes findings flagged gdpr_risk_flag / GDPR tags / PII-related keywords."
            ),
        )
        sections = [
            ReportSection(
                heading="PII / leakage risk overview",
                summary=(
                    f"Identified {len(rows)} GDPR-relevant findings; "
                    f"{len(active)} remain active."
                ),
                metrics={
                    "gdpr_findings": len(rows),
                    "active": len(active),
                    "severity": _severity_summary(active),
                },
                narrative=(
                    "Article 32 requires appropriate technical measures. Unpatched "
                    "exposures that may leak personal data should be treated as priority risks."
                ),
            ),
            ReportSection(
                heading="Exposure inventory",
                summary="Active GDPR-relevant findings for remediation tracking.",
                tables=[
                    {
                        "name": "gdpr_active_findings",
                        "columns": [
                            "vulnerability_id",
                            "asset_name",
                            "severity",
                            "controls",
                            "title",
                        ],
                        "rows": [
                            [
                                str(r.vulnerability_id),
                                r.asset_name,
                                r.severity.value,
                                ", ".join(r.controls),
                                r.title,
                            ]
                            for r in active
                        ],
                    }
                ],
            ),
        ]
        return ComplianceReport(
            metadata=meta,
            executive_summary=sections[0].summary,
            sections=sections,
            control_mapping=buckets,
            findings=rows,
            recommendations=[
                "Contain and remediate High/Critical PII exposure paths immediately.",
                "Assess breach notification obligations under Art.33 if exploitation is plausible.",
                "Align residual risks with DPIA / Art.32 documentation.",
            ],
        )

    async def generate_nist_csf(self, auditor: User) -> ComplianceReport:
        """NIST CSF 2.0 categories + linked SP 800-53 Rev.5 controls."""
        vulns, assets = await self._load_scope()
        csf_rows = self._to_rows(vulns, control_keys=("nist_csf",))
        # Enrich control list with 800-53 for display when CSF empty but 800-53 present
        for row, vuln in zip(csf_rows, vulns):
            meta = vuln.compliance_metadata or {}
            if not row.controls:
                row.controls = _extract_controls(meta, "nist_800_53") or ["ID.RA-01"]

        buckets = self._bucket_by_control(
            csf_rows,
            titles={**_NIST_CSF_TITLES, **_NIST_800_53_TITLES},
            default_control="ID.RA-01",
            default_title=_NIST_CSF_TITLES["ID.RA-01"],
        )
        active = [r for r in csf_rows if r.status in ACTIVE_FINDING_STATUSES]
        sp_rows = self._to_rows(vulns, control_keys=("nist_800_53",))
        sp_active = [r for r in sp_rows if r.controls and r.status in ACTIVE_FINDING_STATUSES]

        meta = self._metadata(
            auditor,
            report_type="nist_csf",
            title="NIST CSF 2.0 / SP 800-53 — Vulnerability Control Mapping Report",
            standard="NIST Cybersecurity Framework 2.0 + SP 800-53 Rev.5",
            assets=assets,
            active_count=len(active),
            scope_notes=(
                "Findings mapped to NIST CSF categories (ID/PR/DE/RS) with related "
                "SP 800-53 technical controls (RA-5, SI-2, etc.)."
            ),
        )
        sections = [
            ReportSection(
                heading="Executive overview",
                summary=(
                    f"Mapped {len(csf_rows)} findings across {len(buckets)} NIST controls. "
                    f"{len(active)} remain active; {len(sp_active)} carry explicit 800-53 tags."
                ),
                metrics={
                    "total_findings": len(csf_rows),
                    "active_findings": len(active),
                    "control_buckets": len(buckets),
                    "severity_summary": _severity_summary(active),
                },
            ),
            ReportSection(
                heading="CSF / 800-53 posture",
                summary="Control coverage derived from scanner normalization heuristics.",
                metrics={
                    "csf_controls": sorted({c for r in csf_rows for c in r.controls}),
                    "sp80053_controls": sorted(
                        {c for r in sp_rows for c in r.controls}
                    ),
                },
                narrative=(
                    "Use this report to align VA findings with Govern/Identify/Protect/"
                    "Detect/Respond outcomes. AI-suggested mappings remain pending until "
                    "an analyst accepts them."
                ),
            ),
        ]
        return ComplianceReport(
            metadata=meta,
            executive_summary=sections[0].summary,
            sections=sections,
            control_mapping=buckets,
            findings=csf_rows,
            recommendations=[
                "Prioritize Critical/High findings under ID.RA-01 / RA-5 for continuous monitoring.",
                "Track flaw remediation (SI-2 / PR.PS-02) to closure with re-scan evidence.",
                "Review AI-suggested NIST mappings before accepting into compliance_metadata.",
            ],
        )

    async def _load_scope(
        self,
    ) -> tuple[list[Vulnerability], list[Asset]]:
        vuln_stmt = select(Vulnerability).options(selectinload(Vulnerability.asset))
        vulns = list((await self.db.execute(vuln_stmt)).scalars().all())
        assets = list((await self.db.execute(select(Asset))).scalars().all())
        return vulns, assets

    def _to_rows(
        self,
        vulns: list[Vulnerability],
        *,
        control_keys: tuple[str, ...],
    ) -> list[ReportFindingRow]:
        rows: list[ReportFindingRow] = []
        for v in vulns:
            asset = v.asset
            meta = v.compliance_metadata or {}
            rows.append(
                ReportFindingRow(
                    vulnerability_id=v.id,
                    title=v.title,
                    severity=v.severity,
                    status=v.status,
                    asset_id=v.asset_id,
                    asset_name=asset.name if asset is not None else str(v.asset_id),
                    is_cde_scope=bool(asset.is_cde_scope) if asset is not None else False,
                    cve_id=v.cve_id,
                    cwe_id=v.cwe_id,
                    cvss_score=v.cvss_score,
                    controls=_extract_controls(meta, *control_keys),
                    remediation=v.remediation,
                    first_seen_at=v.first_seen_at,
                    last_seen_at=v.last_seen_at,
                )
            )
        return rows

    def _bucket_by_control(
        self,
        rows: list[ReportFindingRow],
        *,
        titles: dict[str, str],
        default_control: str,
        default_title: str,
    ) -> list[ControlBucket]:
        grouped: dict[str, list[ReportFindingRow]] = defaultdict(list)
        for row in rows:
            controls = row.controls or [default_control]
            for control in controls:
                grouped[control].append(row)

        buckets: list[ControlBucket] = []
        for control_id, findings in sorted(grouped.items(), key=lambda kv: (-len(kv[1]), kv[0])):
            # de-dupe findings inside a bucket by vulnerability id
            unique: dict[uuid.UUID, ReportFindingRow] = {f.vulnerability_id: f for f in findings}
            uniq_list = list(unique.values())
            buckets.append(
                ControlBucket(
                    control_id=control_id,
                    control_title=titles.get(
                        control_id, default_title if control_id == default_control else control_id
                    ),
                    finding_count=len(uniq_list),
                    severity_summary=_severity_summary(uniq_list),
                    findings=uniq_list,
                )
            )
        return buckets

    def _metadata(
        self,
        auditor: User,
        *,
        report_type: str,
        title: str,
        standard: str,
        assets: list[Asset],
        active_count: int,
        scope_notes: Optional[str] = None,
    ) -> ReportMetadata:
        return ReportMetadata(
            report_id=uuid.uuid4(),
            report_type=report_type,
            title=title,
            standard=standard,
            generated_at=_utcnow(),
            auditor_user_id=auditor.id,
            auditor_name=auditor.full_name,
            auditor_email=auditor.email,
            auditor_role=auditor.role.value,
            scope_total_assets=len(assets),
            scope_cde_assets=sum(1 for a in assets if a.is_cde_scope),
            scope_active_findings=active_count,
            scope_notes=scope_notes,
            export_format="json_pdf_ready",
        )
