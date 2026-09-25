"""Threat intelligence sync + vulnerability enrichment (RBVM)."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.enums import ACTIVE_FINDING_STATUSES, Severity
from app.models.threat_intel import ThreatIntelCve, ThreatIntelSyncRun
from app.models.vulnerability import Vulnerability
from app.services.threat_intel.kev_client import KevEntry, fetch_kev_catalog
from app.services.threat_intel.nvd_client import NvdEnrichment, fetch_nvd_cve
from app.services.threat_intel.epss_client import EpssScore, fetch_epss_scores

logger = logging.getLogger(__name__)

# RBVM score boosts (additive on top of CVSS / severity baseline)
KEV_SCORE_BOOST = 25.0
PUBLIC_EXPLOIT_BOOST = 15.0
RANSOMWARE_BOOST = 10.0
# EPSS contributes up to this many points (epss 0.0–1.0 → 0–EPSS_SCORE_WEIGHT)
EPSS_SCORE_WEIGHT = 20.0

SEVERITY_BASE = {
    Severity.CRITICAL: 90.0,
    Severity.HIGH: 70.0,
    Severity.MEDIUM: 45.0,
    Severity.LOW: 20.0,
    Severity.INFO: 5.0,
    Severity.UNKNOWN: 30.0,
}


def normalize_cve_id(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    cve = value.strip().upper()
    if cve.startswith("CVE-"):
        return cve
    return None


def compute_threat_risk_score(
    *,
    severity: Severity,
    cvss_score: Optional[float],
    in_kev: bool,
    has_public_exploit: bool,
    known_ransomware_use: Optional[str] = None,
    epss_score: Optional[float] = None,
) -> float:
    """Risk-Based Vulnerability Management priority score (0–100 capped).

    Combines severity/CVSS baseline with KEV, public-exploit, ransomware, and EPSS.
    """
    base = SEVERITY_BASE.get(severity, 30.0)
    if cvss_score is not None:
        base = max(base, float(cvss_score) * 10.0)
    score = base
    if in_kev:
        score += KEV_SCORE_BOOST
    if has_public_exploit:
        score += PUBLIC_EXPLOIT_BOOST
    if (known_ransomware_use or "").lower() == "known":
        score += RANSOMWARE_BOOST
    if epss_score is not None:
        score += max(0.0, min(1.0, float(epss_score))) * EPSS_SCORE_WEIGHT
    return min(100.0, round(score, 2))


class ThreatIntelService:
    def __init__(self, session: Session, settings: Optional[Settings] = None) -> None:
        self.session = session
        self.settings = settings or get_settings()

    def start_sync_run(self, source: str) -> ThreatIntelSyncRun:
        run = ThreatIntelSyncRun(source=source, status="running")
        self.session.add(run)
        self.session.flush()
        return run

    def finish_sync_run(
        self,
        run: ThreatIntelSyncRun,
        *,
        status: str,
        records_upserted: int = 0,
        vulnerabilities_enriched: int = 0,
        error_message: Optional[str] = None,
    ) -> ThreatIntelSyncRun:
        run.status = status
        run.records_upserted = records_upserted
        run.vulnerabilities_enriched = vulnerabilities_enriched
        run.error_message = error_message
        run.finished_at = datetime.now(timezone.utc)
        self.session.flush()
        return run

    def upsert_kev_entries(self, entries: list[KevEntry]) -> int:
        count = 0
        for entry in entries:
            row = self.session.get(ThreatIntelCve, entry.cve_id)
            sources = ["cisa_kev"]
            if row is None:
                row = ThreatIntelCve(cve_id=entry.cve_id, sources=sources)
                self.session.add(row)
            else:
                existing = list(row.sources or [])
                if "cisa_kev" not in existing:
                    existing.append("cisa_kev")
                row.sources = existing
            row.in_kev = True
            row.vendor_project = entry.vendor_project or row.vendor_project
            row.product = entry.product or row.product
            row.vulnerability_name = entry.vulnerability_name or row.vulnerability_name
            row.date_added = entry.date_added
            row.due_date = entry.due_date
            row.known_ransomware_use = entry.known_ransomware_use
            row.required_action = entry.required_action
            meta = dict(row.raw_metadata or {})
            meta["kev"] = {
                "notes": entry.notes,
                "vendorProject": entry.vendor_project,
                "product": entry.product,
            }
            row.raw_metadata = meta
            count += 1
        self.session.flush()
        return count

    def upsert_nvd_enrichment(self, enrichment: NvdEnrichment) -> ThreatIntelCve:
        row = self.session.get(ThreatIntelCve, enrichment.cve_id)
        if row is None:
            row = ThreatIntelCve(cve_id=enrichment.cve_id, sources=["nvd"])
            self.session.add(row)
        else:
            sources = list(row.sources or [])
            if "nvd" not in sources:
                sources.append("nvd")
            row.sources = sources
        row.has_public_exploit = row.has_public_exploit or enrichment.has_public_exploit
        if enrichment.cvss_score is not None:
            row.nvd_cvss_score = enrichment.cvss_score
        if enrichment.exploitability_score is not None:
            row.nvd_exploitability_score = enrichment.exploitability_score
        meta = dict(row.raw_metadata or {})
        meta["nvd"] = {
            "exploit_references": enrichment.exploit_references,
            "has_public_exploit": enrichment.has_public_exploit,
        }
        row.raw_metadata = meta
        self.session.flush()
        return row

    def upsert_epss(self, score: EpssScore) -> ThreatIntelCve:
        row = self.session.get(ThreatIntelCve, score.cve_id)
        if row is None:
            row = ThreatIntelCve(cve_id=score.cve_id, sources=["epss"])
            self.session.add(row)
        else:
            sources = list(row.sources or [])
            if "epss" not in sources:
                sources.append("epss")
            row.sources = sources
        row.epss_score = score.epss
        row.epss_percentile = score.percentile
        row.epss_fetched_at = datetime.now(timezone.utc)
        meta = dict(row.raw_metadata or {})
        meta["epss"] = {
            "epss": score.epss,
            "percentile": score.percentile,
            "date": score.score_date.isoformat() if score.score_date else None,
        }
        row.raw_metadata = meta
        self.session.flush()
        return row

    def sync_kev_catalog(self) -> dict[str, Any]:
        run = self.start_sync_run("kev")
        try:
            entries, meta = fetch_kev_catalog(url=self.settings.kev_catalog_url)
            upserted = self.upsert_kev_entries(entries)
            self.finish_sync_run(run, status="success", records_upserted=upserted)
            return {"status": "success", "upserted": upserted, "meta": meta, "run_id": str(run.id)}
        except Exception as exc:
            logger.exception("KEV sync failed")
            self.finish_sync_run(run, status="failed", error_message=str(exc))
            raise

    def enrich_vulnerabilities(
        self,
        *,
        limit: int = 500,
        fetch_nvd: bool = True,
        fetch_epss: bool = True,
        only_unenriched: bool = False,
    ) -> dict[str, Any]:
        """Match findings with CVE IDs against KEV/NVD/EPSS and set RBVM scores."""
        run = self.start_sync_run("enrich")
        try:
            stmt = select(Vulnerability).where(Vulnerability.cve_id.is_not(None))
            if only_unenriched:
                stmt = stmt.where(Vulnerability.threat_enriched_at.is_(None))
            stmt = stmt.limit(limit)
            vulns = list(self.session.scalars(stmt).all())

            # Prefetch EPSS for the batch
            epss_map: dict[str, EpssScore] = {}
            if fetch_epss and self.settings.epss_enabled:
                cve_ids = [
                    cve
                    for v in vulns
                    if (cve := normalize_cve_id(v.cve_id)) is not None
                ]
                if cve_ids:
                    epss_map = fetch_epss_scores(
                        cve_ids,
                        url=self.settings.epss_api_url,
                        timeout=self.settings.epss_timeout_seconds,
                    )
                    for score in epss_map.values():
                        self.upsert_epss(score)

            enriched = 0
            nvd_lookups = 0
            for vuln in vulns:
                cve_id = normalize_cve_id(vuln.cve_id)
                if not cve_id:
                    continue
                intel = self.session.get(ThreatIntelCve, cve_id)

                if fetch_nvd and (intel is None or "nvd" not in (intel.sources or [])):
                    nvd = fetch_nvd_cve(
                        cve_id,
                        api_key=self.settings.nvd_api_key or None,
                        rate_limit_sleep=self.settings.nvd_rate_limit_sleep,
                    )
                    nvd_lookups += 1
                    if nvd is not None:
                        intel = self.upsert_nvd_enrichment(nvd)

                epss_row = epss_map.get(cve_id)
                epss_val = (
                    epss_row.epss
                    if epss_row is not None
                    else (intel.epss_score if intel is not None else None)
                )
                epss_pct = (
                    epss_row.percentile
                    if epss_row is not None
                    else (intel.epss_percentile if intel is not None else None)
                )

                if intel is None and epss_row is None:
                    # No KEV/NVD/EPSS hit — still mark as enriched with baseline score
                    vuln.is_actively_exploited = False
                    vuln.has_public_exploit = False
                    vuln.epss_score = None
                    vuln.epss_percentile = None
                    vuln.threat_risk_score = compute_threat_risk_score(
                        severity=vuln.severity,
                        cvss_score=vuln.cvss_score,
                        in_kev=False,
                        has_public_exploit=False,
                    )
                    vuln.threat_intel_metadata = {"cve_id": cve_id, "matched": False}
                    vuln.threat_enriched_at = datetime.now(timezone.utc)
                    enriched += 1
                    continue

                in_kev = bool(intel.in_kev) if intel is not None else False
                has_exploit = bool(intel.has_public_exploit) if intel is not None else False
                ransomware = intel.known_ransomware_use if intel is not None else None
                vuln.is_actively_exploited = in_kev
                vuln.has_public_exploit = has_exploit
                if intel is not None:
                    vuln.kev_date_added = intel.date_added
                    vuln.kev_due_date = intel.due_date
                vuln.epss_score = epss_val
                vuln.epss_percentile = epss_pct
                vuln.threat_risk_score = compute_threat_risk_score(
                    severity=vuln.severity,
                    cvss_score=vuln.cvss_score
                    or (intel.nvd_cvss_score if intel is not None else None),
                    in_kev=in_kev,
                    has_public_exploit=has_exploit,
                    known_ransomware_use=ransomware,
                    epss_score=epss_val,
                )
                vuln.threat_intel_metadata = {
                    "cve_id": cve_id,
                    "matched": True,
                    "in_kev": in_kev,
                    "has_public_exploit": has_exploit,
                    "vendor_project": intel.vendor_project if intel else None,
                    "product": intel.product if intel else None,
                    "known_ransomware_use": ransomware,
                    "required_action": intel.required_action if intel else None,
                    "nvd_cvss_score": intel.nvd_cvss_score if intel else None,
                    "epss_score": epss_val,
                    "epss_percentile": epss_pct,
                    "sources": list(intel.sources or []) if intel else (["epss"] if epss_row else []),
                }
                vuln.threat_enriched_at = datetime.now(timezone.utc)

                # Mild severity promotion for KEV when still below high
                if in_kev and vuln.severity in (Severity.LOW, Severity.INFO, Severity.UNKNOWN):
                    vuln.severity = Severity.HIGH

                enriched += 1

            self.finish_sync_run(
                run,
                status="success",
                records_upserted=nvd_lookups + len(epss_map),
                vulnerabilities_enriched=enriched,
            )
            return {
                "status": "success",
                "vulnerabilities_enriched": enriched,
                "nvd_lookups": nvd_lookups,
                "epss_lookups": len(epss_map),
                "run_id": str(run.id),
            }
        except Exception as exc:
            logger.exception("Threat enrichment failed")
            self.finish_sync_run(run, status="failed", error_message=str(exc))
            raise

    def status_summary(self) -> dict[str, Any]:
        from sqlalchemy import func

        kev_total = (
            self.session.scalar(
                select(func.count())
                .select_from(ThreatIntelCve)
                .where(ThreatIntelCve.in_kev.is_(True))
            )
            or 0
        )
        exploit_total = (
            self.session.scalar(
                select(func.count())
                .select_from(ThreatIntelCve)
                .where(ThreatIntelCve.has_public_exploit.is_(True))
            )
            or 0
        )
        active_vulns = (
            self.session.scalar(
                select(func.count())
                .select_from(Vulnerability)
                .where(
                    Vulnerability.is_actively_exploited.is_(True),
                    Vulnerability.status.in_(list(ACTIVE_FINDING_STATUSES)),
                )
            )
            or 0
        )
        last_runs = list(
            self.session.scalars(
                select(ThreatIntelSyncRun).order_by(ThreatIntelSyncRun.started_at.desc()).limit(10)
            ).all()
        )
        return {
            "kev_catalog_entries": int(kev_total),
            "cves_with_public_exploit": int(exploit_total),
            "actively_exploited_open_findings": int(active_vulns),
            "last_sync_runs": [
                {
                    "id": str(r.id),
                    "source": r.source,
                    "status": r.status,
                    "records_upserted": r.records_upserted,
                    "vulnerabilities_enriched": r.vulnerabilities_enriched,
                    "started_at": r.started_at.isoformat() if r.started_at else None,
                    "finished_at": r.finished_at.isoformat() if r.finished_at else None,
                    "error_message": r.error_message,
                }
                for r in last_runs
            ],
        }
