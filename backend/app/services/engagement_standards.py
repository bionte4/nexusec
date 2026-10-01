"""International VA/PT engagement standards — PTES, ASVS, OWASP Top 10.

These checklists are orchestration/process evidence (human-led PT), not
auto-exploit controls. Used by engagement reports and offline DAST suites.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Optional, Sequence

from app.core.enums import FindingStatus
from app.models.scan import Scan
from app.schemas.reports import EngagementFindingRow, ReportSection

# PTES technical process phases (human-led; tooling supports Pre-engagement → Reporting).
PTES_PHASES: tuple[dict[str, str], ...] = (
    {
        "id": "ptes.pre_engagement",
        "title": "Pre-engagement Interactions",
        "owner": "human",
        "hint": "RoE, scope, legal, emergency contacts, lab_mode vs production.",
    },
    {
        "id": "ptes.intelligence_gathering",
        "title": "Intelligence Gathering",
        "owner": "tool+human",
        "hint": "OSINT + asset inventory; Nmap discovery / imported recon.",
    },
    {
        "id": "ptes.threat_modeling",
        "title": "Threat Modeling",
        "owner": "human",
        "hint": "Business-critical paths, CDE, trust boundaries (analyst).",
    },
    {
        "id": "ptes.vulnerability_analysis",
        "title": "Vulnerability Analysis",
        "owner": "tool",
        "hint": "Nuclei / OpenVAS import / ZAP import or lab DAST suite.",
    },
    {
        "id": "ptes.exploitation",
        "title": "Exploitation",
        "owner": "human",
        "hint": "Manual PT only — platform never auto-exploits.",
    },
    {
        "id": "ptes.post_exploitation",
        "title": "Post Exploitation",
        "owner": "human",
        "hint": "Impact validation, lateral movement notes (human evidence).",
    },
    {
        "id": "ptes.reporting",
        "title": "Reporting",
        "owner": "tool+human",
        "hint": "Draft → dual-control SoD → Client PDF + compliance exports.",
    },
)

# OWASP ASVS 4.x chapter-level L1 tracking (process coverage, not full L2/L3).
ASVS_CHAPTERS: tuple[dict[str, str], ...] = (
    {"id": "V1", "title": "Architecture, Design and Threat Modeling", "owner": "human"},
    {"id": "V2", "title": "Authentication", "owner": "tool+human"},
    {"id": "V3", "title": "Session Management", "owner": "tool+human"},
    {"id": "V4", "title": "Access Control", "owner": "human"},
    {"id": "V5", "title": "Validation, Sanitization and Encoding", "owner": "tool"},
    {"id": "V7", "title": "Error Handling and Logging", "owner": "tool"},
    {"id": "V8", "title": "Data Protection", "owner": "human"},
    {"id": "V9", "title": "Communication", "owner": "tool"},
    {"id": "V10", "title": "Malicious Code", "owner": "human"},
    {"id": "V11", "title": "Business Logic", "owner": "human"},
    {"id": "V12", "title": "Files and Resources", "owner": "tool+human"},
    {"id": "V13", "title": "API and Web Service", "owner": "tool+human"},
    {"id": "V14", "title": "Configuration", "owner": "tool"},
)

OWASP_TOP10_2021: tuple[dict[str, str], ...] = (
    {"id": "A01:2021", "title": "Broken Access Control"},
    {"id": "A02:2021", "title": "Cryptographic Failures"},
    {"id": "A03:2021", "title": "Injection"},
    {"id": "A04:2021", "title": "Insecure Design"},
    {"id": "A05:2021", "title": "Security Misconfiguration"},
    {"id": "A06:2021", "title": "Vulnerable and Outdated Components"},
    {"id": "A07:2021", "title": "Identification and Authentication Failures"},
    {"id": "A08:2021", "title": "Software and Data Integrity Failures"},
    {"id": "A09:2021", "title": "Security Logging and Monitoring Failures"},
    {"id": "A10:2021", "title": "Server-Side Request Forgery (SSRF)"},
)

# Alert title / CWE → OWASP Top 10:2021 (for ZAP / DAST normalization).
_OWASP_BY_ALERT: dict[str, str] = {
    "sql injection": "A03:2021",
    "cross site scripting": "A03:2021",
    "xss": "A03:2021",
    "path traversal": "A01:2021",
    "directory browsing": "A01:2021",
    "csrf": "A01:2021",
    "missing anti-clickjacking": "A05:2021",
    "content security policy": "A05:2021",
    "x-content-type-options": "A05:2021",
    "strict-transport-security": "A02:2021",
    "application error disclosure": "A05:2021",
    "server leaks information": "A05:2021",
    "vulnerable js library": "A06:2021",
    "session id in url rewrite": "A07:2021",
    "cookie no httponly": "A07:2021",
    "cookie without secure flag": "A02:2021",
    "insecure http method": "A05:2021",
    "ssrf": "A10:2021",
    "server side request forgery": "A10:2021",
    "integrity": "A08:2021",
    "subresource integrity": "A08:2021",
    "timestamp disclosure": "A09:2021",
    "insecure design": "A04:2021",
}

_OWASP_BY_CWE: dict[str, str] = {
    "22": "A01:2021",
    "79": "A03:2021",
    "89": "A03:2021",
    "200": "A05:2021",
    "209": "A05:2021",
    "287": "A07:2021",
    "319": "A02:2021",
    "352": "A01:2021",
    "502": "A08:2021",
    "611": "A05:2021",
    "693": "A05:2021",
    "918": "A10:2021",
    "1021": "A05:2021",
}


def map_owasp_category(
    *,
    title: str = "",
    cwe_id: Optional[str] = None,
    explicit: Optional[str] = None,
) -> str:
    """Return OWASP Top 10:2021 id (e.g. A05:2021)."""
    if explicit and str(explicit).strip().upper().startswith("A"):
        raw = str(explicit).strip().upper()
        if ":2021" not in raw and raw.startswith("A") and ":" not in raw:
            return f"{raw}:2021"
        return raw if ":2021" in raw else f"{raw}:2021"
    if cwe_id:
        digits = "".join(ch for ch in str(cwe_id) if ch.isdigit())
        if digits in _OWASP_BY_CWE:
            return _OWASP_BY_CWE[digits]
    low = (title or "").lower()
    for needle, cat in _OWASP_BY_ALERT.items():
        if needle in low:
            return cat
    return "A05:2021"


def hash_template_dirs(dirs: Sequence[str]) -> Optional[str]:
    """Stable short hash of template pack paths + mtimes (best-effort, no raise)."""
    parts: list[str] = []
    for raw in dirs:
        path = Path(raw)
        try:
            if path.is_dir():
                # Sample shallow listing — avoid walking huge trees in hot path.
                names = sorted(p.name for p in path.iterdir())[:50]
                mtime = int(path.stat().st_mtime)
                parts.append(f"{path}:{mtime}:{','.join(names)}")
            elif path.is_file():
                parts.append(f"{path}:{int(path.stat().st_mtime)}:{path.stat().st_size}")
            else:
                parts.append(f"{path}:missing")
        except OSError:
            parts.append(f"{path}:error")
    if not parts:
        return None
    digest = hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()
    return digest[:16]


def extract_scan_evidence(config: dict[str, Any] | None) -> dict[str, Any]:
    """Pull P1 evidence fields from scan.config / last_result."""
    cfg = config if isinstance(config, dict) else {}
    last = cfg.get("last_result") if isinstance(cfg.get("last_result"), dict) else {}
    roe_id = cfg.get("roe_id") or cfg.get("roe_document_id")
    return {
        "roe_id": str(roe_id).strip() if isinstance(roe_id, str) and roe_id.strip() else None,
        "roe_acknowledged": cfg.get("roe_acknowledged") is True,
        "lab_mode": cfg.get("lab_mode") is True,
        "imported": cfg.get("imported") is True,
        "tool_version": last.get("tool_version"),
        "template_hash": last.get("template_hash") or cfg.get("template_hash"),
        "finished_at": last.get("finished_at"),
        "command": last.get("command"),
    }


def _override_done(overrides: dict[str, Any], phase_id: str) -> Optional[bool]:
    raw = overrides.get(phase_id)
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, dict) and "done" in raw:
        return bool(raw["done"])
    return None


def build_ptes_checklist(
    *,
    scans: list[Scan],
    rows: list[EngagementFindingRow],
    eng_type: str,
    dual_control_approved: bool,
    delivery: str,
    overrides: Optional[dict[str, Any]] = None,
) -> ReportSection:
    """Auto-compute PTES phase status; human phases need overrides or CONFIRMED findings."""
    overrides = overrides if isinstance(overrides, dict) else {}
    types = {
        (s.scan_type.value if hasattr(s.scan_type, "value") else str(s.scan_type))
        for s in scans
    }
    engines = {
        (s.engine.value if hasattr(s.engine, "value") else str(s.engine))
        for s in scans
    }
    has_roe = any(
        isinstance(s.config, dict)
        and (s.config.get("roe_acknowledged") is True or s.config.get("roe_id"))
        for s in scans
    )
    discovery = "discovery" in types or "nmap" in engines
    va = "va" in types or bool(engines & {"nuclei", "openvas", "zap", "nexusec"})
    confirmed = sum(1 for r in rows if r.status == FindingStatus.CONFIRMED)
    reporting = dual_control_approved or delivery == "draft"

    auto = {
        "ptes.pre_engagement": has_roe,
        "ptes.intelligence_gathering": discovery,
        "ptes.threat_modeling": False,  # human
        "ptes.vulnerability_analysis": va,
        "ptes.exploitation": confirmed > 0 and eng_type == "pt",
        "ptes.post_exploitation": False,  # human
        "ptes.reporting": reporting,
    }

    table_rows: list[list[str]] = []
    done_count = 0
    metrics: dict[str, Any] = {"phases": {}}
    for phase in PTES_PHASES:
        pid = phase["id"]
        override = _override_done(overrides, pid)
        done = auto[pid] if override is None else override
        if done:
            done_count += 1
        metrics["phases"][pid] = {
            "done": done,
            "owner": phase["owner"],
            "title": phase["title"],
            "override": override is not None,
        }
        table_rows.append(
            [
                phase["title"],
                phase["owner"],
                "done" if done else "pending",
                phase["hint"],
            ]
        )

    human_pending = [
        p["title"]
        for p in PTES_PHASES
        if p["owner"] == "human" and not metrics["phases"][p["id"]]["done"]
    ]
    return ReportSection(
        heading="PTES process checklist",
        summary=(
            f"PTES coverage {done_count}/{len(PTES_PHASES)}. "
            "Exploitation/post-exploitation remain human-led (no auto-exploit)."
        ),
        metrics={
            **metrics,
            "done_count": done_count,
            "total": len(PTES_PHASES),
            "human_pending": human_pending,
            "standard": "PTES",
        },
        tables=[
            {
                "name": "ptes_phases",
                "columns": ["phase", "owner", "status", "hint"],
                "rows": table_rows,
            }
        ],
        narrative=(
            "PTES maps the engagement lifecycle. Tooling covers intelligence gathering "
            "and vulnerability analysis; exploitation confirmation is a human pentester "
            "action recorded via finding status=confirmed and evidence notes."
        ),
    )


def build_asvs_checklist(
    *,
    rows: list[EngagementFindingRow],
    scans: list[Scan],
    overrides: Optional[dict[str, Any]] = None,
) -> ReportSection:
    """ASVS chapter tracking — tool findings + human overrides for L1 process evidence."""
    overrides = overrides if isinstance(overrides, dict) else {}
    owasp_seen = {
        str(getattr(r, "source_tool", "") or "")
        for r in rows
    }  # placeholder; use evidence from titles below
    # Infer chapter coverage from OWASP categories / engines present.
    engines = {
        (s.engine.value if hasattr(s.engine, "value") else str(s.engine))
        for s in scans
    }
    has_dast = "zap" in engines
    has_va = bool(engines & {"nuclei", "openvas", "nexusec", "zap"})
    has_auth = any(
        isinstance(s.config, dict) and s.config.get("authenticated") is True
        for s in scans
    )
    owasp_cats = set()
    for r in rows:
        # EngagementFindingRow has no owasp field — infer from title heuristics
        owasp_cats.add(map_owasp_category(title=r.title or "", cwe_id=r.cwe_id))

    auto_map = {
        "V1": False,
        "V2": has_auth or "A07:2021" in owasp_cats,
        "V3": "A07:2021" in owasp_cats,
        "V4": "A01:2021" in owasp_cats,
        "V5": "A03:2021" in owasp_cats or has_dast,
        "V7": "A09:2021" in owasp_cats or "A05:2021" in owasp_cats,
        "V8": "A02:2021" in owasp_cats,
        "V9": "A02:2021" in owasp_cats or has_va,
        "V10": False,
        "V11": False,
        "V12": "A01:2021" in owasp_cats,
        "V13": has_dast or has_va,
        "V14": "A05:2021" in owasp_cats or "A06:2021" in owasp_cats,
    }

    table_rows: list[list[str]] = []
    done_count = 0
    metrics: dict[str, Any] = {"chapters": {}, "owasp_categories_seen": sorted(owasp_cats)}
    for ch in ASVS_CHAPTERS:
        cid = ch["id"]
        override = _override_done(overrides, cid)
        done = auto_map.get(cid, False) if override is None else override
        if done:
            done_count += 1
        metrics["chapters"][cid] = {
            "done": done,
            "owner": ch["owner"],
            "title": ch["title"],
            "override": override is not None,
        }
        table_rows.append(
            [cid, ch["title"], ch["owner"], "covered" if done else "gap"]
        )

    _ = owasp_seen  # silence unused in some paths
    return ReportSection(
        heading="OWASP ASVS L1 chapter coverage",
        summary=(
            f"ASVS chapter signals {done_count}/{len(ASVS_CHAPTERS)}. "
            "Gaps in human-owned chapters (V1/V4/V8/V10/V11) require analyst review."
        ),
        metrics={
            **metrics,
            "done_count": done_count,
            "total": len(ASVS_CHAPTERS),
            "standard": "OWASP ASVS 4.x (L1 process tracking)",
        },
        tables=[
            {
                "name": "asvs_chapters",
                "columns": ["id", "chapter", "owner", "status"],
                "rows": table_rows,
            }
        ],
        narrative=(
            "ASVS chapters are tracked as engagement process evidence. Automated DAST/VA "
            "signals map to selected chapters; architecture, access-control design, and "
            "business logic remain human PT responsibilities."
        ),
    )


def merge_checklist_overrides_from_scans(scans: list[Scan]) -> tuple[dict, dict]:
    """Collect optional config.ptes_checklist / asvs_checklist overrides from scans."""
    ptes: dict[str, Any] = {}
    asvs: dict[str, Any] = {}
    for s in scans:
        cfg = s.config if isinstance(s.config, dict) else {}
        if isinstance(cfg.get("ptes_checklist"), dict):
            ptes.update(cfg["ptes_checklist"])
        if isinstance(cfg.get("asvs_checklist"), dict):
            asvs.update(cfg["asvs_checklist"])
    return ptes, asvs


def owasp_top10_dast_alerts() -> list[dict[str, Any]]:
    """Deterministic offline DAST alert set covering OWASP Top 10:2021 (no zaproxy)."""
    return [
        {
            "pluginid": "90001",
            "alert": "Broken Access Control — IDOR probe indicator",
            "riskcode": "3",
            "cweid": "639",
            "owasp": "A01:2021",
            "desc": "Unauthenticated access pattern suggests missing object-level authz (lab suite).",
            "solution": "Enforce authorization checks on every object reference.",
        },
        {
            "pluginid": "90002",
            "alert": "Cookie Without Secure Flag",
            "riskcode": "2",
            "cweid": "614",
            "owasp": "A02:2021",
            "desc": "Session cookie may be sent over cleartext channels.",
            "solution": "Set Secure and HttpOnly on session cookies; prefer TLS-only.",
        },
        {
            "pluginid": "90003",
            "alert": "SQL Injection",
            "riskcode": "3",
            "cweid": "89",
            "owasp": "A03:2021",
            "desc": "Parameterized query failure pattern in lab DAST suite.",
            "solution": "Use parameterized queries / ORM bindings; never concatenate SQL.",
        },
        {
            "pluginid": "90004",
            "alert": "Insecure Design — missing rate limit on sensitive action",
            "riskcode": "2",
            "cweid": "799",
            "owasp": "A04:2021",
            "desc": "Sensitive endpoint accepts unbounded unauthenticated attempts (lab).",
            "solution": "Threat-model sensitive flows; add rate limits and step-up auth.",
        },
        {
            "pluginid": "90005",
            "alert": "Content Security Policy (CSP) Header Not Set",
            "riskcode": "2",
            "cweid": "693",
            "owasp": "A05:2021",
            "desc": "Missing CSP increases XSS impact.",
            "solution": "Deploy a restrictive Content-Security-Policy.",
        },
        {
            "pluginid": "90006",
            "alert": "Vulnerable JS Library",
            "riskcode": "2",
            "cweid": "1104",
            "owasp": "A06:2021",
            "desc": "Client library version flagged as outdated in lab suite.",
            "solution": "Upgrade dependency; track SCA in CI.",
        },
        {
            "pluginid": "90007",
            "alert": "Session ID in URL Rewrite",
            "riskcode": "2",
            "cweid": "598",
            "owasp": "A07:2021",
            "desc": "Session identifier exposed in URL (lab).",
            "solution": "Keep session IDs in secure cookies only.",
        },
        {
            "pluginid": "90008",
            "alert": "Subresource Integrity Attribute Missing",
            "riskcode": "1",
            "cweid": "353",
            "owasp": "A08:2021",
            "desc": "Third-party script without SRI.",
            "solution": "Add integrity= hashes for CDN scripts.",
        },
        {
            "pluginid": "90009",
            "alert": "Timestamp Disclosure — Unix",
            "riskcode": "1",
            "cweid": "200",
            "owasp": "A09:2021",
            "desc": "Verbose timestamps may aid attackers correlating events.",
            "solution": "Reduce verbose server banners; centralize security logging.",
        },
        {
            "pluginid": "90010",
            "alert": "Server Side Request Forgery",
            "riskcode": "3",
            "cweid": "918",
            "owasp": "A10:2021",
            "desc": "URL fetch parameter accepts internal addresses (lab indicator).",
            "solution": "Allowlist outbound destinations; block link-local/metadata IPs.",
        },
    ]


def build_offline_owasp_dast_report(targets: list[str], *, policy: str = "owasp_top10") -> str:
    """JSON report compatible with ZapJsonParser — no external ZAP daemon."""
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat()
    alerts_src = owasp_top10_dast_alerts()
    sites: list[dict[str, Any]] = []
    for raw in targets:
        host = raw
        if "://" in raw:
            from urllib.parse import urlparse

            host = urlparse(raw).hostname or raw
        uri = raw if "://" in raw else f"https://{raw}/"
        alerts = []
        for a in alerts_src:
            alerts.append(
                {
                    "pluginid": a["pluginid"],
                    "alertRef": a["pluginid"],
                    "alert": a["alert"],
                    "name": a["alert"],
                    "riskcode": a["riskcode"],
                    "riskdesc": "Lab suite",
                    "confidence": "2",
                    "desc": a["desc"],
                    "solution": a["solution"],
                    "cweid": a["cweid"],
                    "owasp": a["owasp"],
                    "wascid": "15",
                    "instances": [
                        {"uri": uri, "method": "GET", "param": "", "attack": "", "evidence": ""}
                    ],
                }
            )
        sites.append({"@name": raw, "@host": host, "alerts": alerts})
    payload = {
        "@version": "nexusec-dast-suite/1.0",
        "@generated": now,
        "site": sites if len(sites) > 1 else sites[0],
        "nexusec_mock": True,
        "policy": policy,
        "suite": "owasp_top10_2021",
        "standard": "OWASP Top 10:2021",
    }
    return json.dumps(payload, indent=2)
