"""OWASP ZAP connector wrapper — import real JSON or mock alerts for lab/CI DAST.

Live ZAP daemon (zaproxy API) can be added later; production defaults to import.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional, Sequence

from workers.tool_wrappers.base import ExecutionResult, ToolExecutionError
from workers.tool_wrappers.validators import TargetValidationError, validate_target

DEFAULT_ZAP_MODE = "import"


@dataclass
class ZapScanRequest:
    targets: list[str]
    timeout_seconds: int = 900
    mode: Optional[str] = None
    report_json: Optional[str] = None
    # spider | active (mock labels only)
    scan_policy: str = "baseline"
    lab_mode: bool = False


def _risk_for(name: str) -> tuple[str, str, str]:
    """Return (riskcode, riskdesc, cweid)."""
    table = {
        "Missing Anti-clickjacking Header": ("1", "Low (Medium)", "1021"),
        "Content Security Policy (CSP) Header Not Set": ("2", "Medium (Medium)", "693"),
        "X-Content-Type-Options Header Missing": ("1", "Low (Medium)", "693"),
        "Strict-Transport-Security Header Not Set": ("1", "Low (Medium)", "319"),
        "Application Error Disclosure": ("2", "Medium (Medium)", "209"),
        "SQL Injection": ("3", "High (Medium)", "89"),
        "Cross Site Scripting (Reflected)": ("3", "High (Medium)", "79"),
    }
    return table.get(name, ("1", "Low (Medium)", "16"))


def build_mock_zap_report(targets: list[str], *, policy: str = "baseline") -> str:
    """Deterministic ZAP-like JSON (site + alerts) for normalization demos.

    ``policy=owasp_top10`` (or ``asvs`` / ``international``) emits the offline
    OWASP Top 10:2021 DAST suite — no external zaproxy required.
    """
    pol = (policy or "baseline").lower()
    if pol in {"owasp_top10", "owasp", "asvs", "international", "top10"}:
        try:
            from app.services.engagement_standards import build_offline_owasp_dast_report

            return build_offline_owasp_dast_report(targets, policy=pol)
        except ImportError:
            import sys
            from pathlib import Path

            root = Path(__file__).resolve().parents[2]
            if str(root) not in sys.path:
                sys.path.insert(0, str(root))
            from app.services.engagement_standards import build_offline_owasp_dast_report

            return build_offline_owasp_dast_report(targets, policy=pol)

    now = datetime.now(timezone.utc).isoformat()
    baseline_alerts = [
        "Missing Anti-clickjacking Header",
        "Content Security Policy (CSP) Header Not Set",
        "X-Content-Type-Options Header Missing",
        "Strict-Transport-Security Header Not Set",
    ]
    active_extra = [
        "Application Error Disclosure",
        "SQL Injection",
        "Cross Site Scripting (Reflected)",
    ]
    names = list(baseline_alerts)
    if pol in {"active", "full", "attack"}:
        names.extend(active_extra)

    sites: list[dict[str, Any]] = []
    for raw in targets:
        host = raw
        if "://" in raw:
            from urllib.parse import urlparse

            host = urlparse(raw).hostname or raw
        alerts = []
        for n, alert_name in enumerate(names):
            riskcode, riskdesc, cwe = _risk_for(alert_name)
            alerts.append(
                {
                    "pluginid": str(10000 + n),
                    "alertRef": f"{10000 + n}",
                    "alert": alert_name,
                    "name": alert_name,
                    "riskcode": riskcode,
                    "riskdesc": riskdesc,
                    "confidence": "2",
                    "desc": (
                        f"ZAP mock ({policy}) finding '{alert_name}' on {host}. "
                        "Unauthenticated DAST surface check (CWE-"
                        f"{cwe})."
                    ),
                    "solution": "Apply the recommended secure header / input validation fix.",
                    "cweid": cwe,
                    "wascid": "15",
                    "instances": [
                        {
                            "uri": raw if "://" in raw else f"https://{raw}/",
                            "method": "GET",
                            "param": "",
                            "attack": "",
                            "evidence": "",
                        }
                    ],
                }
            )
        sites.append({"@name": raw, "@host": host, "alerts": alerts})

    payload = {
        "@version": "2.15.0",
        "@generated": now,
        "site": sites if len(sites) > 1 else sites[0],
        "nexusec_mock": True,
        "policy": policy,
    }
    return json.dumps(payload, indent=2)


class ZapWrapper:
    """Build ZAP JSON report (mock) or accept imported report_json."""

    def __init__(self, *, mode: Optional[str] = None) -> None:
        self.mode = (mode or os.getenv("ZAP_MODE") or DEFAULT_ZAP_MODE).lower()

    def run(self, request: ZapScanRequest) -> ExecutionResult:
        if request.report_json and str(request.report_json).strip():
            return ExecutionResult(
                command=("zap", "import-json"),
                returncode=0,
                stdout=str(request.report_json),
                stderr="",
            )

        try:
            targets: list[str] = []
            for t in request.targets:
                host = validate_target(t if "://" not in t else t.split("://", 1)[1].split("/")[0])
                # Keep original URL-ish target for report URIs when provided
                if "://" in t:
                    from urllib.parse import urlparse

                    p = urlparse(t)
                    if p.scheme not in {"http", "https"}:
                        raise TargetValidationError(f"ZAP target must be http(s): {t!r}")
                    targets.append(f"{p.scheme}://{host}{p.path or ''}".rstrip("/") or f"{p.scheme}://{host}")
                else:
                    targets.append(f"https://{host}")
        except TargetValidationError as exc:
            raise ToolExecutionError(str(exc)) from exc
        if not targets:
            raise ToolExecutionError("No valid ZAP targets")

        mode = (request.mode or self.mode).lower()
        if mode == "import" and not (request.report_json and str(request.report_json).strip()):
            raise ToolExecutionError(
                "zap_mode=import requires report_json (use Import scanner report). "
                "For lab demos use zap_mode=mock with lab_mode=true."
            )
        if mode == "daemon":
            raise ToolExecutionError(
                "ZAP daemon mode is not enabled in this build; "
                "use Import ZAP JSON or zap_mode=mock with lab_mode=true"
            )
        if mode not in {"mock", "", "default"}:
            raise ToolExecutionError(
                f"Unsupported zap_mode={mode!r} (use import+report_json or mock+lab_mode)"
            )

        app_env = (os.getenv("APP_ENV") or "").lower()
        if app_env in {"production", "prod"} and not request.lab_mode:
            raise ToolExecutionError(
                "ZAP mock is refused in production. Import real ZAP JSON via "
                "Import scanner report, or enqueue with lab_mode=true for demos only."
            )

        payload = build_mock_zap_report(targets, policy=request.scan_policy)
        return ExecutionResult(
            command=("zap", "mock", request.scan_policy, *targets),
            returncode=0,
            stdout=payload,
            stderr=f"zap mock connector: generated synthetic DAST report (policy={request.scan_policy})",
        )
