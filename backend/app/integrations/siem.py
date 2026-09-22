"""SIEM exporters — CEF and JSON (syslog / HEC-friendly)."""

from __future__ import annotations

import json
import logging
import socket
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

from app.core.config import get_settings

logger = logging.getLogger(__name__)


def to_json_syslog(finding: dict[str, Any]) -> str:
    """Single-line JSON log suitable for syslog / Elastic bulk ingest."""
    event = {
        "@timestamp": finding.get("event_time") or datetime.now(timezone.utc).isoformat(),
        "event": {
            "module": "nexusec",
            "dataset": "vulnerability",
            "severity": finding.get("severity"),
            "action": "finding",
        },
        "vulnerability": {
            "id": finding.get("vulnerability_id"),
            "title": finding.get("title"),
            "severity": finding.get("severity"),
            "status": finding.get("status"),
            "cve": finding.get("cve_id"),
            "cwe": finding.get("cwe_id"),
            "score": {"base": finding.get("cvss_score")},
        },
        "host": {"name": finding.get("asset_name"), "id": finding.get("asset_id")},
        "observer": {"product": "NexuSec", "vendor": "NexuSec"},
        "message": finding.get("title"),
    }
    return json.dumps(event, separators=(",", ":"), ensure_ascii=True)


def _cef_escape(value: str) -> str:
    return (
        str(value).replace("\\", "\\\\").replace("=", "\\=").replace("\n", "\\n").replace("\r", "")
    )


def to_cef(finding: dict[str, Any]) -> str:
    """
    Common Event Format line.

    CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    """
    sev_map = {
        "info": 1,
        "unknown": 2,
        "low": 3,
        "medium": 5,
        "high": 8,
        "critical": 10,
    }
    sev = sev_map.get(str(finding.get("severity", "unknown")).lower(), 2)
    signature = finding.get("cve_id") or finding.get("cwe_id") or "NexuSecFinding"
    name = _cef_escape(str(finding.get("title") or "vulnerability")[:128])
    extensions = {
        "msg": _cef_escape(str(finding.get("description") or finding.get("title") or "")[:512]),
        "cs1": _cef_escape(str(finding.get("vulnerability_id"))),
        "cs1Label": "vulnerabilityId",
        "cs2": _cef_escape(str(finding.get("status"))),
        "cs2Label": "findingStatus",
        "cs3": _cef_escape(str(finding.get("cwe_id") or "")),
        "cs3Label": "cwe",
        "cn1": str(finding.get("cvss_score") or 0),
        "cn1Label": "cvssScore",
        "dhost": _cef_escape(str(finding.get("asset_name") or "")),
        "deviceExternalId": _cef_escape(str(finding.get("asset_id") or "")),
        "externalId": _cef_escape(str(finding.get("cve_id") or "")),
        "rt": datetime.now(timezone.utc).strftime("%b %d %Y %H:%M:%S UTC"),
    }
    ext = " ".join(f"{k}={v}" for k, v in extensions.items() if v not in {"", "None"})
    return f"CEF:0|NexuSec|NexuSec VA/PT|0.1.0|{_cef_escape(str(signature))}|" f"{name}|{sev}|{ext}"


class SiemForwarder:
    """Forward normalized findings to HTTP SIEM collectors (Elastic/Splunk HEC style)."""

    def __init__(
        self,
        *,
        enabled: Optional[bool] = None,
        fmt: Optional[str] = None,
        url: Optional[str] = None,
        hec_token: Optional[str] = None,
        timeout_seconds: float = 10.0,
    ) -> None:
        settings = get_settings()
        self.enabled = settings.siem_enabled if enabled is None else enabled
        self.fmt = (fmt or settings.siem_format).lower()
        self.url = url if url is not None else settings.siem_webhook_url
        self.hec_token = hec_token if hec_token is not None else settings.siem_hec_token
        self.timeout_seconds = timeout_seconds

    def format_event(self, finding: dict[str, Any]) -> str:
        if self.fmt == "cef":
            return to_cef(finding)
        return to_json_syslog(finding)

    def forward(self, finding: dict[str, Any]) -> dict[str, Any]:
        if not self.enabled or not self.url:
            return {"skipped": True, "reason": "siem disabled or url missing"}

        line = self.format_event(finding)
        headers = {"Content-Type": "application/json"}
        # Splunk HEC token support (optional)
        if self.hec_token:
            headers["Authorization"] = f"Splunk {self.hec_token}"

        body: Any
        if self.fmt == "cef":
            # wrap CEF for HTTP collectors that expect JSON
            body = {
                "event": line,
                "sourcetype": "nexusec:cef",
                "source": "nexusec",
                "host": socket.gethostname(),
            }
        else:
            # JSON syslog already a JSON object string — send as event envelope
            body = {
                "event": json.loads(line),
                "sourcetype": "nexusec:vulnerability",
                "source": "nexusec",
                "host": socket.gethostname(),
            }

        try:
            with httpx.Client(timeout=self.timeout_seconds) as client:
                resp = client.post(self.url, headers=headers, json=body)
            ok = 200 <= resp.status_code < 300
            if not ok:
                logger.warning("SIEM forward failed status=%s", resp.status_code)
            return {
                "ok": ok,
                "status_code": resp.status_code,
                "format": self.fmt,
            }
        except httpx.HTTPError as exc:
            logger.warning("SIEM forward error: %s", exc)
            return {"ok": False, "error": str(exc), "format": self.fmt}
