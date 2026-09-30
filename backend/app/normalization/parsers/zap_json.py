"""OWASP ZAP JSON report → NormalizedFinding parser."""

from __future__ import annotations

import json
from typing import Any, Optional
from urllib.parse import urlparse

from app.core.enums import Severity
from app.normalization.base import FindingParser, RawInput
from app.normalization.schema import NormalizedFinding

_RISK_MAP = {
    "0": Severity.INFO,
    "1": Severity.LOW,
    "2": Severity.MEDIUM,
    "3": Severity.HIGH,
    "4": Severity.CRITICAL,
}


def _cwe(value: Any) -> Optional[str]:
    if value is None or value == "" or str(value) in {"-1", "0"}:
        return None
    raw = str(value).strip()
    if raw.upper().startswith("CWE-"):
        return raw.upper()
    if raw.isdigit():
        return f"CWE-{raw}"
    return None


class ZapJsonParser(FindingParser):
    """Parse ZAP JSON export (``site.alerts`` or top-level ``alerts``)."""

    name = "zap"

    def parse(self, raw: RawInput) -> list[NormalizedFinding]:
        text = self._to_text(raw)
        if not text.strip():
            return []
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid ZAP JSON: {exc}") from exc

        findings: list[NormalizedFinding] = []
        for site in self._iter_sites(data):
            host = str(site.get("@host") or site.get("host") or "")
            alerts = site.get("alerts") or []
            if not isinstance(alerts, list):
                continue
            for alert in alerts:
                if not isinstance(alert, dict):
                    continue
                findings.extend(self._from_alert(alert, default_host=host))
        if not findings and isinstance(data.get("alerts"), list):
            for alert in data["alerts"]:
                if isinstance(alert, dict):
                    findings.extend(self._from_alert(alert, default_host=""))
        return findings

    @staticmethod
    def _iter_sites(data: dict[str, Any]) -> list[dict[str, Any]]:
        site = data.get("site")
        if isinstance(site, list):
            return [s for s in site if isinstance(s, dict)]
        if isinstance(site, dict):
            return [site]
        return []

    def _from_alert(
        self, alert: dict[str, Any], *, default_host: str
    ) -> list[NormalizedFinding]:
        title = str(alert.get("alert") or alert.get("name") or "ZAP alert").strip()
        riskcode = str(alert.get("riskcode") or "1")
        severity = _RISK_MAP.get(riskcode, Severity.LOW)
        cwe_id = _cwe(alert.get("cweid") or alert.get("cwe"))
        plugin = str(alert.get("pluginid") or alert.get("alertRef") or "zap")
        desc = str(alert.get("desc") or alert.get("description") or title)
        solution = str(alert.get("solution") or "").strip() or None

        instances = alert.get("instances") or [{}]
        if not isinstance(instances, list) or not instances:
            instances = [{}]

        out: list[NormalizedFinding] = []
        for inst in instances:
            if not isinstance(inst, dict):
                inst = {}
            uri = str(inst.get("uri") or "")
            host = default_host
            path = None
            port = None
            if uri:
                parsed = urlparse(uri)
                host = parsed.hostname or host
                path = parsed.path or None
                if parsed.port:
                    port = parsed.port
                elif parsed.scheme == "https":
                    port = 443
                elif parsed.scheme == "http":
                    port = 80

            out.append(
                NormalizedFinding(
                    vuln_id=f"zap:{plugin}:{host}:{path or '/'}:{title}"[:128],
                    name=title[:512],
                    description=desc[:4000],
                    severity=severity,
                    cwe_id=cwe_id,
                    port=port,
                    protocol="tcp" if port else None,
                    affected_component=(path or uri or host or None),
                    target_hint=host or None,
                    remediation_steps=solution,
                    owasp_category="A05:2021",
                    evidence={
                        "zap": {
                            "pluginid": plugin,
                            "riskcode": riskcode,
                            "uri": uri,
                            "method": inst.get("method"),
                        }
                    },
                    source_tool="zap",
                    raw_source={"alert": title, "uri": uri},
                    iso_27001_clause=["A.8.8"],
                    nist_csf=["ID.RA-01"],
                    nist_800_53=["RA-5"],
                )
            )
        return out

    @staticmethod
    def _to_text(raw: RawInput) -> str:
        if isinstance(raw, bytes):
            return raw.decode("utf-8", errors="replace")
        if isinstance(raw, str):
            return raw
        raise TypeError("ZapJsonParser expects JSON string/bytes")
