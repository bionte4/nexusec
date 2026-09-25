"""OpenVAS / Greenbone GVM XML report → NormalizedFinding parser."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Optional
from xml.etree.ElementTree import Element

from app.core.enums import Severity
from app.normalization.base import FindingParser, RawInput
from app.normalization.schema import NormalizedFinding

_THREAT_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "log": Severity.INFO,
    "info": Severity.INFO,
    "debug": Severity.INFO,
    "false positive": Severity.INFO,
}


class OpenVasXmlParser(FindingParser):
    """Parse OpenVAS / GVM ``<report>`` XML (results/result nodes)."""

    name = "openvas"

    def parse(self, raw: RawInput) -> list[NormalizedFinding]:
        text = self._to_text(raw)
        if not text.strip():
            return []
        try:
            root = ET.fromstring(text)
        except ET.ParseError as exc:
            raise ValueError(f"Invalid OpenVAS XML: {exc}") from exc

        # Accept <report>, <get_reports_response><report>, or bare <results>
        results_parent = root
        if root.tag.endswith("get_reports_response"):
            report = root.find(".//report")
            if report is not None:
                results_parent = report
        elif root.tag.endswith("report"):
            results_parent = root

        findings: list[NormalizedFinding] = []
        for result in results_parent.findall(".//result"):
            finding = self._parse_result(result)
            if finding is not None:
                findings.append(finding)
        return findings

    def _parse_result(self, el: Element) -> Optional[NormalizedFinding]:
        name = (el.findtext("name") or "").strip()
        if not name:
            nvt = el.find("nvt")
            name = (nvt.findtext("name") if nvt is not None else None) or "OpenVAS finding"
        host = (el.findtext("host") or el.findtext("host/asset/host") or "").strip()
        port_raw = (el.findtext("port") or "").strip()
        port, protocol = self._parse_port(port_raw)
        threat = (el.findtext("threat") or el.findtext("severity") or "unknown").strip()
        severity = _THREAT_MAP.get(threat.lower(), Severity.UNKNOWN)
        # Prefer numeric CVSS if present
        cvss_score = None
        sev_text = (el.findtext("severity") or "").strip()
        try:
            cvss_score = float(sev_text)
            if severity == Severity.UNKNOWN:
                severity = self._cvss_to_severity(cvss_score)
        except ValueError:
            pass

        nvt = el.find("nvt")
        cve_id = None
        cwe_id = None
        oid = None
        if nvt is not None:
            oid = nvt.attrib.get("oid") or nvt.findtext("oid")
            cve_raw = (nvt.findtext("cve") or "").strip()
            if cve_raw and cve_raw.upper() not in {"", "NOCVE", "N/A"}:
                # may be comma-separated
                first = cve_raw.split(",")[0].strip().upper()
                if first.startswith("CVE-"):
                    cve_id = first
            refs = nvt.findtext("refs") or nvt.findtext("xref") or ""
            cwe_match = re.search(r"CWE-?(\d+)", refs, re.I)
            if cwe_match:
                cwe_id = f"CWE-{cwe_match.group(1)}"

        description = (el.findtext("description") or "").strip() or None
        if cwe_id is None and description:
            cwe_match = re.search(r"CWE-?(\d+)", description, re.I)
            if cwe_match:
                cwe_id = f"CWE-{cwe_match.group(1)}"
        vuln_id = f"openvas:{oid or name}:{host}:{port_raw}"[:128]

        return NormalizedFinding(
            vuln_id=vuln_id,
            name=name[:512],
            description=description,
            severity=severity,
            cvss_score=cvss_score,
            cve_id=cve_id,
            cwe_id=cwe_id,
            port=port,
            protocol=protocol,
            affected_component=port_raw or None,
            evidence={
                "openvas": {
                    "threat": threat,
                    "port": port_raw,
                    "oid": oid,
                    "host": host,
                }
            },
            source_tool="openvas",
            raw_source={"result_id": el.attrib.get("id")},
            target_hint=host or None,
        )

    @staticmethod
    def _to_text(raw: RawInput) -> str:
        if isinstance(raw, bytes):
            return raw.decode("utf-8", errors="replace")
        if isinstance(raw, str):
            return raw
        raise TypeError("OpenVasXmlParser expects XML string/bytes")

    @staticmethod
    def _parse_port(port_raw: str) -> tuple[Optional[int], Optional[str]]:
        if not port_raw:
            return None, None
        # e.g. "22/tcp", "443/tcp", "general/tcp"
        m = re.match(r"^(\d+)\s*/\s*(\w+)$", port_raw.strip())
        if m:
            return int(m.group(1)), m.group(2).lower()
        return None, None

    @staticmethod
    def _cvss_to_severity(score: float) -> Severity:
        if score >= 9.0:
            return Severity.CRITICAL
        if score >= 7.0:
            return Severity.HIGH
        if score >= 4.0:
            return Severity.MEDIUM
        if score > 0:
            return Severity.LOW
        return Severity.INFO
