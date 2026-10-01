"""Tenable Nessus .nessus XML → NormalizedFinding."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Optional

from app.core.enums import Severity
from app.normalization.base import FindingParser, RawInput
from app.normalization.schema import NormalizedFinding
from app.normalization.severity_map import map_severity


class NessusXmlParser(FindingParser):
    """Parse Nessus Client XML (.nessus) ReportItem elements."""

    name = "nessus"

    def parse(self, raw: RawInput) -> list[NormalizedFinding]:
        root = self._root(raw)
        findings: list[NormalizedFinding] = []
        for host in root.findall(".//ReportHost"):
            host_name = host.get("name") or ""
            for tag in host.findall("HostProperties/tag"):
                if tag.get("name") == "host-ip" and (tag.text or "").strip():
                    host_name = tag.text.strip()
                    break
            for item in host.findall("ReportItem"):
                parsed = self._parse_item(item, host_name=host_name)
                if parsed is not None:
                    findings.append(parsed)
        return findings

    def _parse_item(
        self, item: ET.Element, *, host_name: str
    ) -> Optional[NormalizedFinding]:
        plugin_id = item.get("pluginID") or item.get("pluginId") or ""
        plugin_name = item.get("pluginName") or (item.findtext("plugin_name") or "")
        if not plugin_id and not plugin_name:
            return None
        severity = map_severity(item.get("severity"), default=Severity.INFO)
        risk = (item.findtext("risk_factor") or "").strip()
        if risk:
            severity = map_severity(risk, default=severity)

        port_raw = item.get("port")
        port = None
        try:
            if port_raw and port_raw != "0":
                port = int(port_raw)
        except ValueError:
            port = None

        cve = None
        for el in item.findall("cve"):
            if (el.text or "").strip():
                cve = el.text.strip()
                break

        cvss = item.findtext("cvss3_base_score") or item.findtext("cvss_base_score")
        try:
            cvss_f = float(cvss) if cvss else None
        except ValueError:
            cvss_f = None

        cwe = item.findtext("cwe")
        cwe_id = None
        if cwe:
            cwe_id = (
                f"CWE-{cwe}" if not str(cwe).upper().startswith("CWE") else str(cwe)
            )

        vuln_id = f"nessus:{plugin_id}:{port or 0}"[:128]
        return NormalizedFinding(
            vuln_id=vuln_id,
            name=(plugin_name or f"Nessus {plugin_id}")[:512],
            description=(item.findtext("description") or plugin_name or None),
            severity=severity,
            cvss_score=cvss_f,
            cve_id=cve,
            cwe_id=cwe_id,
            remediation_steps=(item.findtext("solution") or None),
            port=port,
            protocol=(item.get("protocol") or None),
            affected_component=(item.get("svc_name") or None),
            evidence={
                "plugin_family": item.get("pluginFamily"),
                "synopsis": item.findtext("synopsis"),
            },
            source_tool="nessus",
            raw_source={
                "pluginID": plugin_id,
                "pluginName": plugin_name,
                "host": host_name,
            },
            target_hint=host_name or None,
        )

    @staticmethod
    def _root(raw: RawInput) -> ET.Element:
        if isinstance(raw, bytes):
            text = raw.decode("utf-8", errors="replace")
        elif isinstance(raw, str):
            text = raw
        else:
            raise TypeError("NessusXmlParser expects XML string/bytes")
        text = text.strip()
        if not text:
            raise ValueError("Empty Nessus XML")
        return ET.fromstring(text)
