"""PortSwigger Burp Suite issue export (XML) → NormalizedFinding."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Optional
from urllib.parse import urlparse

from app.normalization.base import FindingParser, RawInput
from app.normalization.schema import NormalizedFinding
from app.normalization.severity_map import map_severity


class BurpXmlParser(FindingParser):
    """Parse Burp `issues` XML export (common professional pentest deliverable)."""

    name = "burp"

    def parse(self, raw: RawInput) -> list[NormalizedFinding]:
        root = self._root(raw)
        findings: list[NormalizedFinding] = []
        # Burp wraps as <issues><issue>...</issue></issues> or bare <issue>
        issues = list(root.findall(".//issue"))
        if root.tag == "issue":
            issues = [root]
        for idx, issue in enumerate(issues):
            parsed = self._parse_issue(issue, idx)
            if parsed is not None:
                findings.append(parsed)
        return findings

    def _parse_issue(self, issue: ET.Element, idx: int) -> Optional[NormalizedFinding]:
        serial = (issue.findtext("serialNumber") or "").strip()
        name = (issue.findtext("name") or "").strip()
        if not name and not serial:
            return None
        severity = map_severity(issue.findtext("severity"), default=map_severity("medium"))
        host = (issue.findtext("host") or "").strip()
        # host may include scheme attributes
        host_el = issue.find("host")
        if host_el is not None and host_el.get("ip"):
            host = host or host_el.get("ip") or host
        path = (issue.findtext("path") or "").strip()
        url = f"{host.rstrip('/')}{path}" if host and path else host or path
        parsed_url = urlparse(url if "://" in url else f"https://{url}" if url else "")
        port = parsed_url.port
        cwe = (issue.findtext("vulnerabilityClassifications") or "").strip()
        # Often "CWE-79: ..."
        cwe_id = None
        if "CWE-" in cwe.upper():
            part = cwe.upper().split("CWE-", 1)[1]
            num = "".join(ch for ch in part if ch.isdigit())
            if num:
                cwe_id = f"CWE-{num}"

        vuln_id = f"burp:{serial or idx}:{name}"[:128]
        return NormalizedFinding(
            vuln_id=vuln_id,
            name=(name or f"Burp issue {serial or idx}")[:512],
            description=(issue.findtext("issueBackground") or issue.findtext("issueDetail") or name),
            severity=severity,
            cwe_id=cwe_id,
            remediation_steps=(
                issue.findtext("remediationBackground")
                or issue.findtext("remediationDetail")
                or None
            ),
            affected_component=url or path or None,
            port=port,
            evidence={
                "confidence": issue.findtext("confidence"),
                "type": issue.findtext("type"),
                "path": path,
            },
            source_tool="burp",
            raw_source={"serialNumber": serial, "name": name, "host": host, "path": path},
            target_hint=parsed_url.hostname or host or None,
        )

    @staticmethod
    def _root(raw: RawInput) -> ET.Element:
        if isinstance(raw, bytes):
            text = raw.decode("utf-8", errors="replace")
        elif isinstance(raw, str):
            text = raw
        else:
            raise TypeError("BurpXmlParser expects XML string/bytes")
        text = text.strip()
        if not text:
            raise ValueError("Empty Burp XML")
        return ET.fromstring(text)
