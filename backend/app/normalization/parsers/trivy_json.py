"""Aqua Trivy JSON → NormalizedFinding parser."""

from __future__ import annotations

import json
from typing import Any, Optional

from app.normalization.base import FindingParser, RawInput
from app.normalization.schema import NormalizedFinding
from app.normalization.severity_map import map_severity


class TrivyJsonParser(FindingParser):
    """Parse `trivy image -f json` / fs / config Results[].Vulnerabilities|Misconfigurations."""

    name = "trivy"

    def parse(self, raw: RawInput) -> list[NormalizedFinding]:
        data = self._load(raw)
        results = data.get("Results") if isinstance(data, dict) else None
        if results is None and isinstance(data, list):
            results = data
        if not isinstance(results, list):
            # Single-result document without Results wrapper
            if isinstance(data, dict) and (
                data.get("Vulnerabilities") or data.get("Misconfigurations")
            ):
                results = [data]
            else:
                raise ValueError("Trivy JSON must contain Results[]")

        findings: list[NormalizedFinding] = []
        for result in results:
            if not isinstance(result, dict):
                continue
            target = str(result.get("Target") or result.get("target") or "")
            for vuln in result.get("Vulnerabilities") or []:
                if isinstance(vuln, dict):
                    parsed = self._vuln(vuln, target=target)
                    if parsed:
                        findings.append(parsed)
            for mis in result.get("Misconfigurations") or []:
                if isinstance(mis, dict):
                    parsed = self._misconfig(mis, target=target)
                    if parsed:
                        findings.append(parsed)
            for secret in result.get("Secrets") or []:
                if isinstance(secret, dict):
                    parsed = self._secret(secret, target=target)
                    if parsed:
                        findings.append(parsed)
        return findings

    def _vuln(self, item: dict[str, Any], *, target: str) -> Optional[NormalizedFinding]:
        vid = str(item.get("VulnerabilityID") or item.get("PkgID") or item.get("Title") or "")
        if not vid:
            return None
        pkg = str(item.get("PkgName") or item.get("Package") or "")
        title = str(item.get("Title") or vid)
        return NormalizedFinding(
            vuln_id=f"trivy:{vid}:{pkg}"[:128],
            name=title[:512],
            description=str(item.get("Description") or title),
            severity=map_severity(item.get("Severity"), default=map_severity("unknown")),
            cvss_score=self._cvss(item),
            cve_id=vid if vid.upper().startswith("CVE-") else None,
            cwe_id=self._cwe(item),
            remediation_steps=str(item.get("FixedVersion") or "") or None,
            affected_component=(f"{pkg}@{item.get('InstalledVersion')}" if pkg else target) or None,
            evidence={"primary_url": item.get("PrimaryURL"), "target": target},
            source_tool="trivy",
            raw_source=item,
            target_hint=target or None,
        )

    def _misconfig(self, item: dict[str, Any], *, target: str) -> Optional[NormalizedFinding]:
        mid = str(item.get("ID") or item.get("AVDID") or item.get("Title") or "")
        if not mid:
            return None
        title = str(item.get("Title") or mid)
        return NormalizedFinding(
            vuln_id=f"trivy-misconfig:{mid}"[:128],
            name=title[:512],
            description=str(item.get("Description") or item.get("Message") or title),
            severity=map_severity(item.get("Severity"), default=map_severity("medium")),
            remediation_steps=str(item.get("Resolution") or "") or None,
            affected_component=target or None,
            evidence={"target": target, "type": item.get("Type")},
            source_tool="trivy",
            raw_source=item,
            target_hint=target or None,
        )

    def _secret(self, item: dict[str, Any], *, target: str) -> Optional[NormalizedFinding]:
        sid = str(item.get("RuleID") or item.get("Title") or "secret")
        return NormalizedFinding(
            vuln_id=f"trivy-secret:{sid}:{item.get('StartLine')}"[:128],
            name=str(item.get("Title") or sid)[:512],
            description=str(item.get("Category") or "Secret detected"),
            severity=map_severity(item.get("Severity"), default=map_severity("high")),
            affected_component=str(item.get("File") or target) or None,
            evidence={"target": target, "match": item.get("Match")},
            source_tool="trivy",
            raw_source=item,
            target_hint=target or None,
        )

    @staticmethod
    def _cvss(item: dict[str, Any]) -> Optional[float]:
        cvss = item.get("CVSS") or {}
        if not isinstance(cvss, dict):
            return None
        for vendor in ("nvd", "redhat", "ghsa"):
            block = cvss.get(vendor) or cvss.get(vendor.upper())
            if isinstance(block, dict):
                score = block.get("V3Score") or block.get("V2Score") or block.get("Score")
                try:
                    return float(score) if score is not None else None
                except (TypeError, ValueError):
                    continue
        return None

    @staticmethod
    def _cwe(item: dict[str, Any]) -> Optional[str]:
        cwe_ids = item.get("CweIDs") or item.get("CWE") or []
        if isinstance(cwe_ids, list) and cwe_ids:
            return str(cwe_ids[0])
        if isinstance(cwe_ids, str):
            return cwe_ids
        return None

    @staticmethod
    def _load(raw: RawInput) -> Any:
        if isinstance(raw, (dict, list)):
            return raw
        if isinstance(raw, bytes):
            text = raw.decode("utf-8", errors="replace")
        elif isinstance(raw, str):
            text = raw
        else:
            raise TypeError("TrivyJsonParser expects JSON")
        return json.loads(text) if text.strip() else {}
