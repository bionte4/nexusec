"""Nuclei JSON / JSONL → NormalizedFinding parser."""

from __future__ import annotations

import json
from typing import Any, Optional

from app.core.enums import Severity
from app.normalization.base import FindingParser, RawInput
from app.normalization.schema import NormalizedFinding

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.UNKNOWN,
}


class NucleiJsonParser(FindingParser):
    name = "nuclei"

    def parse(self, raw: RawInput) -> list[NormalizedFinding]:
        items = self._load_items(raw)
        findings: list[NormalizedFinding] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            parsed = self._parse_item(item)
            if parsed is not None:
                findings.append(parsed)
        return findings

    def _load_items(self, raw: RawInput) -> list[Any]:
        if isinstance(raw, list):
            return raw
        if isinstance(raw, dict):
            return [raw]
        if isinstance(raw, bytes):
            text = raw.decode("utf-8", errors="replace")
        elif isinstance(raw, str):
            text = raw
        else:
            raise TypeError("NucleiJsonParser expects JSON string/bytes/list/dict")

        text = text.strip()
        if not text:
            return []

        # JSON array
        if text.startswith("["):
            data = json.loads(text)
            if not isinstance(data, list):
                raise ValueError("Expected JSON array from Nuclei")
            return data

        # Single object
        if text.startswith("{"):
            # Could be one object or JSONL starting with {
            lines = [ln for ln in text.splitlines() if ln.strip()]
            if len(lines) == 1:
                obj = json.loads(lines[0])
                return [obj] if isinstance(obj, dict) else list(obj)
            items: list[Any] = []
            for line in lines:
                items.append(json.loads(line))
            return items

        # JSONL without leading [
        items = []
        for line in text.splitlines():
            line = line.strip()
            if line:
                items.append(json.loads(line))
        return items

    def _parse_item(self, item: dict[str, Any]) -> Optional[NormalizedFinding]:
        info = item.get("info") or {}
        if not isinstance(info, dict):
            info = {}

        template_id = str(
            item.get("template-id") or item.get("templateID") or info.get("name") or "nuclei"
        )
        name = str(info.get("name") or template_id)
        severity_raw = str(info.get("severity") or "unknown").lower()
        severity = _SEVERITY_MAP.get(severity_raw, Severity.UNKNOWN)

        classification = info.get("classification") or {}
        cwe_list = classification.get("cwe-id") or classification.get("cwe_id") or []
        cwe_id = None
        if isinstance(cwe_list, list) and cwe_list:
            cwe_id = str(cwe_list[0])
        elif isinstance(cwe_list, str):
            cwe_id = cwe_list

        cve_list = classification.get("cve-id") or classification.get("cve_id") or []
        cve_id = None
        if isinstance(cve_list, list) and cve_list:
            cve_id = str(cve_list[0])
        elif isinstance(cve_list, str):
            cve_id = cve_list

        cvss_score = classification.get("cvss-score") or classification.get("cvss_score")
        try:
            cvss_score_f = float(cvss_score) if cvss_score is not None else None
        except (TypeError, ValueError):
            cvss_score_f = None

        host = item.get("host") or item.get("matched-at") or item.get("ip")
        matched = str(item.get("matched-at") or host or "")
        port = self._extract_port(item, matched)

        tags = info.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]

        mitre = []
        for tag in tags:
            if str(tag).upper().startswith("T") and str(tag)[1:].replace(".", "").isdigit():
                mitre.append(str(tag).upper())

        return NormalizedFinding(
            vuln_id=f"nuclei:{template_id}:{matched}"[:128],
            name=name[:512],
            description=(info.get("description") or item.get("matcher-name") or None),
            severity=severity,
            cvss_score=cvss_score_f,
            cwe_id=cwe_id,
            cve_id=cve_id,
            mitre_tactics=mitre,
            remediation_steps=info.get("remediation"),
            port=port,
            protocol=str(item.get("type") or "http")[:32],
            affected_component=str(item.get("template-id") or template_id)[:512],
            evidence={
                "matched_at": matched,
                "matcher_name": item.get("matcher-name"),
                "extracted_results": item.get("extracted-results") or [],
                "tags": tags,
            },
            source_tool="nuclei",
            raw_source=item,
            target_hint=str(host) if host else self._host_from_url(matched),
            iso_27001_clause=["A.8.8"],
            pci_dss_requirement=["11.3.1"],
            gdpr_risk_flag="pii" in {str(t).lower() for t in tags},
        )

    @staticmethod
    def _extract_port(item: dict[str, Any], matched: str) -> Optional[int]:
        if item.get("port") is not None:
            try:
                return int(item["port"])
            except (TypeError, ValueError):
                pass
        # matched-at like https://host:8443/path
        if "://" in matched:
            try:
                from urllib.parse import urlparse

                parsed = urlparse(matched)
                if parsed.port:
                    return int(parsed.port)
                if parsed.scheme == "https":
                    return 443
                if parsed.scheme == "http":
                    return 80
            except Exception:
                return None
        return None

    @staticmethod
    def _host_from_url(value: str) -> Optional[str]:
        if not value:
            return None
        if "://" not in value:
            return value.split("/")[0].split(":")[0]
        try:
            from urllib.parse import urlparse

            return urlparse(value).hostname
        except Exception:
            return None
