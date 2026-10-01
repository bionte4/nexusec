"""Generic JSON findings adapter — lenient field aliases (P1)."""

from __future__ import annotations

import json
from typing import Any, Optional

from app.normalization.base import FindingParser, RawInput
from app.normalization.schema import NormalizedFinding
from app.normalization.severity_map import map_severity


class GenericJsonParser(FindingParser):
    """
    Accept loosely-shaped JSON findings lists without full NormalizedFinding keys.

    Supported envelopes:
      - { "findings": [ {...}, ... ] }
      - [ {...}, ... ]
      - single { ... } object
    """

    name = "generic"

    def parse(self, raw: RawInput) -> list[NormalizedFinding]:
        items = self._load(raw)
        out: list[NormalizedFinding] = []
        for idx, item in enumerate(items):
            if not isinstance(item, dict):
                continue
            parsed = self._parse_item(item, idx)
            if parsed is not None:
                out.append(parsed)
        return out

    def _parse_item(self, item: dict[str, Any], idx: int) -> Optional[NormalizedFinding]:
        name = self._pick(
            item,
            "name",
            "title",
            "issue_name",
            "vulnerability",
            "rule_name",
            "msg",
            "message",
        )
        if not name:
            return None
        vuln_id = self._pick(
            item,
            "vuln_id",
            "id",
            "rule_id",
            "ruleId",
            "plugin_id",
            "finding_id",
        ) or f"generic-{idx}-{name}"[:120]

        severity = map_severity(
            self._pick(item, "severity", "risk", "level", "priority"),
            default=map_severity("medium"),
        )
        host = self._pick(
            item,
            "target_hint",
            "host",
            "hostname",
            "ip",
            "url",
            "target",
            "asset",
        )
        port_raw = item.get("port")
        port = None
        try:
            if port_raw is not None and str(port_raw).strip() != "":
                port = int(port_raw)
        except (TypeError, ValueError):
            port = None

        cvss = item.get("cvss_score") or item.get("cvss") or item.get("cvssScore")
        try:
            cvss_f = float(cvss) if cvss is not None else None
        except (TypeError, ValueError):
            cvss_f = None

        return NormalizedFinding(
            vuln_id=str(vuln_id)[:128],
            name=str(name)[:512],
            description=self._pick(item, "description", "detail", "details", "summary"),
            severity=severity,
            cvss_score=cvss_f,
            cwe_id=self._pick(item, "cwe_id", "cwe", "CWE"),
            cve_id=self._pick(item, "cve_id", "cve", "CVE"),
            remediation_steps=self._pick(
                item, "remediation_steps", "remediation", "solution", "fix", "recommendation"
            ),
            affected_component=self._pick(
                item, "affected_component", "component", "package", "path", "location"
            ),
            port=port,
            protocol=self._pick(item, "protocol", "proto"),
            evidence=item.get("evidence") if isinstance(item.get("evidence"), dict) else {},
            source_tool=str(self._pick(item, "source_tool", "tool", "scanner") or "generic")[:64],
            raw_source=item,
            target_hint=host,
        )

    @staticmethod
    def _pick(item: dict[str, Any], *keys: str) -> Optional[str]:
        for k in keys:
            v = item.get(k)
            if v is None or v == "":
                continue
            return str(v)
        return None

    @staticmethod
    def _load(raw: RawInput) -> list[Any]:
        if isinstance(raw, list):
            return raw
        if isinstance(raw, dict):
            if isinstance(raw.get("findings"), list):
                return list(raw["findings"])
            if isinstance(raw.get("results"), list):
                return list(raw["results"])
            if isinstance(raw.get("issues"), list):
                return list(raw["issues"])
            return [raw]
        if isinstance(raw, bytes):
            text = raw.decode("utf-8", errors="replace")
        elif isinstance(raw, str):
            text = raw
        else:
            raise TypeError("GenericJsonParser expects JSON-compatible input")
        data = json.loads(text) if text.strip() else []
        if isinstance(data, dict):
            if isinstance(data.get("findings"), list):
                return list(data["findings"])
            if isinstance(data.get("results"), list):
                return list(data["results"])
            if isinstance(data.get("issues"), list):
                return list(data["issues"])
            return [data]
        return list(data)
