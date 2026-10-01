"""SARIF 2.1.0 → NormalizedFinding parser (P1 import ecosystem)."""

from __future__ import annotations

import json
from typing import Any, Optional
from urllib.parse import urlparse

from app.normalization.base import FindingParser, RawInput
from app.normalization.schema import NormalizedFinding
from app.normalization.severity_map import map_severity


class SarifParser(FindingParser):
    """Parse OASIS SARIF JSON (common CI/SAST/DAST export)."""

    name = "sarif"

    def parse(self, raw: RawInput) -> list[NormalizedFinding]:
        data = self._load(raw)
        runs = data.get("runs") if isinstance(data, dict) else None
        if not isinstance(runs, list):
            raise ValueError("SARIF document must contain runs[]")

        findings: list[NormalizedFinding] = []
        for run_idx, run in enumerate(runs):
            if not isinstance(run, dict):
                continue
            tool_name = self._tool_name(run) or "sarif"
            rules = self._index_rules(run)
            results = run.get("results") or []
            if not isinstance(results, list):
                continue
            for res_idx, result in enumerate(results):
                if not isinstance(result, dict):
                    continue
                parsed = self._parse_result(
                    result,
                    rules=rules,
                    tool_name=tool_name,
                    run_idx=run_idx,
                    res_idx=res_idx,
                )
                if parsed is not None:
                    findings.append(parsed)
        return findings

    def _parse_result(
        self,
        result: dict[str, Any],
        *,
        rules: dict[str, dict[str, Any]],
        tool_name: str,
        run_idx: int,
        res_idx: int,
    ) -> Optional[NormalizedFinding]:
        rule_id = str(result.get("ruleId") or result.get("ruleID") or "sarif-finding")
        rule = rules.get(rule_id, {})
        msg = result.get("message") or {}
        text = ""
        if isinstance(msg, dict):
            text = str(msg.get("text") or msg.get("markdown") or "")
        elif isinstance(msg, str):
            text = msg

        rule_name = ""
        if isinstance(rule.get("shortDescription"), dict):
            rule_name = str(rule["shortDescription"].get("text") or "")
        if not rule_name and isinstance(rule.get("fullDescription"), dict):
            rule_name = str(rule["fullDescription"].get("text") or "")
        if not rule_name:
            rule_name = str(rule.get("name") or rule_id)

        level = result.get("level") or rule.get("defaultConfiguration", {}).get("level")
        if isinstance(rule.get("defaultConfiguration"), dict) and not result.get("level"):
            level = rule["defaultConfiguration"].get("level")
        severity = map_severity(level, default=map_severity("warning"))

        props = result.get("properties") if isinstance(result.get("properties"), dict) else {}
        rule_props = rule.get("properties") if isinstance(rule.get("properties"), dict) else {}
        cwe_id = self._first_str(
            props.get("cwe"),
            props.get("cwe_id"),
            rule_props.get("cwe"),
            rule_props.get("cwe_id"),
            self._from_taxa(result),
        )
        cve_id = self._first_str(props.get("cve"), props.get("cve_id"), rule_props.get("cve"))

        uri, snippet = self._location(result)
        host = None
        port = None
        if uri:
            parsed_url = urlparse(uri if "://" in uri else f"https://{uri}")
            host = parsed_url.hostname or (uri if not uri.startswith("/") else None)
            port = parsed_url.port

        vuln_id = f"sarif:{tool_name}:{rule_id}:{res_idx}"
        return NormalizedFinding(
            vuln_id=vuln_id[:128],
            name=(rule_name or text or rule_id)[:512],
            description=text or rule_name or None,
            severity=severity,
            cwe_id=cwe_id,
            cve_id=cve_id,
            affected_component=(uri or None),
            evidence={"uri": uri, "snippet": snippet, "run": run_idx} if uri or snippet else {},
            source_tool=tool_name[:64],
            raw_source=result,
            target_hint=host,
            port=port,
            remediation_steps=self._first_str(
                props.get("remediation"),
                rule_props.get("remediation"),
                rule.get("helpUri"),
            ),
        )

    @staticmethod
    def _tool_name(run: dict[str, Any]) -> str:
        tool = run.get("tool") or {}
        driver = tool.get("driver") if isinstance(tool, dict) else {}
        if isinstance(driver, dict):
            return str(driver.get("name") or "sarif")
        return "sarif"

    @staticmethod
    def _index_rules(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
        tool = run.get("tool") or {}
        driver = tool.get("driver") if isinstance(tool, dict) else {}
        rules = driver.get("rules") if isinstance(driver, dict) else None
        out: dict[str, dict[str, Any]] = {}
        if not isinstance(rules, list):
            return out
        for rule in rules:
            if isinstance(rule, dict) and rule.get("id"):
                out[str(rule["id"])] = rule
        return out

    @staticmethod
    def _location(result: dict[str, Any]) -> tuple[Optional[str], Optional[str]]:
        locations = result.get("locations") or []
        if not isinstance(locations, list) or not locations:
            return None, None
        loc0 = locations[0]
        if not isinstance(loc0, dict):
            return None, None
        phys = loc0.get("physicalLocation") or {}
        if not isinstance(phys, dict):
            return None, None
        art = phys.get("artifactLocation") or {}
        uri = None
        if isinstance(art, dict):
            uri = art.get("uri") or art.get("uriBaseId")
        region = phys.get("region") or {}
        snippet = None
        if isinstance(region, dict):
            sn = region.get("snippet") or {}
            if isinstance(sn, dict):
                snippet = sn.get("text")
        return (str(uri) if uri else None), (str(snippet) if snippet else None)

    @staticmethod
    def _from_taxa(result: dict[str, Any]) -> Optional[str]:
        taxa = result.get("taxa") or []
        if not isinstance(taxa, list):
            return None
        for t in taxa:
            if isinstance(t, dict) and t.get("id"):
                return str(t["id"])
        return None

    @staticmethod
    def _first_str(*vals: object) -> Optional[str]:
        for v in vals:
            if v is None or v == "":
                continue
            if isinstance(v, list) and v:
                return str(v[0])
            return str(v)
        return None

    @staticmethod
    def _load(raw: RawInput) -> dict[str, Any]:
        if isinstance(raw, dict):
            return raw
        if isinstance(raw, bytes):
            text = raw.decode("utf-8", errors="replace")
        elif isinstance(raw, str):
            text = raw
        else:
            raise TypeError("SarifParser expects JSON object")
        data = json.loads(text) if text.strip() else {}
        if not isinstance(data, dict):
            raise ValueError("SARIF root must be a JSON object")
        return data
