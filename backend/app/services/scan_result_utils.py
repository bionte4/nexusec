"""Helpers to pull raw scanner output from scan.config.last_result."""

from __future__ import annotations

from typing import Any, Optional

from app.core.enums import ScannerEngine
from app.models.scan import Scan
from app.normalization import NormalizedFinding, build_default_registry, compute_fingerprint


def last_result(scan: Scan) -> dict[str, Any]:
    cfg = scan.config or {}
    raw = cfg.get("last_result")
    return raw if isinstance(raw, dict) else {}


def extract_raw_output(result: dict[str, Any], engine: ScannerEngine | str) -> Optional[str]:
    eng = engine.value if isinstance(engine, ScannerEngine) else str(engine)
    for key in ("stdout_xml", "stdout_jsonl", "stdout", "raw"):
        val = result.get(key)
        if isinstance(val, str) and val.strip():
            return val
    if eng == ScannerEngine.NEXUSEC.value and isinstance(result.get("findings"), list):
        import json

        return json.dumps(result.get("findings"))
    return None


def findings_from_scan(scan: Scan) -> list[NormalizedFinding]:
    result = last_result(scan)
    raw = extract_raw_output(result, scan.engine)
    if not raw:
        return []
    registry = build_default_registry()
    parser_name = {
        ScannerEngine.NMAP: "nmap",
        ScannerEngine.NUCLEI: "nuclei",
        ScannerEngine.NEXUSEC: "nexusec",
        ScannerEngine.OPENVAS: "openvas",
    }.get(scan.engine, scan.engine.value)
    try:
        parser = registry.get(parser_name)
    except KeyError:
        return []
    try:
        return parser.parse(raw)
    except Exception:
        return []


def fingerprint_map(scan: Scan) -> dict[str, NormalizedFinding]:
    """Map fingerprint → finding using target_hint as asset_key."""
    out: dict[str, NormalizedFinding] = {}
    for finding in findings_from_scan(scan):
        key = compute_fingerprint(finding, asset_key=finding.target_hint or "")
        out[key] = finding
    return out
