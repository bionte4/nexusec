"""Policy gates for RoE acknowledgment and mock/synthetic findings."""

from __future__ import annotations

import json
from typing import Any, Optional

from app.core.config import Settings, get_settings
from app.core.enums import ScannerEngine
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability


class EngagementExportBlocked(Exception):
    """Raised when engagement export would ship mock/lab findings."""

    def __init__(self, message: str, *, synthetic_count: int = 0, mock_scans: int = 0) -> None:
        super().__init__(message)
        self.synthetic_count = synthetic_count
        self.mock_scans = mock_scans


def is_production_env(settings: Optional[Settings] = None) -> bool:
    settings = settings or get_settings()
    return (settings.app_env or "").lower() in {"production", "prod"}


def assert_roe_for_scan(
    config: dict[str, Any] | None,
    *,
    settings: Optional[Settings] = None,
) -> None:
    """Require RoE acknowledgment before enqueueing live/lab scanners.

    ``lab_mode=true`` may skip RoE only outside production.
    """
    cfg = config if isinstance(config, dict) else {}
    if cfg.get("roe_acknowledged") is True:
        return
    settings = settings or get_settings()
    if cfg.get("lab_mode") is True and not is_production_env(settings):
        return
    raise ValueError(
        "Rules of Engagement acknowledgment required: set config.roe_acknowledged=true "
        "(or config.lab_mode=true only in non-production for offline demos)"
    )


def is_mock_scan_config(engine: ScannerEngine | str, config: dict[str, Any] | None) -> bool:
    cfg = config if isinstance(config, dict) else {}
    eng = engine.value if isinstance(engine, ScannerEngine) else str(engine).lower()
    # Real imported reports are never treated as mock connector jobs.
    if cfg.get("imported") is True:
        return False
    if eng == "zap":
        mode = str(cfg.get("zap_mode") or cfg.get("mode") or "mock").lower()
        if isinstance(cfg.get("report_json"), str) and cfg["report_json"].strip():
            return False
        return mode in {"mock", "", "default"}
    if eng == "openvas":
        if isinstance(cfg.get("report_xml"), str) and cfg["report_xml"].strip():
            return False
        mode = str(cfg.get("openvas_mode") or cfg.get("mode") or "mock").lower()
        return mode in {"mock", "", "default"}
    return False


def is_synthetic_finding(vuln: Vulnerability) -> bool:
    evidence = vuln.evidence if isinstance(vuln.evidence, dict) else {}
    raw = vuln.raw_source if isinstance(vuln.raw_source, dict) else {}
    meta = vuln.threat_intel_metadata if isinstance(vuln.threat_intel_metadata, dict) else {}
    if evidence.get("nexusec_mock") is True or raw.get("nexusec_mock") is True:
        return True
    blob = " ".join(
        [
            str(vuln.title or ""),
            str(vuln.description or ""),
            json.dumps(evidence, default=str),
            json.dumps(raw, default=str),
            json.dumps(meta, default=str),
        ]
    ).lower()
    markers = (
        "nexusec_mock",
        "zap mock",
        "synthetic dast",
        "mock connector",
        "openvas mock",
        "gvm-like",
    )
    return any(m in blob for m in markers)


def assert_engagement_export_allowed(
    scans: list[Scan],
    vulns: list[Vulnerability],
    *,
    allow_mock: bool = False,
) -> dict[str, Any]:
    """Block client engagement exports that include mock/synthetic evidence.

    Returns a warning payload when ``allow_mock`` is true.
    """
    mock_scans = [
        s
        for s in scans
        if is_mock_scan_config(s.engine, s.config if isinstance(s.config, dict) else {})
    ]
    synthetic = [v for v in vulns if is_synthetic_finding(v)]
    info: dict[str, Any] = {
        "allow_mock": allow_mock,
        "mock_scan_count": len(mock_scans),
        "synthetic_finding_count": len(synthetic),
        "mock_scan_ids": [str(s.id) for s in mock_scans[:20]],
        "warning": None,
    }
    if not synthetic and not mock_scans:
        return info
    msg = (
        f"Engagement export blocked: {len(synthetic)} synthetic finding(s) and "
        f"{len(mock_scans)} mock scanner job(s). Use real nmap/nuclei results or "
        f"imported reports. Pass allow_mock=true only for lab demos."
    )
    if allow_mock:
        info["warning"] = msg.replace("blocked", "includes mock data")
        return info
    raise EngagementExportBlocked(
        msg,
        synthetic_count=len(synthetic),
        mock_scans=len(mock_scans),
    )
