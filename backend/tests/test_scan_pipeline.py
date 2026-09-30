"""Unit tests for VA pipeline helpers (no DB)."""

from __future__ import annotations

from app.core.enums import ScannerEngine
from app.services.scan_pipeline_service import default_va_config


def test_default_va_config_nuclei() -> None:
    cfg = default_va_config(ScannerEngine.NUCLEI)
    assert cfg["rate_limit"] == 25
    assert "dos" in cfg["exclude_tags"]
    assert "/opt/nuclei-templates/ssl" in cfg["template_dirs"]
    assert "/opt/nuclei-templates/network" in cfg["template_dirs"]


def test_default_va_config_openvas() -> None:
    cfg = default_va_config(ScannerEngine.OPENVAS)
    assert cfg["openvas_mode"] == "mock"
    assert set(cfg["openvas_catalogs"]) == {"webserver", "dbserver", "appserver"}


def test_default_va_config_zap() -> None:
    cfg = default_va_config(ScannerEngine.ZAP)
    assert cfg["zap_mode"] == "mock"
    assert cfg["zap_policy"] == "baseline"


def test_pipeline_va_engine_allowlist() -> None:
    allowed = {
        ScannerEngine.NUCLEI,
        ScannerEngine.NEXUSEC,
        ScannerEngine.OPENVAS,
        ScannerEngine.ZAP,
    }
    assert ScannerEngine.NMAP not in allowed
    assert ScannerEngine.OTHER not in allowed
    assert ScannerEngine.ZAP in allowed
