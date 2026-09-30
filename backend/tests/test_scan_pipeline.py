"""Unit tests for VA pipeline helpers (no DB)."""

from __future__ import annotations

from app.core.enums import ScannerEngine
from app.services.scan_pipeline_service import default_va_config


def test_default_va_config_nuclei() -> None:
    cfg = default_va_config(ScannerEngine.NUCLEI)
    assert cfg["rate_limit"] == 25
    assert "dos" in cfg["exclude_tags"]


def test_default_va_config_openvas() -> None:
    assert default_va_config(ScannerEngine.OPENVAS)["openvas_mode"] == "mock"


def test_pipeline_va_engine_allowlist() -> None:
    allowed = {
        ScannerEngine.NUCLEI,
        ScannerEngine.NEXUSEC,
        ScannerEngine.OPENVAS,
    }
    assert ScannerEngine.NMAP not in allowed
    assert ScannerEngine.OTHER not in allowed
