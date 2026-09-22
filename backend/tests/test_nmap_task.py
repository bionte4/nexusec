"""Unit tests for Nmap Celery task status transitions (DB mocked)."""

from __future__ import annotations

import sys
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.enums import AssetType, ScanStatus, ScannerEngine  # noqa: E402
from workers.tool_wrappers.base import ExecutionResult  # noqa: E402


@pytest.fixture
def scan_and_asset():
    asset = MagicMock()
    asset.asset_type = AssetType.IP
    asset.ip_address = "10.0.0.8"
    asset.domain = None
    asset.hostname = None

    scan = MagicMock()
    scan.id = uuid.uuid4()
    scan.assets = [asset]
    scan.config = {"nmap_flags": ["-sV", "-Pn"], "timeout_seconds": 30}
    scan.started_at = None
    scan.engine = ScannerEngine.NMAP
    return scan


def test_run_nmap_scan_marks_completed(scan_and_asset) -> None:
    scan = scan_and_asset
    session = MagicMock()
    query = session.query.return_value
    query.options.return_value.filter.return_value.one_or_none.return_value = scan

    fake_result = ExecutionResult(
        command=("nmap", "-sV", "-Pn", "-oX", "-", "10.0.0.8"),
        returncode=0,
        stdout="<?xml version='1.0'?><nmaprun></nmaprun>",
        stderr="",
    )

    with patch("workers.tasks.session_scope") as scope:
        scope.return_value.__enter__.return_value = session
        scope.return_value.__exit__.return_value = None
        with patch("workers.tasks.NmapWrapper") as wrapper_cls:
            wrapper_cls.return_value.run.return_value = fake_result
            with patch("workers.tasks._normalize_and_ingest") as ingest:
                from app.normalization.ingest import IngestStats

                ingest.return_value = IngestStats(inserted=2, updated=0, skipped=0)
                from workers.tasks import run_nmap_scan

                result = run_nmap_scan.run(str(scan.id))

    assert result["status"] == "completed"
    assert result["ingest"]["inserted"] == 2
    assert scan.status == ScanStatus.COMPLETED
    assert scan.progress == 100.0
    assert "last_result" in scan.config


def test_run_nmap_scan_fails_without_targets() -> None:
    scan = MagicMock()
    scan.id = uuid.uuid4()
    scan.assets = []
    scan.config = {}
    scan.started_at = None

    session = MagicMock()
    query = session.query.return_value
    query.options.return_value.filter.return_value.one_or_none.return_value = scan

    with patch("workers.tasks.session_scope") as scope:
        scope.return_value.__enter__.return_value = session
        scope.return_value.__exit__.return_value = None
        from workers.tasks import run_nmap_scan

        result = run_nmap_scan.run(str(scan.id))

    assert result["status"] == "failed"
    assert scan.status == ScanStatus.FAILED
