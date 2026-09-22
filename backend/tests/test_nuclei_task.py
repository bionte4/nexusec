"""Unit tests for Nuclei wrapper argv building and Celery task."""

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
from workers.tool_wrappers.base import ExecutionResult, ToolExecutionError  # noqa: E402
from workers.tool_wrappers.nuclei import (  # noqa: E402
    NucleiScanRequest,
    NucleiWrapper,
    validate_nuclei_target,
)


def test_validate_nuclei_target_adds_https() -> None:
    assert validate_nuclei_target("example.com") == "https://example.com"
    assert validate_nuclei_target("https://example.com/path") == "https://example.com/path"


def test_validate_nuclei_target_rejects_shell_meta() -> None:
    with pytest.raises(Exception):
        validate_nuclei_target("example.com;id")


def test_nuclei_wrapper_build_argv_allowlists() -> None:
    argv = NucleiWrapper().build_argv(
        NucleiScanRequest(
            targets=["https://example.com"],
            severities=["high", "critical"],
            tags=["cve"],
            exclude_tags=["dos"],
            rate_limit=25,
        )
    )
    assert argv[0] == "nuclei"
    assert "-jsonl" in argv
    assert "-duc" in argv
    assert argv[argv.index("-severity") + 1] == "high,critical"
    assert argv[argv.index("-tags") + 1] == "cve"
    assert argv[argv.index("-u") + 1] == "https://example.com"


def test_nuclei_wrapper_rejects_bad_severity() -> None:
    with pytest.raises(ToolExecutionError):
        NucleiWrapper().build_argv(
            NucleiScanRequest(targets=["example.com"], severities=["ultra"])
        )


@pytest.fixture
def nuclei_scan_and_asset():
    asset = MagicMock()
    asset.asset_type = AssetType.DOMAIN
    asset.ip_address = None
    asset.domain = "example.com"
    asset.hostname = None
    asset.url = "https://example.com"

    scan = MagicMock()
    scan.id = uuid.uuid4()
    scan.assets = [asset]
    scan.config = {
        "severity": ["critical", "high"],
        "tags": ["cve"],
        "timeout_seconds": 60,
    }
    scan.started_at = None
    scan.engine = ScannerEngine.NUCLEI
    return scan


def test_run_nuclei_scan_marks_completed(nuclei_scan_and_asset) -> None:
    scan = nuclei_scan_and_asset
    session = MagicMock()
    query = session.query.return_value
    query.options.return_value.filter.return_value.one_or_none.return_value = scan

    fake_result = ExecutionResult(
        command=("nuclei", "-jsonl", "-u", "https://example.com"),
        returncode=0,
        stdout=(
            '{"template-id":"tech-detect","info":{"name":"Tech","severity":"info"},'
            '"host":"https://example.com","matched-at":"https://example.com"}\n'
        ),
        stderr="",
    )

    with patch("workers.tasks.session_scope") as scope:
        scope.return_value.__enter__.return_value = session
        scope.return_value.__exit__.return_value = None
        with patch("workers.tasks.NucleiWrapper") as wrapper_cls:
            wrapper_cls.return_value.run.return_value = fake_result
            with patch("workers.tasks._normalize_and_ingest") as ingest:
                from app.normalization.ingest import IngestStats

                ingest.return_value = IngestStats(inserted=1, updated=0, skipped=0)
                from workers.tasks import run_nuclei_scan

                result = run_nuclei_scan.run(str(scan.id))

    assert result["status"] == "completed"
    assert result["ingest"]["inserted"] == 1
    assert scan.status == ScanStatus.COMPLETED
    assert scan.progress == 100.0
