"""Tests for the custom asyncio NexuSec scanner engine."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCANNER = ROOT / "scanners" / "python"
if str(SCANNER) not in sys.path:
    sys.path.insert(0, str(SCANNER))

from nexusec_scanner.circuit_breaker import CircuitBreaker, CircuitState  # noqa: E402
from nexusec_scanner.engine import NexusecScannerEngine, ScanConfig  # noqa: E402
from nexusec_scanner.exclusions import ExclusionList  # noqa: E402
from nexusec_scanner.findings import probe_to_finding  # noqa: E402
from nexusec_scanner.probes import ProbeResult  # noqa: E402
from nexusec_scanner.rate_limit import RateLimiter  # noqa: E402
from app.normalization.schema import NormalizedFinding  # noqa: E402


def test_exclusion_list_host_cidr_suffix() -> None:
    excl = ExclusionList.from_entries(
        ["10.0.0.5", "10.0.1.0/24", "*.internal.corp", ".lab.local"]
    )
    assert excl.is_excluded("10.0.0.5")
    assert excl.is_excluded("10.0.1.20")
    assert excl.is_excluded("db.internal.corp")
    assert excl.is_excluded("x.lab.local")
    assert not excl.is_excluded("8.8.8.8")


def test_circuit_breaker_trips_and_recovers() -> None:
    cb = CircuitBreaker(failure_threshold=3, recovery_timeout=0.05)
    assert cb.allow("h1")
    cb.record_failure("h1")
    cb.record_failure("h1")
    cb.record_failure("h1")
    assert cb.state("h1") == CircuitState.OPEN
    assert not cb.allow("h1")
    # force recovery window
    cb._opened_at["h1"] = cb._opened_at["h1"] - 1.0
    assert cb.state("h1") == CircuitState.HALF_OPEN
    assert cb.allow("h1")
    cb.record_success("h1")
    assert cb.state("h1") == CircuitState.CLOSED


@pytest.mark.asyncio
async def test_rate_limiter_allows_burst_then_waits() -> None:
    limiter = RateLimiter(rate_per_second=100.0, burst=2, per_host_min_interval=0.0)
    await limiter.acquire("a")
    await limiter.acquire("a")
    # third acquire should still complete quickly with high rate
    await asyncio.wait_for(limiter.acquire("a"), timeout=1.0)


def test_probe_to_finding_matches_normalized_schema() -> None:
    result = ProbeResult(
        host="10.0.0.8",
        port=23,
        open=True,
        banner="Ubuntu telnetd",
        latency_ms=12.3,
    )
    finding = probe_to_finding(result)
    assert finding is not None
    normalized = NormalizedFinding.model_validate(finding)
    assert normalized.source_tool == "nexusec"
    assert normalized.port == 23
    assert normalized.severity.value == "high"
    assert normalized.target_hint == "10.0.0.8"
    assert "A.8.8" in normalized.iso_27001_clause


@pytest.mark.asyncio
async def test_engine_respects_exclusions_and_maps_open_ports() -> None:
    config = ScanConfig(
        ports=[22, 80],
        exclusions=ExclusionList.from_entries(["10.0.0.9"]),
        rate_per_second=1000,
        burst=50,
        per_host_min_interval=0.0,
        max_concurrent_probes=10,
        circuit_failure_threshold=50,
    )
    engine = NexusecScannerEngine(config)

    async def fake_probe(host, port, **kwargs):
        return ProbeResult(host=host, port=port, open=(port == 22), banner="SSH-2.0")

    with patch("nexusec_scanner.engine.tcp_probe", side_effect=fake_probe):
        report = await engine.scan(["10.0.0.8", "10.0.0.9"])

    assert report.targets_excluded == ["10.0.0.9"]
    assert report.targets_scanned == ["10.0.0.8"]
    assert report.stats["ports_open"] == 1
    assert len(report.findings) == 1
    NormalizedFinding.model_validate(report.findings[0])


@pytest.mark.asyncio
async def test_engine_skips_when_circuit_open() -> None:
    config = ScanConfig(
        ports=[22, 80, 443],
        rate_per_second=1000,
        burst=50,
        per_host_min_interval=0.0,
        circuit_failure_threshold=1,
    )
    engine = NexusecScannerEngine(config)

    async def always_fail(host, port, **kwargs):
        return ProbeResult(host=host, port=port, open=False, error="TimeoutError")

    with patch("nexusec_scanner.engine.tcp_probe", side_effect=always_fail):
        report = await engine.scan(["10.0.0.8"])

    # After first failure circuit opens; later ports may be skipped
    assert report.stats["probes_executed"] < report.stats["probes_planned"]
    assert "10.0.0.8" in report.targets_circuit_open
