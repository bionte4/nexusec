"""Async lightweight port/asset scanner with safety controls."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional, Sequence

from nexusec_scanner.circuit_breaker import CircuitBreaker
from nexusec_scanner.exclusions import ExclusionList
from nexusec_scanner.findings import probe_to_finding
from nexusec_scanner.probes import ProbeResult, tcp_probe
from nexusec_scanner.rate_limit import RateLimiter

DEFAULT_PORTS: tuple[int, ...] = (
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    139,
    443,
    445,
    3306,
    3389,
    5432,
    5900,
    8080,
    8443,
)


@dataclass
class ScanConfig:
    ports: Sequence[int] = DEFAULT_PORTS
    connect_timeout: float = 1.5
    grab_banner: bool = True
    max_concurrent_probes: int = 50
    rate_per_second: float = 25.0
    burst: int = 15
    per_host_min_interval: float = 0.03
    circuit_failure_threshold: int = 5
    circuit_recovery_timeout: float = 30.0
    exclusions: ExclusionList = field(default_factory=ExclusionList)


@dataclass
class ScanReport:
    targets_requested: list[str]
    targets_scanned: list[str]
    targets_excluded: list[str]
    targets_circuit_open: list[str]
    probe_results: list[ProbeResult]
    findings: list[dict[str, Any]]
    stats: dict[str, Any]


class NexusecScannerEngine:
    """
    High-concurrency asyncio TCP scanner.

    Safety:
    - global + per-host rate limiting
    - per-host circuit breaker
    - exclusion list (host / CIDR / domain suffix)
    """

    def __init__(self, config: Optional[ScanConfig] = None) -> None:
        self.config = config or ScanConfig()
        self.limiter = RateLimiter(
            rate_per_second=self.config.rate_per_second,
            burst=self.config.burst,
            per_host_min_interval=self.config.per_host_min_interval,
        )
        self.breaker = CircuitBreaker(
            failure_threshold=self.config.circuit_failure_threshold,
            recovery_timeout=self.config.circuit_recovery_timeout,
        )
        self._semaphore = asyncio.Semaphore(self.config.max_concurrent_probes)

    async def scan(self, targets: Iterable[str]) -> ScanReport:
        requested = [t.strip() for t in targets if t and str(t).strip()]
        excluded: list[str] = []
        scanned: list[str] = []
        circuit_open: list[str] = []

        work: list[tuple[str, int]] = []
        for target in requested:
            if self.config.exclusions.is_excluded(target):
                excluded.append(target)
                continue
            scanned.append(target)
            for port in self.config.ports:
                work.append((target, int(port)))

        results: list[ProbeResult] = []

        async def _one(host: str, port: int) -> Optional[ProbeResult]:
            if not self.breaker.allow(host):
                if host not in circuit_open:
                    circuit_open.append(host)
                return None
            await self.limiter.acquire(host)
            async with self._semaphore:
                # Re-check breaker after waiting in queue
                if not self.breaker.allow(host):
                    if host not in circuit_open:
                        circuit_open.append(host)
                    return None
                result = await tcp_probe(
                    host,
                    port,
                    timeout=self.config.connect_timeout,
                    grab_banner=self.config.grab_banner,
                )
                if result.open:
                    self.breaker.record_success(host)
                else:
                    # Treat timeouts/refused as failure signal for breaker
                    self.breaker.record_failure(host)
                return result

        gathered = await asyncio.gather(*[_one(h, p) for h, p in work])
        for item in gathered:
            if item is not None:
                results.append(item)

        findings = []
        for probe in results:
            finding = probe_to_finding(probe)
            if finding is not None:
                findings.append(finding)

        open_count = sum(1 for r in results if r.open)
        return ScanReport(
            targets_requested=requested,
            targets_scanned=scanned,
            targets_excluded=excluded,
            targets_circuit_open=circuit_open,
            probe_results=results,
            findings=findings,
            stats={
                "probes_planned": len(work),
                "probes_executed": len(results),
                "ports_open": open_count,
                "findings": len(findings),
                "excluded": len(excluded),
                "circuit_open_targets": len(circuit_open),
            },
        )


def run_scan_sync(targets: Sequence[str], config: Optional[ScanConfig] = None) -> ScanReport:
    """Sync wrapper for Celery workers."""
    engine = NexusecScannerEngine(config=config)
    return asyncio.run(engine.scan(targets))
