"""Token-bucket style async rate limiter for scanner probes."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass


@dataclass
class RateLimiter:
    """
    Limits probe rate globally and optionally per-target.

    - ``rate_per_second``: sustained global probe rate
    - ``burst``: max immediate probes
    - ``per_host_min_interval``: minimum seconds between probes to the same host
    """

    rate_per_second: float = 20.0
    burst: int = 10
    per_host_min_interval: float = 0.05

    def __post_init__(self) -> None:
        self._tokens = float(self.burst)
        self._updated_at = time.monotonic()
        self._lock = asyncio.Lock()
        self._host_last: dict[str, float] = {}

    async def acquire(self, host: str | None = None) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self._updated_at
                self._updated_at = now
                self._tokens = min(
                    float(self.burst),
                    self._tokens + elapsed * self.rate_per_second,
                )

                wait_host = 0.0
                if host:
                    last = self._host_last.get(host)
                    if last is not None:
                        wait_host = max(0.0, self.per_host_min_interval - (now - last))

                if self._tokens >= 1.0 and wait_host <= 0.0:
                    self._tokens -= 1.0
                    if host:
                        self._host_last[host] = now
                    return

                wait_token = 0.0
                if self._tokens < 1.0:
                    wait_token = (1.0 - self._tokens) / max(self.rate_per_second, 0.001)
                await asyncio.sleep(max(wait_token, wait_host, 0.001))
