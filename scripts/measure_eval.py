#!/usr/bin/env python3
"""Measure Scenario A interactive API latency for paper tables.

Usage (stack running, credentials valid):
  python scripts/measure_eval.py
"""

from __future__ import annotations

import json
import statistics
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

API = "http://localhost:8000"
EMAIL = "admin@example.com"
PASSWORD = "ChangeMeNow123!"
SAMPLES = 30
CONCURRENCY = 8


def _request(method: str, path: str, token: str | None = None, body: dict | None = None):
    data = None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        data = json.dumps(body).encode()
    req = urllib.request.Request(f"{API}{path}", data=data, headers=headers, method=method)
    started = time.perf_counter()
    with urllib.request.urlopen(req, timeout=30) as resp:
        payload = resp.read()
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return resp.status, payload, elapsed_ms


def login() -> str:
    _, raw, _ = _request(
        "POST",
        "/api/v1/auth/login",
        body={"email": EMAIL, "password": PASSWORD},
    )
    return json.loads(raw)["access_token"]


def measure_endpoint(token: str, path: str) -> dict:
    times: list[float] = []
    errors = 0

    def one() -> float:
        try:
            _, _, ms = _request("GET", path, token=token)
            return ms
        except urllib.error.HTTPError:
            return -1.0

    # serial samples
    for _ in range(SAMPLES):
        ms = one()
        if ms < 0:
            errors += 1
        else:
            times.append(ms)

    # concurrent burst
    conc_times: list[float] = []
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        futs = [pool.submit(one) for _ in range(SAMPLES)]
        for fut in as_completed(futs):
            ms = fut.result()
            if ms < 0:
                errors += 1
            else:
                conc_times.append(ms)

    def stats(vals: list[float]) -> dict:
        if not vals:
            return {"n": 0}
        vals_sorted = sorted(vals)
        p95_idx = max(0, int(round(0.95 * (len(vals_sorted) - 1))))
        return {
            "n": len(vals),
            "median_ms": round(statistics.median(vals), 1),
            "p95_ms": round(vals_sorted[p95_idx], 1),
            "mean_ms": round(statistics.mean(vals), 1),
        }

    wall0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        list(pool.map(lambda _: one(), range(SAMPLES)))
    wall = time.perf_counter() - wall0
    throughput = (SAMPLES / wall) if wall > 0 else 0.0

    return {
        "path": path,
        "serial": stats(times),
        "concurrent": stats(conc_times),
        "approx_throughput_req_s": round(throughput, 1),
        "errors": errors,
    }


def main() -> None:
    token = login()
    results = {
        "host_note": "Measured against local Docker Compose stack",
        "samples": SAMPLES,
        "concurrency": CONCURRENCY,
        "endpoints": [
            measure_endpoint(token, "/api/v1/dashboard/overview"),
            measure_endpoint(token, "/api/v1/vulnerabilities?page_size=20"),
            measure_endpoint(token, "/api/v1/health"),
        ],
    }
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
