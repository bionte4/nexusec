# Custom Scanner Engine (Python asyncio)

Lightweight TCP connect / banner scanner with:

- global + per-host rate limiting
- per-host circuit breaker
- exclusion lists (host, CIDR, `*.domain` suffix)

Output findings conform to `NormalizedFinding` (`source_tool=nexusec`).

```bash
# From repo root
PYTHONPATH=scanners/python python -c "
from nexusec_scanner import run_scan_sync, ScanConfig, ExclusionList
report = run_scan_sync(['127.0.0.1'], ScanConfig(ports=[22,80], exclusions=ExclusionList.from_entries([])))
print(report.stats, len(report.findings))
"
```

Enqueue via API: `POST /api/v1/scans` with `"engine": "nexusec"`.
Lab preview: `POST /api/v1/scanner/run`.
