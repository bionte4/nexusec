# Import ecosystem — parser contract & roadmap

NexuSec normalizes third-party scanner reports into one `NormalizedFinding` schema via a **parser registry**. Live workers (Nmap/Nuclei/…) and **import-only** engines share the same ingest path.

> Closest peer: OWASP DefectDojo (broad import hub). NexuSec prioritizes **live orchestration + selective mature imports**, not 100 parsers on day one.

## Supported import engines

| Engine (`ScannerEngine`) | Parser name | Format | Live worker? |
|--------------------------|-------------|--------|--------------|
| `nmap` | `nmap` | Nmap XML | Yes |
| `nuclei` | `nuclei` | JSON / JSONL | Yes |
| `nexusec` | `nexusec` | Strict unified JSON | Yes |
| `openvas` | `openvas` | GVM/OpenVAS XML | GMP / import |
| `zap` | `zap` | ZAP `site.alerts` JSON | Import / mock |
| `osint` | `osint` | OSINT JSON | Yes (passive) |
| `sarif` | `sarif` | OASIS SARIF 2.1 JSON | **Import only** |
| `generic` | `generic` | Lenient JSON findings | **Import only** |
| `trivy` | `trivy` | Trivy `-f json` | **Import only** |
| `burp` | `burp` | Burp `issues` XML | **Import only** |
| `nessus` | `nessus` | Nessus `.nessus` XML | **Import only** |

API: `POST /api/v1/scans/import-report` with `{ name, engine, asset_ids, raw }` (raw ≤ 2MB).  
UI: Scans → **Import scanner report**.

## Generic JSON shape (recommended for adapters)

```json
{
  "findings": [
    {
      "id": "rule-1",
      "title": "Missing HSTS",
      "severity": "medium",
      "description": "…",
      "host": "https://app.example.com",
      "port": 443,
      "cwe": "CWE-319",
      "cve": null,
      "cvss": 5.3,
      "remediation": "Enable Strict-Transport-Security",
      "component": "nginx"
    }
  ]
}
```

Aliases accepted: `name`/`title`, `vuln_id`/`id`/`rule_id`, `severity`/`risk`/`level`, `host`/`url`/`target`, `remediation`/`solution`/`fix`.

Use **`nexusec`** when payload already matches `NormalizedFinding` fields exactly; use **`generic`** for vendor-shaped JSON.

## SARIF

Prefer SARIF when the tool already exports it (CodeQL, Semgrep, many CI SAST/DAST). One SARIF door covers many products without a dedicated parser.

## Plugin contract (P3) — how to add a parser

1. **Implement** `FindingParser` in `backend/app/normalization/parsers/<tool>_<fmt>.py`:
   - `name: str` — registry key (lowercase, stable)
   - `parse(raw) -> list[NormalizedFinding]`
   - Map severity via `app.normalization.severity_map.map_severity`
   - Set `source_tool`, `vuln_id` (stable), `target_hint` when possible
2. **Register** in `build_default_registry()` (`registry.py`).
3. **Enum** — if exposed as import engine: add `ScannerEngine` value + Alembic `ALTER TYPE scanner_engine ADD VALUE`.
4. **Wire** `ENGINE_PARSER_NAMES` / `IMPORTABLE_ENGINES` in `engine_map.py`.
5. **Fixture** under `backend/tests/fixtures/import_ecosystem/` + test in `test_import_ecosystem_parsers.py`.
6. **Docs** — one row in this table + UI `<option>` on Scans import form.
7. **Do not** enable live Celery enqueue for import-only engines unless a secure wrapper exists.

Minimal parser skeleton:

```python
from app.normalization.base import FindingParser, RawInput
from app.normalization.schema import NormalizedFinding

class MyToolParser(FindingParser):
    name = "mytool"

    def parse(self, raw: RawInput) -> list[NormalizedFinding]:
        ...
```

## Roadmap (realistic)

| Phase | Scope | Status |
|-------|--------|--------|
| P0 | Core gold fixtures regression (nmap/nuclei/openvas) | Done (tests) |
| P1 | SARIF + generic JSON | Done |
| P2 | Trivy, Burp, Nessus | Done |
| P3 | Documented plugin contract + UI engines | Done (this doc) |
| Later | Semgrep/Checkov native, Acunetix, Nikto, … as needed | Backlog |

**Rule:** expand parsers when an engagement **actually delivers** that format — not to match DefectDojo’s catalogue size.

## Related

- [`scanner-connectors.md`](scanner-connectors.md) — live connectors  
- [`usage-va-pt.md`](usage-va-pt.md) — operator workflow  
- [`data-model.md`](data-model.md) — finding fields  
