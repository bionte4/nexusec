# NexuSec

Enterprise VA / PT / SOC orchestration platform.

## Monorepo (Prompt 1)

```
NexuSec/
├── backend/      # FastAPI core API, SQLAlchemy models, schemas, services
├── workers/      # Celery tasks & secure CLI tool wrappers
├── scanners/     # Custom high-performance scanner engine (Go stub)
├── database/     # Alembic migrations & migration config
├── frontend/     # SOC dashboard (future)
└── infra/docker/ # Container images
```

## Models

| Entity | Highlights |
|--------|------------|
| **Users** | RBAC: `admin`, `pentester`, `soc_analyst` |
| **Assets** | Types: `ip`, `domain`, `cloud_resource` + `is_cde_scope` (PCI-DSS) |
| **Scans** | Metadata, engine, status, timestamps, target assets |
| **Vulnerabilities** | title, severity, CVSS v3.1, CWE, status + `compliance_metadata` JSON |

## Quick start

```bash
cp .env.example .env
# Replace all CHANGE_ME_* values (SECRET_KEY, POSTGRES_PASSWORD, REDIS_PASSWORD)

# Full stack (API, Celery worker, isolated scanner-worker, Postgres, Redis, frontend)
docker compose up -d --build
# API: http://localhost:8000/docs  ·  SOC UI: http://localhost:8080

# Or infra only + local API/worker:
docker compose up -d postgres redis
cd backend && python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cd .. && alembic -c database/alembic.ini upgrade head
cd backend && uvicorn app.main:app --reload

# Worker (repo root) — use queues=default,integrations,scans for local single worker
PYTHONPATH=backend:. celery -A workers.celery_app.celery_app worker --loglevel=info -Q default,integrations,scans
```

CI: `.github/workflows/ci.yml` runs Black, Flake8, pytest, pip-audit, Bandit, frontend build, and Docker image builds.

API docs: http://localhost:8000/docs

## Auth (Prompt 2)

```bash
# First registered user becomes Admin
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@nexusec.local","full_name":"Admin","password":"ChangeMeNow123!"}'

curl -X POST http://localhost:8000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@nexusec.local","password":"ChangeMeNow123!"}'
```

RBAC: `admin` · `pentester` · `soc_analyst` — asset writes require Admin/Pentester. Mutating requests are written to `audit_logs`.

```bash
cd backend && pytest -q
```

## Normalization (Prompt 4)

Parsers: `nmap` (XML), `nuclei` (JSON/JSONL), `nexusec` (custom JSON) → unified `NormalizedFinding` → DB ingest with dedup on `(asset_id, fingerprint)`.

```bash
# Preview (no write)
POST /api/v1/normalize/preview  {"engine":"nmap","raw":"<nmaprun>...</nmaprun>"}

# Ingest for a scan
POST /api/v1/normalize/scans/{scan_id}
```

Nmap Celery jobs auto-normalize XML into `vulnerabilities` on completion.

## SOC Dashboard & Remediation (Prompt 5)

```bash
GET  /api/v1/dashboard/overview
GET  /api/v1/dashboard/severity
GET  /api/v1/dashboard/asset-risk
GET  /api/v1/dashboard/trends?days=30

GET    /api/v1/vulnerabilities
PATCH  /api/v1/vulnerabilities/{id}          # status: open|in_progress|false_positive|resolved
POST   /api/v1/vulnerabilities/{id}/assign
POST   /api/v1/vulnerabilities/{id}/comments
```

Statuses lifecycle: `open` → `in_progress` → `resolved` / `false_positive`. All endpoints require JWT; writes need SOC Analyst+.

## Compliance Reports (Prompt 6)

```bash
GET /api/v1/reports
GET /api/v1/reports/iso27001
GET /api/v1/reports/pci-dss
GET /api/v1/reports/gdpr
```

Each response is JSON / PDF-ready with metadata (`generated_at`, auditor name/email/role, asset & CDE scope), control mapping buckets, sections/tables, findings, and recommendations.

## Integrations (Prompt 7)

```bash
GET  /api/v1/integrations/status
POST /api/v1/integrations/preview
POST /api/v1/integrations/vulnerabilities/{id}/dispatch
```

- Webhooks: Slack / Teams / generic (Critical/High)
- Ticketing: Jira or ServiceNow on **critical** confirmed findings
- SIEM: CEF or JSON → HTTP collector (Elastic/Splunk HEC)

Configure via `.env` (`WEBHOOK_*`, `TICKET_*`, `SIEM_*`). Celery task: `integrations.dispatch_finding`.

## Custom Scanner (Prompt 8)

Asyncio engine in `scanners/python/nexusec_scanner` with rate limits, circuit breakers, and exclusions.

```bash
POST /api/v1/scanner/run          # lab/preview
POST /api/v1/scans  {"engine":"nexusec", "asset_ids":[...], "config":{"exclusions":["10.0.0.0/8"], "ports":[22,80,443]}}
```

Celery task: `scans.run_nexusec` → ingest via `nexusec` normalizer.
