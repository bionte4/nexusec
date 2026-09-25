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

## Usage guides

- **VA & Penetration Testing:** [`docs/usage-va-pt.md`](docs/usage-va-pt.md) — assets, scans (nmap/nuclei/nexusec/openvas), normalize, triage, compliance reports
- **Scanner connectors (UI cards):** [`docs/scanner-connectors.md`](docs/scanner-connectors.md) — Nmap, Nuclei, NexuSec, OpenVAS presets, worker config, troubleshooting
- Data model: [`docs/data-model.md`](docs/data-model.md)
- Integrations & hardening: [`docs/integrations-hardening.md`](docs/integrations-hardening.md)

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

## Multi-Tenancy (Prompt 12)

Strict org isolation: `Organization` tenant + `organization_id` on users, assets, scans, vulnerabilities, and audit logs.

- Role `super_admin` — cross-tenant; scope with header `X-Organization-Id`
- Roles `admin` / `pentester` / `soc_analyst` — locked to their organization
- First registered user becomes Super Admin and seeds the `default` org

```bash
POST /api/v1/organizations                      # Super Admin onboard client
GET  /api/v1/organizations
GET  /api/v1/organizations/me
GET  /api/v1/organizations/me/metrics
GET  /api/v1/organizations/{id}/metrics
POST /api/v1/organizations/{id}/workspace-token/rotate
```

## Custom Scanner (Prompt 8)

Asyncio engine in `scanners/python/nexusec_scanner` with rate limits, circuit breakers, and exclusions.

```bash
POST /api/v1/scanner/run          # lab/preview
POST /api/v1/scans  {"engine":"nexusec", "asset_ids":[...], "config":{"exclusions":["10.0.0.0/8"], "ports":[22,80,443]}}
```

Celery task: `scans.run_nexusec` → ingest via `nexusec` normalizer.

## Threat Intelligence (Prompt 11)

Periodic Celery Beat jobs sync the [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and enrich findings via NVD references (public exploit heuristics). Matching CVEs get `is_actively_exploited`, optional severity promotion, and an RBVM `threat_risk_score`.

```bash
GET  /api/v1/threat-intel/status
GET  /api/v1/threat-intel/actively-exploited
POST /api/v1/threat-intel/sync          # Admin — queue KEV sync + enrichment
```

Configure: `KEV_CATALOG_URL`, `NVD_API_KEY`, `THREAT_INTEL_*`. Compose service: `beat`.

## Observability (Prompt 13)

```bash
GET /health                      # liveness (also /api/v1/health)
GET /api/v1/health/ready         # Postgres + Redis readiness
GET /api/v1/health/detailed      # + Celery workers + Docker daemon (Admin)
GET /api/v1/health/workers       # worker nodes, tool binaries, hung scans (Admin)
GET /metrics                     # Prometheus (prometheus-fastapi-instrumentator)
```

Custom gauges: `nexusec_active_scans`, `nexusec_celery_workers`, `nexusec_hung_scans`, `nexusec_scanner_tool_available`.

## AI Remediation (Prompt 14)

```bash
POST /api/v1/vulnerabilities/{id}/generate-ai-patch
```

Providers: OpenAI-compatible via official ``openai`` SDK (`AI_API_KEY` + `AI_BASE_URL` — Groq, OpenRouter, OpenAI). Without keys, a secure template mock is used. Core helper: `generate_ai_remediation_patch(cwe_id, description)`. Output is saved to `vulnerability.remediation`.

## AI False-Positive Analysis (Prompt 15)

```bash
POST /api/v1/vulnerabilities/{id}/analyze-fp
```

Evaluates finding context (port, banner, evidence, asset) and returns structured JSON:

- `confidence_score` (0–1)
- `is_likely_false_positive` (bool)
- `reasoning` (SOC analyst note)

Persisted under `vulnerability.threat_intel_metadata.ai_fp_analysis`. Same LLM keys as Prompt 14; mock heuristics when keys are absent (`AI_FP_PROVIDER=auto|openai|anthropic|mock`).

## AI SOC ChatOps / RAG (Prompt 16)

```bash
POST /api/v1/soc/chat
Content-Type: application/json

{"query": "Which assets currently violate PCI-DSS requirements?"}
```

Lightweight RAG: keyword intent classification → PostgreSQL retrieval (assets, scans, vulnerabilities) → LLM (or mock) answer. Response includes `answer`, `intent`, `stats`, and `sources`.
