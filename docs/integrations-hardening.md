# Integrations & hardening notes

## Webhooks / tickets / SIEM (`.env`)

Copy from `.env.example`. Keep integrations **disabled** until URLs/tokens are set.

| Variable | Purpose |
|----------|---------|
| `WEBHOOK_ENABLED` | Master switch for finding alerts |
| `WEBHOOK_URLS` | Comma-separated Slack/Teams/generic HTTPS endpoints |
| `WEBHOOK_PROVIDER` | `generic` \| `slack` \| `teams` |
| `WEBHOOK_MIN_SEVERITY` | `high` or `critical` gate |
| `DIGEST_ENABLED` / `DIGEST_INTERVAL_HOURS` | Periodic overdue + Crit/High summary |
| `TICKET_ENABLED` / `TICKET_PROVIDER` | `jira` or `servicenow` |
| `JIRA_*` / `SERVICENOW_*` | Provider credentials (never commit real values) |
| `SIEM_ENABLED` / `SIEM_WEBHOOK_URL` | HTTP collector / HEC-compatible JSON |

Tenant overrides: Admin → Integrations → webhook settings (stored in `organization.settings`).

## OpenVAS connector

Lihat panduan penuh kartu engine: [`scanner-connectors.md`](scanner-connectors.md) dan live GMP: [`greenbone-gvm.md`](greenbone-gvm.md).

| Variable | Default | Notes |
|----------|---------|-------|
| `OPENVAS_MODE` | `gmp` | Live Greenbone; use `mock` only with `lab_mode` in production |
| — | — | Or pass `config.report_xml` on the scan to import a real report |
| `OPENVAS_GMP_FALLBACK_MOCK` | `false` | Ignored in production (refuse silent mock) |
| `ZAP_MODE` | `import` | Requires `report_json` / Import UI; `mock` needs `lab_mode` in production |

Live `gmp` mode requires `python-gvm` + a configured appliance; without credentials the worker fails closed (no silent mock in production).

## Hardening checklist (ops)

1. Replace every `CHANGE_ME` secret; never commit `.env`.
2. Redis `requirepass` + strong Postgres password; do not expose DB/Redis ports publicly.
3. CORS limited to real UI origins (`CORS_ORIGINS`).
4. JWT `SECRET_KEY` ≥ 48 URL-safe bytes; short access-token TTL.
5. Scanner wrappers use argv lists (`shell=False`); never pass raw user strings into shells.
6. **`.env` placement (top of file, before Application):**
   - `RATE_LIMIT_ENABLED=true` — login/register/scans/AI/reports → 429 when exceeded.
   - `SCAN_BLOCK_PRIVATE_TARGETS=true` — production: block RFC1918 / loopback / cloud metadata. Lab LAN only: `false`, then recreate `api` + `scanner-worker`.
7. AI API keys in `platform_settings` are sealed at rest (`enc:v1:…` via SECRET_KEY).
8. Disable unused AI/ticket/SIEM integrations in production until keys are rotated and scoped.
9. Prefer mock OpenVAS/ZAP only in shared demos; production VA uses nmap/nuclei + **import** real ZAP/OpenVAS reports.
10. Engagement **Client PDF** requires dual-control admin approval (`delivery=client`) with **SoD: approver ≠ scan creator**; drafts do not.
11. Record `roe_id` + Nuclei `template_hash` / `tool_version` on scan evidence; refresh Nuclei pins quarterly (`NUCLEI_VERSION` / `NUCLEI_TEMPLATES_REF`).
12. Engagement reports include **PTES** + **ASVS L1** checklists; exploitation remains human-led (no auto-exploit).
13. PCI-DSS reports default to **CDE-only** (`is_cde_scope` assets).
14. Production VPS: bind API/UI to `127.0.0.1`, terminate TLS at Nginx, open only 22/80/443 — see [`deploy-vps.md`](deploy-vps.md).
