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

Lihat juga panduan penuh kartu engine: [`scanner-connectors.md`](scanner-connectors.md)#6-openvas--va--greenbone-gvm-mock--xml.

| Variable | Default | Notes |
|----------|---------|-------|
| `OPENVAS_MODE` | `mock` | Synthetic GVM XML for labs/CI without Greenbone |
| — | — | Or pass `config.report_xml` on the scan to import a real report |

Live `gmp` mode requires `gvm-cli` + a configured appliance; otherwise the worker falls back to mock or fails closed with a clear error.

## Hardening checklist (ops)

1. Replace every `CHANGE_ME` secret; never commit `.env`.
2. Redis `requirepass` + strong Postgres password; do not expose DB/Redis ports publicly.
3. CORS limited to real UI origins (`CORS_ORIGINS`).
4. JWT `SECRET_KEY` ≥ 48 URL-safe bytes; short access-token TTL.
5. Scanner wrappers use argv lists (`shell=False`); never pass raw user strings into shells.
6. Disable unused AI/ticket/SIEM integrations in production until keys are rotated and scoped.
7. Prefer mock OpenVAS in shared demos; isolate live GVM credentials to private workers only.
