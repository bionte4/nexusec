# Data Model — Prompt 1

## ER overview

```
users 1──* scans
users 1──* audit_logs
users 1──* assets (created_by)

scans *──* assets          (scan_assets)
scans 1──* vulnerabilities
assets 1──* vulnerabilities
```

## RBAC roles

`admin` · `pentester` · `soc_analyst`

## Assets

| Type | Required identifier | PCI-DSS |
|------|---------------------|---------|
| `ip` | `ip_address` | `is_cde_scope` |
| `domain` | `domain` | `is_cde_scope` |
| `cloud_resource` | `cloud_resource_id` | `is_cde_scope` |

## Compliance on findings

`vulnerabilities.compliance_metadata` (JSONB), e.g.:

```json
{
  "iso_27001": ["A.8.8"],
  "pci_dss": ["11.3.1"],
  "gdpr": ["Art.32"],
  "notes": "PII exposure risk"
}
```

Plus normalized columns: `title`, `severity`, `cvss_score`, `cvss_vector`, `cwe_id`, `status`.

## Engagement dual-control (P3) + SoD (P2)

`engagement_approvals` — admin/lead sign-off before `delivery=client` engagement PDF.

| Column | Notes |
|--------|--------|
| `organization_id` | Tenant scope |
| `scan_id` / `asset_id` / `engagement_type` | Optional scope fingerprint (null = org-wide) |
| `approved_by_id` / `approved_at` | Dual-control actor |
| `revoked_at` / `revoked_by_id` | Soft revoke |

**SoD:** when `scan_id` is set, `approved_by_id` must differ from `scans.created_by_id`.

Migration: `012_engagement_approvals`.

## Scan evidence (P0/P1)

Stored on `scans.config` (JSONB), not separate tables:

| Key | Notes |
|-----|--------|
| `roe_acknowledged` | Required to enqueue (lab_mode skip only outside production) |
| `roe_id` | Optional RoE document / ticket reference |
| `lab_mode` | Allows mock OpenVAS/ZAP in production demos; Client PDF still blocked for mock |
| `last_result.tool_version` | Nmap / Nuclei CLI version string |
| `last_result.template_hash` | Nuclei template-pack fingerprint |
| `ptes_checklist` / `asvs_checklist` | Optional overrides merged into engagement report |

Exposed via `GET /api/v1/scans/{id}/evidence`.

## Engagement standards (P1/P2)

Engagement JSON/PDF includes:

- Playbook (Discovery → VA → human confirm → remedi → retest → dual-control)
- **PTES** process checklist (exploitation remains human-led)
- **OWASP ASVS L1** chapter coverage signals
- Offline DAST suite: `zap_policy=owasp_top10` (lab; no zaproxy)

## Migrations

```bash
alembic -c database/alembic.ini upgrade head
```
