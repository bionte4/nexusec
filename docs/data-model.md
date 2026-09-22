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

## Migrations

```bash
alembic -c database/alembic.ini upgrade head
```
