# OSINT connector — passive recon (DNS · crt.sh · RDAP)

Engine **`osint`** menambah fase *Intelligence Gathering* (PTES) tanpa binary Amass/subfinder.

## Modul (allowlist)

| Modul | Sumber | Output tipikal |
|-------|--------|----------------|
| `dns` | Resolver sistem (`getaddrinfo`) | Record A / AAAA |
| `crtsh` | [crt.sh](https://crt.sh) JSON API | Subdomain dari Certificate Transparency |
| `rdap` | [rdap.org](https://rdap.org) | Status registrasi + nameserver (tanpa dump PII penuh) |

Config scan:

```json
{
  "roe_acknowledged": true,
  "roe_id": "ROE-2026-001",
  "osint_modules": ["dns", "crtsh", "rdap"],
  "max_subdomains": 50,
  "timeout_seconds": 60
}
```

## Prasyarat

- Aset bertipe **domain** (atau hostname/URL yang bisa di-FQDN-kan) — **bukan** IP saja  
- Centang **RoE** (recon publik tetap butuh otorisasi scope)  
- Worker butuh **egress HTTPS** ke `crt.sh` dan `rdap.org` (untuk modul tersebut)

## UI

Scans → kartu **OSINT** atau chip **OSINT · dns/CT/RDAP** → pilih modul → Start.

## API

```bash
curl -s -X POST "$API/api/v1/scans" -H "$AUTH" -H 'Content-Type: application/json' \
  -d "{
    \"name\": \"OSINT example.com\",
    \"scan_type\": \"discovery\",
    \"engine\": \"osint\",
    \"asset_ids\": [\"$ASSET_ID\"],
    \"config\": {
      \"roe_acknowledged\": true,
      \"osint_modules\": [\"dns\", \"crtsh\", \"rdap\"]
    },
    \"start\": true
  }"
```

Import JSON OSINT juga didukung: `POST /api/v1/scans/import-report` dengan `engine=osint`.

## Batasan

- Bukan active crawling / port scan (itu **Nmap**)  
- Bukan VA CVE (itu **Nuclei**)  
- Subdomain dari CT bisa stale; validasi manual sebelum scan agresif  
- Rate-limit publik crt.sh/RDAP dapat gagal sementara — job tetap selesai dengan finding parsial

## Deploy VPS

```bash
cd /opt/nexusec && git pull
docker compose up -d --build --force-recreate api scanner-worker frontend
# Migrasi enum osint otomatis via alembic (013_osint_engine)
```

Lihat juga: [`va-without-gvm.md`](va-without-gvm.md) · [`scanner-connectors.md`](scanner-connectors.md) · [`usage-va-pt.md`](usage-va-pt.md)
