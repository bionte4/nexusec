# VA tanpa Greenbone — Nmap, Nuclei & Import

Dokumen ini menjelaskan cara memakai NexuSec untuk VA **tanpa** appliance GVM/OpenVAS.  
NexuSec **sudah menyertakan** Nmap + Nuclei di `scanner-worker`, serta **Import** laporan dari tool eksternal.

> Alur lengkap OSINT → discovery → VA: [`va-pt-workflow.md`](va-pt-workflow.md)  
> Detail UI connector: [`scanner-connectors.md`](scanner-connectors.md) · Alur VA/PT: [`usage-va-pt.md`](usage-va-pt.md) · GVM nanti: [`greenbone-gvm.md`](greenbone-gvm.md)

---

## 1. Apa yang sudah ada vs belum

| Komponen | Ada di NexuSec? | Perlu Greenbone? |
|----------|-----------------|------------------|
| **Nmap** (discovery / fingerprint) | Ya — live di `scanner-worker` | Tidak |
| **Nuclei** (VA template-driven) | Ya — binary + templates di image | Tidak |
| **Import report** (XML/JSON) | Ya — UI Scans + API | Tidak |
| **OSINT** (DNS / crt.sh / RDAP) | Ya — engine `osint` | Tidak |
| **OpenVAS GMP** (live) | Klien saja | **Ya** — appliance terpisah |
| **ZAP daemon** | Belum live | — (pakai Import JSON ZAP) |

**Kesimpulan:** untuk produksi tanpa GVM, jalur resmi = **Nmap + Nuclei + Import**.

---

## 2. Konfigurasi `.env` (VPS tanpa GVM)

```bash
# Jangan pakai GMP sampai Greenbone terpasang
OPENVAS_MODE=import
OPENVAS_GMP_FALLBACK_MOCK=false
ZAP_MODE=import

# Kosongkan / jangan set:
# GVM_USERNAME=
# GVM_PASSWORD=
# GVM_SOCKET=
# GVM_HOST=
```

Terapkan:

```bash
cd /opt/nexusec   # atau path deploy Anda
nano .env         # pastikan nilai di atas
docker compose up -d --force-recreate api scanner-worker
docker compose exec scanner-worker which nmap nuclei
```

Cek health: `GET /api/v1/health/detailed` → `tools.nmap` / `tools.nuclei` tersedia.

---

## 3. Alur UI (disarankan)

```text
1. Assets → daftarkan IP/domain/URL (centang CDE bila PCI)
2. Scans → centang RoE (+ isi RoE ID bila ada)
3a. Preset Discovery · nmap **atau OSINT · dns/CT/RDAP** → Start
3b. Preset VA · nuclei       → Start
    atau Pipeline: discovery → VA (nuclei)
4. Opsional: Import scanner report (OpenVAS XML / ZAP JSON dari mesin lain)
5. Vulnerabilities → triage → Draft PDF → (admin lain) Approve client → Client PDF
```

### Nmap

- Kartu **Nmap** atau chip **Discovery · nmap**
- Default: `port_preset=common_va` + NSE aman (banner, http-title, ssl-cert, …)
- Output: XML → finding service/port

### Nuclei

- Kartu **Nuclei** atau **VA · nuclei**
- Pack default: `/opt/nuclei-templates/{http,ssl,network}`
- Target: URL atau host (dinormalisasi ke `https://…`)
- Auth opsional: header Bearer/Basic + RoE wajib

### Import

- Form **Import scanner report** di halaman Scans
- Engine: `nmap` | `nuclei` | `openvas` | `zap` | `nexusec`
- File/raw ≤ 2MB; ditandai `imported=true` (bukan mock)
- Cocok untuk hasil OpenVAS/ZAP yang dijalankan **di mesin lain**, tanpa GVM di VPS

---

## 4. Contoh API

```bash
export API=https://nexusec.my.id   # atau http://127.0.0.1:8000
export AUTH="Authorization: Bearer $TOKEN"
export ASSET_ID="<uuid-aset>"

# Discovery Nmap
curl -s -X POST "$API/api/v1/scans" -H "$AUTH" -H 'Content-Type: application/json' \
  -d "{
    \"name\": \"Discovery nmap\",
    \"scan_type\": \"discovery\",
    \"engine\": \"nmap\",
    \"asset_ids\": [\"$ASSET_ID\"],
    \"config\": {
      \"roe_acknowledged\": true,
      \"roe_id\": \"ROE-2026-001\",
      \"port_preset\": \"common_va\"
    },
    \"start\": true
  }"

# VA Nuclei
curl -s -X POST "$API/api/v1/scans" -H "$AUTH" -H 'Content-Type: application/json' \
  -d "{
    \"name\": \"VA nuclei\",
    \"scan_type\": \"va\",
    \"engine\": \"nuclei\",
    \"asset_ids\": [\"$ASSET_ID\"],
    \"config\": {
      \"roe_acknowledged\": true,
      \"severity\": [\"critical\", \"high\", \"medium\"],
      \"template_dirs\": [
        \"/opt/nuclei-templates/http\",
        \"/opt/nuclei-templates/ssl\",
        \"/opt/nuclei-templates/network\"
      ]
    },
    \"start\": true
  }"

# Import (contoh ZAP JSON / OpenVAS XML)
curl -s -X POST "$API/api/v1/scans/import-report" -H "$AUTH" \
  -F "engine=zap" \
  -F "name=Imported ZAP" \
  -F "asset_ids=$ASSET_ID" \
  -F "roe_acknowledged=true" \
  -F "file=@./report.json"
```

Evidence versi tool: `GET /api/v1/scans/{id}/evidence` → `tool_version`, `template_hash` (nuclei), `roe_id`.

---

## 5. Apa yang **tidak** perlu dilakukan

- Jangan set `OPENVAS_MODE=gmp` tanpa GVM (scan OpenVAS akan gagal minta `GVM_*`)
- Jangan mengandalkan OpenVAS/ZAP **mock** untuk Client PDF (diblok; lab saja + `lab_mode`)
- Jangan expose port GVM/`9390` ke internet kalau nanti memasang Greenbone

---

## 6. Kapan baru butuh Greenbone?

| Kebutuhan | Solusi |
|-----------|--------|
| VA cepat web/CVE template | **Nuclei** (sudah ada) |
| Port/service discovery | **Nmap** (sudah ada) |
| Laporan dari OpenVAS di laptop/lab lain | **Import XML** |
| Live OpenVAS terintegrasi enqueue | Pasang **GVM terpisah** (RAM besar), isi `GVM_*` — lihat [`greenbone-gvm.md`](greenbone-gvm.md) |

GVM di **satu VPS kecil** bersama NexuSec biasanya tidak layak (feed VT besar, banyak container). Prefer mesin terpisah atau Import.

---

## 7. Troubleshooting

| Gejala | Perbaikan |
|--------|-----------|
| `Binary not found: nmap/nuclei` | Rebuild `scanner-worker`; pastikan image `Dockerfile.scanner` |
| OpenVAS error `GVM_USERNAME`… | Set `OPENVAS_MODE=import`; jangan enqueue mode `gmp` |
| Scan stuck `queued` | `docker compose ps` → recreate `scanner-worker`; UI **Requeue** |
| Target private ditolak | `SCAN_BLOCK_PRIVATE_TARGETS` — `true` di prod; `false` hanya lab LAN |
| Client PDF ditolak (mock) | Jangan mock; pakai nmap/nuclei live atau Import nyata |
| Import gagal ukuran | Batas 2MB — potong report atau split |

---

## Referensi

- [`usage-va-pt.md`](usage-va-pt.md) — RoE, engagement, dual-control, PTES/ASVS  
- [`scanner-connectors.md`](scanner-connectors.md) — preset & config worker  
- [`deploy-vps.md`](deploy-vps.md) — update VPS & `.env`  
- [`greenbone-gvm.md`](greenbone-gvm.md) — opsional, setelah ada appliance  
- [`.env.example`](../.env.example) — template variabel scanner  
