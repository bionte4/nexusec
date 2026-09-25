# Panduan Penggunaan VA & Penetration Testing — NexuSec

Dokumen ini menjelaskan cara memakai NexuSec untuk **Vulnerability Assessment (VA)** dan **Penetration Testing (PT)**: dari inventori aset, menjalankan scan, normalisasi temuan, hingga triage & remediation di SOC.

> **Prasyarat:** stack sudah berjalan (`docker compose up -d`).  
> UI: http://localhost:8081 · API docs: http://localhost:8000/docs

---

## 1. Peran & wewenang

| Role | VA/PT (aset & scan) | SOC (finding) | Administration |
|------|---------------------|---------------|----------------|
| `super_admin` / `admin` | Ya | Ya | Ya |
| `pentester` | Ya (buat aset & scan) | Ya (triage) | Tidak |
| `soc_analyst` | Baca saja | Ya (status, assign, AI) | Tidak |

Login contoh (setelah bootstrap lokal):

- Email: `admin@example.com`
- Password: `ChangeMeNow123!`

---

## 2. Alur kerja ringkas

```text
1. Login (Admin / Pentester)
2. Daftarkan target → Assets (IP / Domain / Cloud)
3. Buat Scan job (engine: nmap | nuclei | nexusec | openvas)
4. Worker menjalankan tool di sandbox → status completed
5. Output dinormalisasi → Vulnerabilities (dedup fingerprint)
6. SOC triage: status, assign, FP analysis, AI remediation
7. Laporan compliance (ISO / PCI-DSS / GDPR) bila diperlukan
```

---

## 3. Persiapan sesi

### 3.1 Login & token API

UI: buka http://localhost:8081 → Sign in.

Atau lewat Terminal:

```bash
export API=http://localhost:8000

TOKEN=$(curl -s -X POST "$API/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"ChangeMeNow123!"}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')

export AUTH="Authorization: Bearer $TOKEN"
```

Semua perintah `curl` berikutnya memakai header `-H "$AUTH"`.

### 3.2 Cek kesehatan platform

```bash
curl -s -H "$AUTH" "$API/api/v1/health/detailed" | python3 -m json.tool
```

Pastikan **postgres** dan **redis** `ok`. Celery worker harus merespons (digunakan untuk menjalankan scan). Docker di container API boleh `degraded` — sandbox scanner ada di service `scanner-worker`.

---

## 4. Inventori aset (scope VA/PT)

Aset adalah target resmi penilaian. Tanpa aset, scan tidak bisa dibuat.

### 4.1 Buat aset IP (contoh lab)

```bash
curl -s -X POST "$API/api/v1/assets" \
  -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{
    "name": "Lab Web Server",
    "asset_type": "ip",
    "ip_address": "192.168.1.10",
    "criticality": "high",
    "is_cde_scope": false,
    "environment": "lab",
    "owner": "security-team",
    "description": "Authorized VA/PT lab host"
  }' | python3 -m json.tool
```

Simpan `id` aset (UUID) sebagai `ASSET_ID`.

### 4.2 Buat aset domain

```bash
curl -s -X POST "$API/api/v1/assets" \
  -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{
    "name": "Staging App",
    "asset_type": "domain",
    "domain": "staging.example.com",
    "url": "https://staging.example.com",
    "criticality": "medium",
    "is_cde_scope": false,
    "environment": "staging"
  }' | python3 -m json.tool
```

### 4.3 Tandai scope PCI-DSS (CDE)

Jika target menyentuh Cardholder Data Environment:

```json
"is_cde_scope": true
```

Finding pada aset CDE akan muncul di laporan PCI-DSS dan prioritas dashboard.

### 4.4 Daftar aset

```bash
curl -s -H "$AUTH" "$API/api/v1/assets?page=1&page_size=50" | python3 -m json.tool
```

---

## 5. Menjalankan Vulnerability Assessment (VA)

VA fokus **discovery + deteksi kerentanan** (bukan eksploit penuh).

### 5.1 Engine yang didukung

| Engine | Tipe scan tipikal | Keterangan |
|--------|-------------------|------------|
| `nmap` | `discovery` / `va` | Port/service fingerprint; output XML dinormalisasi otomatis |
| `nuclei` | `va` / `pt` | Template-driven vulnerability checks (JSONL → ingest) |
| `nexusec` | `va` / `custom` | Scanner internal (asyncio) |
| `openvas` | `va` | Greenbone/OpenVAS XML — default `OPENVAS_MODE=mock` (lab/CI); import via `config.report_xml` |
| `other` | — | Placeholder API/UI |

Jenis `scan_type`: `discovery` · `va` · `pt` · `compliance` · `custom`.

Penjelasan detail kartu UI **Scanner connectors**, preset, config worker, normalisasi, dan troubleshooting: **[`scanner-connectors.md`](scanner-connectors.md)**.

### 5.2 Buat & jalankan scan Nmap (VA discovery)

```bash
# ganti ASSET_ID
export ASSET_ID="<uuid-aset>"

curl -s -X POST "$API/api/v1/scans" \
  -H "$AUTH" -H 'Content-Type: application/json' \
  -d "{
    \"name\": \"VA Discovery — Lab Web\",
    \"scan_type\": \"discovery\",
    \"engine\": \"nmap\",
    \"asset_ids\": [\"$ASSET_ID\"],
    \"config\": {
      \"ports\": \"top-1000\",
      \"timing\": \"T3\"
    },
    \"start_immediately\": true
  }" | python3 -m json.tool
```

Respons berisi `scan.id`, `celery_task_id`, dan `message` (mis. *Scan queued*).

### 5.3 Monitor status scan

```bash
export SCAN_ID="<uuid-scan>"

curl -s -H "$AUTH" "$API/api/v1/scans/$SCAN_ID" | python3 -m json.tool
```

Status siklus: `pending` → `queued` → `running` → `completed` | `failed`.

Daftar semua scan:

```bash
curl -s -H "$AUTH" "$API/api/v1/scans?page=1&page_size=20" | python3 -m json.tool
```

### 5.4 Scan Nuclei (VA konten/web)

```bash
curl -s -X POST "$API/api/v1/scans" \
  -H "$AUTH" -H 'Content-Type: application/json' \
  -d "{
    \"name\": \"VA Nuclei — Staging\",
    \"scan_type\": \"va\",
    \"engine\": \"nuclei\",
    \"asset_ids\": [\"$ASSET_ID\"],
    \"config\": {
      \"severity\": [\"critical\", \"high\", \"medium\"],
      \"tags\": [\"cve\", \"misconfig\"]
    },
    \"start_immediately\": true
  }" | python3 -m json.tool
```

### 5.5 Enqueue ulang scan yang sudah dibuat

```bash
curl -s -X POST "$API/api/v1/scans/$SCAN_ID/start" -H "$AUTH" | python3 -m json.tool
```

---

## 6. Penetration Testing (PT) di NexuSec

NexuSec **mengorkestrasi** bukti VA/PT dan lifecycle temuan. Eksploit manual/alat khusus tetap dijalankan pentester di luar atau via worker yang diizinkan, lalu hasil digabung ke platform.

### 6.1 Recommended PT workflow

1. **Kickoff & RoE** — pastikan target punya RoE tertulis; hanya aset authorized yang didaftarkan.
2. **Discovery VA** — scan `nmap` / discovery untuk peta port & service.
3. **Vulnerability VA** — `nuclei` atau engine lain untuk kandidat finding.
4. **Validasi PT** — pentester konfirmasi exploitabilitas (manual/tool), lalu:
   - update status finding (`confirmed` / `in_progress`),
   - tulis evidence di remediation notes / comments,
   - mapping compliance tetap di `compliance_metadata`.
5. **Remediation & retest** — setelah patch, buat scan baru pada aset yang sama; fingerprint dedup menjaga histori.

### 6.2 Buat job bertipe PT

```bash
curl -s -X POST "$API/api/v1/scans" \
  -H "$AUTH" -H 'Content-Type: application/json' \
  -d "{
    \"name\": \"PT Wave-1 — Auth scope\",
    \"scan_type\": \"pt\",
    \"engine\": \"nuclei\",
    \"asset_ids\": [\"$ASSET_ID\"],
    \"config\": {
      \"notes\": \"Authenticated checks only; no DoS\",
      \"window\": \"2026-09-22T01:00:00Z/2026-09-22T05:00:00Z\"
    },
    \"start_immediately\": true
  }" | python3 -m json.tool
```

### 6.3 Import / preview output tool eksternal

Jika ada output mentah (Nmap XML / Nuclei JSON):

```bash
# Preview saja (tidak menulis DB)
curl -s -X POST "$API/api/v1/normalize/preview" \
  -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"engine":"nmap","raw":"<?xml version=\"1.0\"?><nmaprun>...</nmaprun>"}' \
  | python3 -m json.tool

# Ingest ke scan yang sudah ada
curl -s -X POST "$API/api/v1/normalize/scans/$SCAN_ID" \
  -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"engine":"nmap","raw":"<?xml version=\"1.0\"?><nmaprun>...</nmaprun>"}' \
  | python3 -m json.tool
```

Scan Nmap yang dijalankan lewat Celery biasanya **sudah auto-normalize** saat selesai.

---

## 7. Triage temuan (SOC / setelah VA-PT)

### 7.1 Lihat daftar vulnerability

**UI:** menu **Vulnerabilities** — filter severity, status, asset, compliance.

**API:**

```bash
curl -s -H "$AUTH" \
  "$API/api/v1/vulnerabilities?page=1&page_size=20&severity=critical" \
  | python3 -m json.tool
```

### 7.2 Update status lifecycle

| Status | Kapan dipakai |
|--------|----------------|
| `open` | Baru dari scanner |
| `in_progress` | Sedang dikerjakan / divalidasi PT |
| `confirmed` | Valid setelah pengujian |
| `false_positive` | Bukan isu nyata |
| `resolved` / `remediated` | Sudah diperbaiki & diverifikasi |
| `accepted_risk` | Risiko diterima manajemen |

```bash
export VULN_ID="<uuid-finding>"

curl -s -X PATCH "$API/api/v1/vulnerabilities/$VULN_ID" \
  -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{
    "status": "in_progress",
    "remediation": "Disable anonymous FTP; enforce TLS 1.2+"
  }' | python3 -m json.tool
```

### 7.3 Assign owner

```bash
curl -s -X POST "$API/api/v1/vulnerabilities/$VULN_ID/assign" \
  -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"remediation_owner_label":"AppSec — payments"}' \
  | python3 -m json.tool
```

### 7.4 Analisis false positive (AI)

```bash
curl -s -X POST "$API/api/v1/vulnerabilities/$VULN_ID/analyze-fp" \
  -H "$AUTH" | python3 -m json.tool
```

### 7.5 Draft remediasi / patch (AI)

```bash
curl -s -X POST "$API/api/v1/vulnerabilities/$VULN_ID/generate-ai-patch" \
  -H "$AUTH" | python3 -m json.tool
```

> Output AI **wajib direview manusia** sebelum diterapkan di produksi.

### 7.6 SOC ChatOps

UI: **SOC Chat** — tanya dalam bahasa natural, contoh:

- “Critical findings on CDE assets?”
- “List recent failed scans”
- “Which open High findings lack an owner?”

---

## 8. Laporan compliance

```bash
curl -s -H "$AUTH" "$API/api/v1/reports/iso27001" | python3 -m json.tool
curl -s -H "$AUTH" "$API/api/v1/reports/pci-dss" | python3 -m json.tool
curl -s -H "$AUTH" "$API/api/v1/reports/gdpr" | python3 -m json.tool
curl -s -H "$AUTH" "$API/api/v1/reports/nist-csf" | python3 -m json.tool

# PDF (binary)
curl -s -H "$AUTH" "$API/api/v1/reports/iso27001/pdf" -o iso27001.pdf
curl -s -H "$AUTH" "$API/api/v1/reports/nist-csf/pdf" -o nist.pdf
```

Gunakan setelah finding punya `compliance_metadata` (ISO Annex A, PCI Req.11, GDPR Art.32, NIST CSF/800-53, dll.).

Di UI: tombol **ISO / PCI / GDPR / NIST** (JSON) dan **… PDF**. Detail finding: **Suggest NIST** → tinjau → **Accept**.

Backfill finding lama (Admin):

```bash
curl -s -X POST -H "$AUTH" "$API/api/v1/reports/backfill-metadata?limit=1000"
```

Atau **Admin → Alerts → Backfill NIST + SLA**.

Ticketing (Jira/ServiceNow): set `TICKET_ENABLED=true`, kredensial provider, dan opsional `TICKET_MIN_SEVERITY=high`. Di detail finding: **Create / sync ticket**.

### Digest SOC (overdue + Critical/High)

Celery Beat mengirim ringkasan berkala ke webhook yang sama (`DIGEST_INTERVAL_HOURS`, default 24 jam).

```bash
# Preview
curl -s -H "$AUTH" "$API/api/v1/integrations/digest/preview" | python3 -m json.tool
# Kirim sekarang (async Celery)
curl -s -X POST -H "$AUTH" "$API/api/v1/integrations/digest/send"
```

UI: **Admin → Alerts → Preview digest / Send SOC digest now**.

---

## 8b. Prioritas RBVM (EPSS / SLA / retest)

- Enrichment threat intel menambahkan **EPSS** (FIRST.org) ke skor `threat_risk_score` bersama KEV/NVD.
- Finding baru mendapat `remediation_due_at` sesuai SLA severity (default: Critical 7h, High 14h, Medium 30h, … — lihat `.env` `SLA_DAYS_*`).
- Dashboard menampilkan **Overdue SLA**; filter: `GET /api/v1/vulnerabilities?overdue=true`.
- Status → `remediated` otomatis membuat scan verifikasi (auto-retest) bila `AUTO_RETEST_ENABLED=true`.

---

## 9. Checklist sesi VA

- [ ] RoE / izin tertulis & jendela waktu disepakati  
- [ ] Aset target terdaftar (benar IP/domain; CDE ditandai)  
- [ ] Role `pentester` atau `admin` dipakai untuk menjalankan scan  
- [ ] Worker `scanner-worker` healthy  
- [ ] Scan discovery selesai tanpa `failed`  
- [ ] Finding muncul di **Vulnerabilities**  
- [ ] Critical/High punya owner + status  
- [ ] Retest setelah remediation  

## 10. Checklist sesi PT

- [ ] Scope PT terpisah dari aset out-of-scope  
- [ ] Discovery VA selesai sebagai baseline  
- [ ] Job `scan_type=pt` tercatat di platform  
- [ ] Finding tervalidasi ditandai `confirmed` / `in_progress`  
- [ ] Evidence & langkah exploit **tidak** memasukkan kredensial rahasia ke log/comment  
- [ ] Closing meeting: laporan ISO/PCI/GDPR/NIST + daftar residual risk / overdue SLA

---

## 11. Troubleshooting singkat

| Gejala | Periksa |
|--------|---------|
| Scan stuck `queued` | `docker compose logs worker scanner-worker` — Redis/Celery |
| Scan `failed` | `GET /scans/{id}` → `error_message`; target reachable dari container? |
| Finding kosong setelah completed | Normalisasi gagal? Cek preview normalize; engine sesuai format? |
| 403 pada create asset/scan | Role harus Admin/Pentester |
| Port host bentrok | Postgres host `5433`, UI `8081` (lihat `docker-compose.yml`) |

```bash
docker compose ps
docker compose logs -f scanner-worker
```

---

## 12. Referensi terkait

- Data model: [`docs/data-model.md`](data-model.md)  
- API interaktif: http://localhost:8000/docs  
- Administrasi tenant/user: UI **Administration**  
- Arsitektur paper: [`docs/paper/02_methodology_architecture.md`](paper/02_methodology_architecture.md)

---

*NexuSec mendukung orkestrasi VA/PT yang aman (RBAC, audit trail, sandbox worker). Jangan scan target tanpa otorisasi tertulis.*
