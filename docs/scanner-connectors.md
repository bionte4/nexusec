# Scanner Connectors — NexuSec

Dokumen ini menjelaskan panel **Scanner connectors** di halaman **Scans** (UI: http://localhost:8081), serta perilaku tiap engine di backend/worker.

> Ringkasan operasional VA/PT: [`usage-va-pt.md`](usage-va-pt.md) · Hardening integrasi: [`integrations-hardening.md`](integrations-hardening.md)

---

## 1. Apa itu “Scanner connectors”?

Di halaman **Scans**, bagian atas form menampilkan kartu engine siap pakai:

| Kartu UI | Engine API (`engine`) | Status badge | Prefill tipikal |
|----------|----------------------|--------------|-----------------|
| **Nmap** | `nmap` | Ready | Discovery · port / service fingerprint |
| **Nuclei** | `nuclei` | Ready | VA · template-driven checks |
| **NexuSec** | `nexusec` | Ready | VA · custom async scanner |
| **OpenVAS** | `openvas` | Ready | VA · Greenbone GVM (mock / XML) |

**Cara kerja di UI**

1. Pilih kartu → form **New scan** diisi otomatis (`name`, `scan_type`, `engine`, `config`).
2. Pilih **asset** terdaftar, opsional centang *Start immediately*.
3. **Create scan** → API membuat job + enqueue Celery task ke antrian `scans`.
4. Service **`scanner-worker`** menjalankan tool di sandbox, menyimpan raw output, lalu **normalisasi + ingest** ke tabel vulnerabilities.

Kartu yang terpilih punya highlight (border aksen). Badge **Ready** berarti engine sudah diimplementasi end-to-end (wrapper → parser → enqueue). Engine `other` sengaja tidak ditampilkan sebagai kartu siap pakai.

Preset cepat di form (chip) setara dengan kartu:

- `Discovery · nmap`
- `VA · nuclei`
- `VA · nexusec`
- `VA · openvas`

Jadwal berulang (**Schedules**) memakai preset yang sama.

---

## 2. Alur teknis bersama

```text
UI / API  →  Scan row (status queued)
          →  Celery task (scans.run_<engine>)  [queue: scans]
          →  scanner-worker (Docker sandbox)
          →  Tool wrapper (argv list, shell=False)
          →  Raw stdout (XML / JSONL / JSON)
          →  Parser registry → NormalizedFinding
          →  Fingerprint + upsert vulnerabilities
          →  Scan status completed | failed
```

**Prinsip secure-by-design**

- Target divalidasi (IP/domain/URL); tidak ada interpolasi shell.
- Flag/opsi tool di-allowlist di wrapper.
- Output mentah disimpan di `scan.config.last_result` (dipotong bila terlalu besar).
- Finding masuk skema tunggal + tag compliance (ISO / PCI-DSS / GDPR / NIST) saat enrich.

**Health**

`GET /api/v1/health/detailed` melaporkan ketersediaan binary (`nmap`, `nuclei`) dan status connector OpenVAS (`mode` mock vs `gvm-cli`).

---

## 3. Nmap — Discovery · port / service fingerprint

### 3.1 Tujuan

Memetakan host hidup, port terbuka, layanan, dan (opsional) script hint kerentanan. Cocok sebagai langkah **discovery** sebelum VA mendalam.

### 3.2 UI / preset

- Kartu **Nmap** atau chip **Discovery · nmap**
- `scan_type`: `discovery`
- `engine`: `nmap`
- `config`: `{}` (flag default dipakai worker)

### 3.3 Worker

- Task: `scans.run_nmap`
- Wrapper: `workers/tool_wrappers/nmap.py`
- Output: Nmap XML (`-oX -`) → `stdout_xml`
- Parser: `nmap` (`NmapXmlParser`)

Flag default: `-sV -Pn -T3`. Hanya flag allowlist yang diterima lewat `config.nmap_flags`.

### 3.4 Hasil normalisasi

- Port **open** → finding (port/protocol/service).
- Port **closed** tidak diingest.
- Script output (mis. `smb-vuln-*`) bisa menaikkan severity.

### 3.5 Contoh API

```bash
curl -s -X POST "$API/api/v1/scans" \
  -H "$AUTH" -H 'Content-Type: application/json' \
  -H "X-Organization-Id: $ORG_ID" \
  -d "{
    \"name\": \"Discovery (nmap)\",
    \"scan_type\": \"discovery\",
    \"engine\": \"nmap\",
    \"asset_ids\": [\"$ASSET_ID\"],
    \"config\": { \"nmap_flags\": [\"-sV\", \"-Pn\", \"-T3\"], \"timeout_seconds\": 600 },
    \"start_immediately\": true
  }"
```

### 3.6 Catatan operasional

- Aset harus punya IP / domain / hostname yang valid.
- Setelah completed, UI **Evidence** / host-discovery (bila tersedia) memakai XML di `last_result`.
- Nmap relatif ringan dibanding Nuclei; tetap berjalan di `scanner-worker`.

---

## 4. Nuclei — VA · template-driven checks

### 4.1 Tujuan

Vulnerability Assessment berbasis template ProjectDiscovery: misconfig, CVE HTTP, panel terbuka, dll. Output JSONL dinormalisasi ke finding ber-severity / CVE / CWE bila ada di template.

### 4.2 UI / preset

- Kartu **Nuclei** atau chip **VA · nuclei**
- `scan_type`: `va`
- `engine`: `nuclei`
- Prefill `config` (disarankan untuk Docker):

```json
{
  "severity": ["critical", "high", "medium"],
  "tags": ["cve", "misconfig", "vuln"],
  "exclude_tags": ["dos"],
  "rate_limit": 25,
  "concurrency": 10,
  "bulk_size": 10
}
```

### 4.3 Worker

- Task: `scans.run_nuclei`
- Wrapper: `workers/tool_wrappers/nuclei.py`
- Template default: `/opt/nuclei-templates/http` (katalog penuh terlalu berat di sandbox)
- Output: JSONL → `stdout_jsonl`
- Parser: `nuclei` (`NucleiJsonParser`)

Argv penting (selalu di-set wrapper):

| Flag | Default | Fungsi |
|------|---------|--------|
| `-rate-limit` | 25 | Batas request/detik |
| `-c` | 10 | Concurrency template |
| `-bulk-size` | 10 | Host parallel |
| `-severity` | critical,high,medium | Filter severity |
| `-etags` | dos | Hindari template berbahaya |

### 4.4 Batas resource container

Nuclei (Go) banyak thread. `scanner-worker` dikonfigurasi dengan `pids_limit` / `ulimit nproc` yang cukup (lihat `docker-compose.yml`). Tanpa cap `-c` / `-bulk-size`, scan bisa gagal dengan:

`runtime: failed to create new OS thread … may need to increase max user processes`

Jika error itu muncul: pastikan stack sudah di-rebuild dengan limit terbaru, lalu **Start** ulang scan (jangan hanya mengandalkan nama job lama).

### 4.5 Target aset

Prefer `url` di aset; bila kosong, worker menurunkan `https://domain` / `http://ip`.

### 4.6 Contoh API

```bash
curl -s -X POST "$API/api/v1/scans" \
  -H "$AUTH" -H 'Content-Type: application/json' \
  -H "X-Organization-Id: $ORG_ID" \
  -d "{
    \"name\": \"VA (nuclei)\",
    \"scan_type\": \"va\",
    \"engine\": \"nuclei\",
    \"asset_ids\": [\"$ASSET_ID\"],
    \"config\": {
      \"severity\": [\"critical\", \"high\", \"medium\"],
      \"tags\": [\"cve\", \"misconfig\", \"vuln\"],
      \"exclude_tags\": [\"dos\"],
      \"rate_limit\": 25,
      \"concurrency\": 10,
      \"bulk_size\": 10
    },
    \"start_immediately\": true
  }"
```

---

## 5. NexuSec — VA · custom async scanner

### 5.1 Tujuan

Engine internal platform (Python asyncio di `scanners/python/nexusec_scanner`): port/service probe kustom tanpa bergantung binary pihak ketiga. Berguna untuk lab, regressi, dan skenario di luar Nmap/Nuclei.

### 5.2 UI / preset

- Kartu **NexuSec** atau chip **VA · nexusec**
- `scan_type`: `va`
- `engine`: `nexusec`
- `config`: `{}` (opsi engine-specific boleh ditambah kemudian)

### 5.3 Worker

- Task: `scans.run_nexusec`
- Output findings JSON kustom → parser `nexusec` (`CustomJsonParser`)
- Enrich compliance otomatis (ISO / PCI / GDPR / NIST defaults menurut tipe finding)

### 5.4 Kapan dipakai

- Verifikasi aset tanpa instalasi Nmap/Nuclei di host lain
- Baseline internal yang konsisten di CI
- Melengkapi discovery eksternal dengan logika custom (exclusion list, timeout, dll.)

---

## 6. OpenVAS — VA · Greenbone GVM (mock / XML)

### 6.1 Tujuan

Mengintegrasikan hasil **OpenVAS / Greenbone GVM** ke skema finding yang sama. Di lab/CI default memakai **mock connector** (XML sintetis deterministik) agar demo & tes jalan tanpa appliance Greenbone.

### 6.2 UI / preset

- Kartu **OpenVAS** atau chip **VA · openvas**
- `scan_type`: `va`
- `engine`: `openvas`
- Prefill:

```json
{ "openvas_mode": "mock" }
```

### 6.3 Mode operasi

| Mode | Env / config | Perilaku |
|------|--------------|----------|
| **mock** (default) | `OPENVAS_MODE=mock` atau `config.openvas_mode` | Generate XML GVM-like untuk tiap target tervalidasi |
| **import** | `config.report_xml` | Parse laporan XML nyata tanpa menjalankan GVM |
| **gmp** | `OPENVAS_MODE=gmp` + `gvm-cli` + appliance | Live connector; tanpa setup yang benar → fail closed / fallback mock |

### 6.4 Worker & parser

- Task: `scans.run_openvas`
- Wrapper: `workers/tool_wrappers/openvas.py`
- Output: XML → `stdout_xml`
- Parser: `openvas` (`OpenVasXmlParser`) — severity/threat, port (`22/tcp`), CVE/CWE dari NVT bila ada

Mock default menghasilkan tiga kelas finding per host (contoh): SSH weak crypto, TLS cipher lemah, missing HTTP headers — berguna untuk demo triage/compliance.

### 6.5 Contoh API (mock)

```bash
curl -s -X POST "$API/api/v1/scans" \
  -H "$AUTH" -H 'Content-Type: application/json' \
  -H "X-Organization-Id: $ORG_ID" \
  -d "{
    \"name\": \"VA (openvas)\",
    \"scan_type\": \"va\",
    \"engine\": \"openvas\",
    \"asset_ids\": [\"$ASSET_ID\"],
    \"config\": { \"openvas_mode\": \"mock\" },
    \"start_immediately\": true
  }"
```

### 6.6 Import laporan XML

```bash
# Sisipkan isi file report XML ke field report_xml (hati-hati ukuran payload)
curl -s -X POST "$API/api/v1/scans" \
  -H "$AUTH" -H 'Content-Type: application/json' \
  -H "X-Organization-Id: $ORG_ID" \
  -d "{
    \"name\": \"OpenVAS import\",
    \"scan_type\": \"va\",
    \"engine\": \"openvas\",
    \"asset_ids\": [\"$ASSET_ID\"],
    \"config\": { \"report_xml\": \"<?xml version=\\\"1.0\\\"?><report>...</report>\" },
    \"start_immediately\": true
  }"
```

Atau preview normalisasi tanpa scan penuh:

```bash
POST /api/v1/normalize/preview
{ "engine": "openvas", "raw": "<report>...</report>" }
```

---

## 7. Memilih connector — panduan singkat

| Kebutuhan | Pilih | Alasan |
|-----------|-------|--------|
| Peta port & layanan dulu | **Nmap** | Ringan, XML andal untuk discovery |
| Cek misconfig / CVE web | **Nuclei** | Template HTTP luas; butuh URL/domain |
| Demo / regressi internal | **NexuSec** | Tanpa binary pihak ketiga |
| Lab tanpa Greenbone / import report | **OpenVAS** | Mock atau `report_xml` |
| Appliance Greenbone produksi | **OpenVAS** + GMP | Hanya setelah `gvm-cli` & kredensial aman |

Urutan VA yang disarankan: **Nmap (discovery) → Nuclei / OpenVAS / NexuSec (VA) → triage SOC**.

---

## 8. Normalisasi & deduplikasi

Semua connector masuk registry yang sama (`build_default_registry`):

| Parser name | Format sumber |
|-------------|---------------|
| `nmap` | Nmap XML |
| `nuclei` | Nuclei JSON / JSONL |
| `nexusec` | Custom JSON findings |
| `openvas` | OpenVAS / GVM report XML |

Fingerprint stabil per `(asset, vuln_id/tool fields)` mencegah duplikat saat re-scan. Gold-set regresi: `backend/tests/fixtures/gold/` + `test_gold_set_eval.py`.

---

## 9. Schedules

Kartu/preset yang sama tersedia di form **New schedule**. Engine yang dapat dijadwalkan: `nmap`, `nuclei`, `nexusec`, `openvas`. Beat task `schedules.dispatch_due` membuat Scan baru dan enqueue ke queue `scans`.

---

## 10. Troubleshooting

| Gejala | Penyebab umum | Tindakan |
|--------|---------------|----------|
| Scan stuck `queued` | `scanner-worker` tidak jalan | `docker compose up -d scanner-worker` |
| Nuclei: *failed to create new OS thread* | `pids_limit` / concurrency terlalu tinggi | Rebuild stack terbaru; pakai preset VA nuclei (`-c`/`bulk-size` 10) |
| Nuclei: *Binary not found* | Image worker tanpa nuclei | Pakai image `Dockerfile.scanner`, bukan worker generik |
| OpenVAS 0 finding | XML kosong / mode gmp tanpa appliance | Set `openvas_mode=mock` atau isi `report_xml` |
| Finding kosong padahal completed | Parser mismatch / target unmatched | Cek `config.last_result.ingest` & `normalize/preview` |
| Judul “Discovery (nmap)” tapi engine nuclei | Nama job bebas diedit user | Percayai field `engine` di metadata baris scan, bukan judul saja |
| `Organization scope required` | Super-admin tanpa header | Kirim `X-Organization-Id` |

Cek log:

```bash
docker compose logs -f scanner-worker
```

---

## 11. Referensi kode

| Komponen | Path |
|----------|------|
| UI kartu & preset | `frontend/src/pages/ScansPage.tsx` |
| Enqueue API | `backend/app/services/scan_service.py` |
| Celery tasks | `workers/tasks.py` |
| Wrappers | `workers/tool_wrappers/{nmap,nuclei,openvas}.py` |
| Parsers | `backend/app/normalization/parsers/` |
| Registry | `backend/app/normalization/registry.py` |
| Compose limits | `docker-compose.yml` → service `scanner-worker` |
