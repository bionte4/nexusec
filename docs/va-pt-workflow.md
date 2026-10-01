# Alur VA/PT di NexuSec — engine & urutan kerja

Dokumen ini menjelaskan **urutan scan yang disarankan** dan peran tiap engine (OSINT pasif → discovery aktif → VA → DAST/import → PT manusia → laporan).

> Detail pemakaian: [`usage-va-pt.md`](usage-va-pt.md) · Tanpa GVM: [`va-without-gvm.md`](va-without-gvm.md) · OSINT: [`osint-connector.md`](osint-connector.md)

---

## 1. Diagram alur (disarankan)

```text
┌─────────────────────────────────────────────────────────────────┐
│ 0. Persiapan                                                     │
│    Assets (domain/IP/URL) → centang RoE (+ roe_id) → scope jelas │
└───────────────────────────────┬─────────────────────────────────┘
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│ 1. Intelligence gathering (pasif)                                │
│    Engine: osint                                                 │
│    DNS · Certificate Transparency (crt.sh) · RDAP                │
│    Temuan tipikal: INFO (subdomain, DNS, registrasi)             │
└───────────────────────────────┬─────────────────────────────────┘
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│ 2. Discovery / surface (aktif, ringan)                           │
│    Engine: nmap  (utama)  ATAU  nexusec (TCP connect + banner)   │
│    Port/service terbuka → perluas aset bila subdomain baru       │
└───────────────────────────────┬─────────────────────────────────┘
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│ 3. Vulnerability assessment (otomatis)                           │
│    Engine: nuclei  (utama di VPS tanpa GVM)                      │
│    Opsional: Import OpenVAS XML / pipeline discovery→nuclei      │
│    Temuan tipikal: INFO … CRITICAL (bergantung template)         │
└───────────────────────────────┬─────────────────────────────────┘
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│ 4. DAST web (opsional)                                           │
│    Import ZAP JSON  ATAU  zap_policy=owasp_top10 (lab saja)      │
└───────────────────────────────┬─────────────────────────────────┘
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│ 5. PT manusia (wajib untuk engagement PT)                        │
│    Confirm finding · bukti · remedi · retest                     │
│    Platform TIDAK auto-exploit                                   │
└───────────────────────────────┬─────────────────────────────────┘
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│ 6. Laporan                                                       │
│    Draft PDF → Approve client (SoD ≠ creator) → Client PDF       │
│    + checklist PTES / ASVS di engagement                         │
└─────────────────────────────────────────────────────────────────┘
```

**Pipeline satu klik (UI):** Discovery **nmap** → VA **nuclei** (atau nexusec/openvas/zap bila siap). OSINT dijalankan **sebelum** pipeline sebagai langkah terpisah.

---

## 2. Perbandingan engine

| Engine | Sifat | Fungsi | Severity tipikal | Butuh tool luar? |
|--------|-------|--------|------------------|------------------|
| **osint** | Pasif | Recon DNS / CT / RDAP | Hampir semua **INFO** (LOW jika banyak subdomain CT) | Tidak (HTTPS ke crt.sh/rdap) |
| **nexusec** | Aktif ringan | TCP connect + banner grab | INFO / LOW (port open) | Tidak (built-in asyncio) |
| **nmap** | Aktif | Port/service fingerprint + NSE aman | INFO … (tergantung temuan) | Binary di `scanner-worker` |
| **nuclei** | Aktif VA | Template CVE / misconfig / exposure | INFO … **CRITICAL** | Binary + templates di image |
| **openvas** | VA | GMP live / Import XML / mock lab | Bervariasi | GVM terpisah **atau** Import |
| **zap** | DAST | Import JSON / mock / owasp_top10 lab | Bervariasi | Import (daemon belum live) |

### Kapan pakai apa

| Tujuan | Pakai |
|--------|--------|
| Cari subdomain & jejak registrasi | **osint** |
| Cek port terbuka cepat tanpa Nmap | **nexusec** |
| Discovery standar / fingerprint layanan | **nmap** |
| Temuan keamanan otomatis (High/Critical) | **nuclei** |
| Laporan OpenVAS dari mesin lain | **Import** `openvas` |
| Laporan ZAP DAST | **Import** `zap` |
| Demo lab tanpa target nyata | mock OpenVAS/ZAP + `lab_mode` (bukan Client PDF) |

---

## 3. Kenapa OSINT sering “hanya INFO”?

OSINT **bukan** vulnerability scanner. Ia mengumpulkan sinyal recon:

- DNS A/AAAA → fakta resolve, bukan CVE  
- Subdomain dari CT → permukaan serangan baru, belum dieksploitasi  
- RDAP → status domain / nameserver  

**Critical/High** muncul setelah langkah 3+ (**nuclei**, OpenVAS import, ZAP import) atau konfirmasi PT manusia.

---

## 4. Langkah UI (contoh domain)

1. **Assets** → tambah domain (mis. `klikhadir.site`), centang CDE bila PCI.  
2. **Scans** → centang **RoE** (+ RoE ID).  
3. Preset **OSINT · dns/CT/RDAP** → Start → tinjau subdomain di Vulnerabilities.  
4. Daftarkan subdomain penting sebagai aset baru (opsional).  
5. Preset **Discovery · nmap** *atau* **VA · nexusec** pada aset yang sama.  
6. Preset **VA · nuclei** (atau **Pipeline** discovery→nuclei).  
7. Triage: status, assign, AI remediation, **retest** Critical/High.  
8. **Vulnerabilities** → Draft PDF → admin lain **Approve client** → **Client PDF**.

---

## 5. Mapping ke PTES (proses)

| Fase PTES | Di NexuSec |
|-----------|------------|
| Pre-engagement | RoE checkbox + `roe_id` |
| Intelligence gathering | **osint** (+ inventori Assets) |
| Threat modeling | Manusia (checklist engagement) |
| Vulnerability analysis | **nuclei** / Import OpenVAS / ZAP |
| Exploitation | **Manusia saja** (status `confirmed`) |
| Post-exploitation | Manusia |
| Reporting | Engagement Draft → SoD approve → Client PDF |

Checklist otomatis ada di engagement report (`ptes_checklist` / `asvs_checklist`).

---

## 6. Contoh API ringkas

```bash
# 1) OSINT
curl -s -X POST "$API/api/v1/scans" -H "$AUTH" -H 'Content-Type: application/json' \
  -d "{\"name\":\"OSINT\",\"scan_type\":\"discovery\",\"engine\":\"osint\",
       \"asset_ids\":[\"$ASSET_ID\"],
       \"config\":{\"roe_acknowledged\":true,\"osint_modules\":[\"dns\",\"crtsh\",\"rdap\"]},
       \"start\":true}"

# 2) Nmap discovery
curl -s -X POST "$API/api/v1/scans" -H "$AUTH" -H 'Content-Type: application/json' \
  -d "{\"name\":\"Discovery\",\"scan_type\":\"discovery\",\"engine\":\"nmap\",
       \"asset_ids\":[\"$ASSET_ID\"],
       \"config\":{\"roe_acknowledged\":true,\"port_preset\":\"common_va\"},
       \"start\":true}"

# 3) Nuclei VA
curl -s -X POST "$API/api/v1/scans" -H "$AUTH" -H 'Content-Type: application/json' \
  -d "{\"name\":\"VA nuclei\",\"scan_type\":\"va\",\"engine\":\"nuclei\",
       \"asset_ids\":[\"$ASSET_ID\"],
       \"config\":{\"roe_acknowledged\":true,\"severity\":[\"critical\",\"high\",\"medium\"]},
       \"start\":true}"

# Atau pipeline nmap → nuclei
curl -s -X POST "$API/api/v1/scans/pipeline" -H "$AUTH" -H 'Content-Type: application/json' \
  -d "{\"name\":\"Pipeline\",\"asset_ids\":[\"$ASSET_ID\"],\"va_engine\":\"nuclei\",
       \"va_config\":{\"roe_acknowledged\":true}}"
```

---

## 7. Checklist cepat VPS (tanpa Greenbone)

- [ ] `.env`: `OPENVAS_MODE=import`, `ZAP_MODE=import` (tanpa `GVM_*`)  
- [ ] `scanner-worker` Up; `nmap` & `nuclei` ada di container  
- [ ] RoE sebelum enqueue  
- [ ] Urutan: **osint → nmap/nexusec → nuclei**  
- [ ] Client PDF hanya setelah SoD approve + bukti non-mock  

---

## Referensi

| Dokumen | Isi |
|---------|-----|
| [`osint-connector.md`](osint-connector.md) | Modul DNS/crt.sh/RDAP |
| [`va-without-gvm.md`](va-without-gvm.md) | Produksi tanpa OpenVAS live |
| [`scanner-connectors.md`](scanner-connectors.md) | Preset & config tiap engine |
| [`usage-va-pt.md`](usage-va-pt.md) | RoE, engagement, dual-control, PCI |
| [`greenbone-gvm.md`](greenbone-gvm.md) | Opsional bila nanti ada GVM |
