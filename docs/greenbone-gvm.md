# Greenbone / OpenVAS live (GMP) — NexuSec

NexuSec **tidak menyertakan** appliance Greenbone di compose default (berat: DB feed, VT sync, banyak service).  
Yang ada di platform:

1. **mock** — XML sintetis (lab/CI)  
2. **import** — `config.report_xml` dari laporan GVM yang diekspor  
3. **gmp** — klien live `python-gvm` ke appliance yang Anda sediakan

## Prasyarat live GMP

- Greenbone Community Edition / enterprise / Kali GVM yang sudah jalan  
- User GMP (biasanya admin GVM) + password  
- Endpoint:
  - **Unix socket** (disarankan bila worker satu host dengan `gvmd`): `/run/gvmd/gvmd.sock`  
  - **TLS/TCP** (lab): `GVM_HOST` + `GVM_PORT` (sering `9390`; butuh sertifikat di setup produksi)

## Konfigurasi NexuSec

Di `.env` (lalu recreate `api` + `scanner-worker`):

```bash
OPENVAS_MODE=gmp
OPENVAS_GMP_FALLBACK_MOCK=false

GVM_USERNAME=admin
GVM_PASSWORD=CHANGE_ME
# Pilih salah satu:
GVM_SOCKET=/run/gvmd/gvmd.sock
# atau
GVM_HOST=host.docker.internal
GVM_PORT=9390

GVM_SCAN_CONFIG=Full and fast
GVM_PORT_LIST=All IANA assigned TCP
```

Atau biarkan `OPENVAS_MODE=mock` dan di UI Scans pilih engine **openvas** → mode **gmp** (per-scan override).

### Socket volume (compose)

Jika `gvmd` jalan di stack lain dan mengekspos volume socket:

```yaml
# cuplikan pada scanner-worker
volumes:
  - gvmd_socket:/run/gvmd:ro
environment:
  GVM_SOCKET: /run/gvmd/gvmd.sock
```

## Alur GMP di worker

1. Authenticate  
2. Resolve scan config + port list + scanner “OpenVAS Default”  
3. `create_target` → `create_task` → `start_task`  
4. Poll sampai status `Done` (timeout = `config.timeout_seconds`, default 900s)  
5. `get_report` XML → parser OpenVAS NexuSec → ingest findings  

Command evidence contoh: `openvas gmp tls:host:9390 target.example`

## Install Greenbone (di luar NexuSec)

Ikuti dokumentasi resmi Community Containers:

- https://greenbone.github.io/docs/  
- Forum: TLS/`9390` tidak selalu diaktifkan; socket + SSH forward lebih umum  

Setelah GVM siap dan feed VT tersinkron, isi `GVM_*` di NexuSec lalu rebuild:

```bash
docker compose up -d --build scanner-worker api
docker compose exec scanner-worker python -c "import gvm; print('python-gvm ok')"
```

Cek health: `GET /api/v1/health/detailed` → `tools.openvas.gvm_configured`.

## Mode aman untuk demo

| Situasi | Setting |
|---------|---------|
| Demo tanpa appliance | `OPENVAS_MODE=mock` |
| Import laporan nyata | `config.report_xml` (mode apa pun) |
| Live wajib gagal jelas bila GVM down | `OPENVAS_GMP_FALLBACK_MOCK=false` |
| Live tapi izinkan fallback demo | `OPENVAS_GMP_FALLBACK_MOCK=true` |

## Keamanan

- Jangan commit `GVM_PASSWORD`  
- Batasi network ke `gvmd` (jangan expose `9390` ke internet)  
- Target scan harus dalam scope izin / ROE — worker akan memindai host yang Anda daftarkan sebagai asset
