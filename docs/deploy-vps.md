# Deploy NexuSec di VPS (Docker Compose + Nginx + HTTPS)

Panduan production untuk Ubuntu 22.04/24.04. Contoh domain: **`nexusec.my.id`** (ganti dengan domain Anda).

## 1. Spesifikasi VPS

| Resource | Lab | Produksi ringan |
|----------|-----|-----------------|
| RAM | 4 GB | 8 GB+ |
| CPU | 2 vCPU | 4 vCPU |
| Disk | 40 GB SSD | 80 GB+ |
| OS | Ubuntu 22.04 / 24.04 | sama |
| Port terbuka | 22, 80, 443 | sama |

`scanner-worker` di-compose dibatasi ~2 GB RAM.

## 2. DNS (wajib sebelum Certbot)

Di panel DNS (contoh Sumopod / Cloudflare), buat record **A**:

| Host | Type | Value | Catatan |
|------|------|-------|---------|
| `@` (root) | A | IP publik VPS | **Jangan** ketik FQDN penuh di kolom subdomain (bisa jadi `domain.domain`) |
| `www` | A | IP publik VPS yang sama | Opsional tapi disarankan |

Cek IP VPS:

```bash
curl -4 ifconfig.me; echo
```

Verifikasi propagasi:

```bash
dig +short A nexusec.my.id @8.8.8.8
dig +short A www.nexusec.my.id @8.8.8.8
```

Keduanya harus mengembalikan IP VPS. Jika kosong / `SERVFAIL`, Certbot **akan gagal** — perbaiki DNS dulu.

### Kesalahan umum DNS

- Host diisi `nexusec.my.id` → panel menambahkan zone lagi → jadi `nexusec.my.id.nexusec.my.id` (salah).
- Nameserver zona kosong / SOA `a.misconfigured.dns.server.invalid` → aktifkan DNS hosting di registrar, lalu isi A record.
- AAAA (IPv6) mengarah ke IP yang salah → hapus AAAA sampai IPv6 siap.

## 3. Siapkan server

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y git curl ufw ca-certificates nginx certbot python3-certbot-nginx

sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

Install Docker:

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
# logout / login SSH, lalu:
docker --version && docker compose version
```

## 4. Clone repo + `.env`

```bash
sudo mkdir -p /opt/nexusec && sudo chown $USER:$USER /opt/nexusec
cd /opt/nexusec
git clone https://github.com/bionte4/nexusec.git .
cp .env.example .env
```

Generate secrets:

```bash
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(48))"
python3 -c "import secrets; print('POSTGRES_PASSWORD=' + secrets.token_urlsafe(24))"
python3 -c "import secrets; print('REDIS_PASSWORD=' + secrets.token_urlsafe(24))"
```

Isi minimal di `.env` (jangan commit file ini). **Urutan penting:** rate limit & SSRF di atas, lalu Application:

```bash
# --- Rate limiting (P1) — taruh di bagian atas .env ---
RATE_LIMIT_ENABLED=true

# --- Scanner SSRF / private targets (P1) ---
# true  = produksi VPS (blok RFC1918, loopback, metadata cloud)
# false = hanya lab yang perlu scan LAN/private
SCAN_BLOCK_PRIVATE_TARGETS=true

# --- Application ---
APP_NAME=NexuSec
APP_ENV=production
DEBUG=false

SECRET_KEY=<hasil_generate>
POSTGRES_USER=nexusec
POSTGRES_PASSWORD=<hasil_generate>
POSTGRES_DB=nexusec
REDIS_PASSWORD=<hasil_generate>

# Harus exact origin browser (HTTPS)
CORS_ORIGINS=https://nexusec.my.id,https://www.nexusec.my.id

# AI — key boleh kosong dulu; isi lewat Admin UI. Fallback mock OFF di produksi.
AI_API_KEY=
AI_BASE_URL=https://api.groq.com/openai/v1
AI_MODEL=openai/gpt-oss-20b
AI_REMEDIATION_FALLBACK_MOCK=false
AI_FP_FALLBACK_MOCK=false
AI_SOC_CHAT_FALLBACK_MOCK=false

# Scanner: OpenVAS/ZAP mock = lab saja. Produksi VA: nmap/nuclei + GMP/Import.
OPENVAS_MODE=gmp
ZAP_MODE=import
OPENVAS_GMP_FALLBACK_MOCK=false
```

Referensi lengkap variabel: [`.env.example`](../.env.example) (bagian `# --- Rate limiting` dan `# --- Scanner SSRF`).

## 5. Bind API/UI ke localhost

Di `docker-compose.yml`, pastikan port hanya listen di loopback (Nginx yang expose 80/443):

```yaml
# service api
ports:
  - "127.0.0.1:8000:8000"

# service frontend
ports:
  - "127.0.0.1:8081:8080"
```

Postgres (`5433`) dan Redis (`6379`) sudah `127.0.0.1` di compose default.

## 6. Build & jalankan

```bash
cd /opt/nexusec
docker compose up -d --build
docker compose ps
docker compose logs api --tail 50
curl -s http://127.0.0.1:8000/health
```

Alembic migration jalan otomatis saat API start (`RUN_MIGRATIONS=true`).

## 7. Nginx reverse proxy

```bash
sudo tee /etc/nginx/sites-available/nexusec >/dev/null <<'EOF'
server {
    listen 80;
    server_name nexusec.my.id www.nexusec.my.id;

    client_max_body_size 20m;

    location /api/ {
        proxy_pass http://127.0.0.1:8000/api/;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 120s;
    }

    location /docs {
        proxy_pass http://127.0.0.1:8000/docs;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /openapi.json {
        proxy_pass http://127.0.0.1:8000/openapi.json;
        proxy_set_header Host $host;
    }

    location /health {
        proxy_pass http://127.0.0.1:8000/health;
    }

    location / {
        proxy_pass http://127.0.0.1:8081/;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF

sudo ln -sf /etc/nginx/sites-available/nexusec /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx
```

## 8. HTTPS (Let's Encrypt)

Setelah DNS A record benar:

```bash
sudo certbot --nginx -d nexusec.my.id -d www.nexusec.my.id
```

Jika Certbot melaporkan `SERVFAIL` / `DNS problem`, kembali ke [§2 DNS](#2-dns-wajib-sebelum-certbot) — bukan masalah Nginx.

## 9. Buat admin pertama

Password minimal **12** karakter (huruf besar/kecil + angka + simbol).

```bash
cat > /tmp/register.json <<'EOF'
{
  "email": "admin@nexusec.my.id",
  "full_name": "Admin",
  "password": "GantiPasswordKuat12!"
}
EOF

# Lewat HTTPS (setelah Certbot) atau localhost API:
curl -sS -X POST https://nexusec.my.id/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d @/tmp/register.json

# Alternatif lokal:
# curl -sS -X POST http://127.0.0.1:8000/api/v1/auth/register \
#   -H 'Content-Type: application/json' \
#   -d @/tmp/register.json
```

User pertama menjadi Super Admin.

**Hindari** `curl -d '{"..."}'` dengan kutip yang salah di bash — sering menghasilkan `JSON decode error`. Pakai file `@/tmp/register.json` seperti di atas.

## 10. Pasca-deploy

1. Buka https://nexusec.my.id → login.
2. **Admin → Sistem → Ai**: isi Groq API key, Base URL `https://api.groq.com/openai/v1`, model `openai/gpt-oss-20b` → **Simpan** → **Uji koneksi**.
3. Daftarkan aset (centang **CDE scope** untuk aset PCI) → jalankan scan:
   - Prefer **Nmap / Nuclei** atau **Import** ZAP JSON / OpenVAS XML.
   - Mock ZAP/OpenVAS = lab saja (memblokir Client PDF).
4. Centang **RoE** sebelum start scan / pipeline.
5. Alur laporan (P0–P3):
   - Prefer **Nmap / Nuclei** + **Import** ZAP/OpenVAS; mock hanya lab (`lab_mode`).
   - Isi **RoE** (+ opsional RoE ID) sebelum start.
   - **Vulnerabilities** → Draft PDF (internal).
   - Admin lain (bukan creator scan) → **Approve client** (SoD).
   - **Client PDF** (`delivery=client`) — berisi playbook + PTES/ASVS.
   - PCI report default **CDE-only**.

Detail AI: [`ai-integration.md`](ai-integration.md). VA/PT: [`usage-va-pt.md`](usage-va-pt.md).  
Tanpa Greenbone di VPS: [`va-without-gvm.md`](va-without-gvm.md) (Nmap / Nuclei / Import).

## 11. Update & backup

```bash
cd /opt/nexusec

# Backup Postgres dulu
docker compose exec -T postgres pg_dump -U nexusec nexusec \
  | gzip > ~/nexusec-$(date +%F).sql.gz

git pull

# Rebuild services yang dipakai scan + laporan
docker compose up -d --build --force-recreate api frontend scanner-worker worker

# Migrasi DB (termasuk 012_engagement_approvals) jalan otomatis di entrypoint API.
# Verifikasi:
docker compose logs api --tail 80 | grep -i alembic
docker compose ps
curl -sS https://nexusec.my.id/api/v1/health
```

Jika baru menambah/mengubah `RATE_LIMIT_ENABLED` / `SCAN_BLOCK_PRIVATE_TARGETS` di `.env`:

```bash
docker compose up -d --force-recreate api scanner-worker
```

## 12. Checklist keamanan

- [ ] Semua `CHANGE_ME` diganti; `.env` tidak di-commit
- [ ] `APP_ENV=production`, `DEBUG=false`
- [ ] `RATE_LIMIT_ENABLED=true` (bagian atas `.env`)
- [ ] `SCAN_BLOCK_PRIVATE_TARGETS=true` (produksi; `false` hanya lab LAN)
- [ ] `AI_*_FALLBACK_MOCK=false` + Admin → Test connection OK
- [ ] `CORS_ORIGINS` hanya HTTPS domain produksi
- [ ] Port 8000/8081/5433/6379 hanya di `127.0.0.1`
- [ ] UFW: 22 + 80 + 443
- [ ] HTTPS Certbot aktif
- [ ] Password admin ≥ 12 karakter
- [ ] Backup DB terjadwal
- [ ] Client engagement PDF hanya setelah dual-control approve
- [ ] Aset PCI ditandai `is_cde_scope`

## 13. Troubleshooting

| Gejala | Penyebab / perbaikan |
|--------|----------------------|
| Certbot `SERVFAIL` / no A record | DNS belum benar; cek `dig` §2 |
| UI load, API 502 | `docker compose logs api`; cek `proxy_pass` |
| CORS error di browser | `CORS_ORIGINS` harus exact (`https://nexusec.my.id`) |
| `JSON decode error` saat register | Body curl kosong/rusak — pakai `-d @file.json` |
| Password ditolak | Minimal 12 karakter |
| Scan stuck `queued` | `docker compose ps` — pastikan `scanner-worker` Up. `docker compose logs scanner-worker --tail 100`. Lalu **Requeue** di UI, atau: `docker compose up -d --force-recreate scanner-worker` |
| Pipeline discovery OK, VA stuck queued | Worker `scans` queue tidak konsumsi nuclei task — recreate `scanner-worker`; klik **Requeue** pada baris VA |
| Target private ditolak | `SCAN_BLOCK_PRIVATE_TARGETS=true` — set `false` hanya untuk lab LAN, lalu recreate `api` + `scanner-worker` |
| 429 Too Many Requests | Rate limit aktif (`RATE_LIMIT_ENABLED`); tunggu window atau naikkan hanya jika perlu |
| Client PDF ditolak (dual-control) | Admin harus **Approve client** dulu untuk scope yang sama; atau pakai Draft PDF |
| Engagement export mock blocked | Jangan pakai ZAP/OpenVAS mock untuk klien; Import report nyata / `allow_mock=true` lab saja |
| AI uji gagal | Base URL harus `https://api.groq.com/openai/v1` (bukan `console.groq.com/keys`); model contoh `openai/gpt-oss-20b` |
| OOM / container kill | Naikkan RAM VPS |

## Referensi

- Quick start lokal: [`../README.md`](../README.md)
- VA tanpa Greenbone (Nmap/Nuclei/Import): [`va-without-gvm.md`](va-without-gvm.md)
- VA/PT usage (RoE, engagement, dual-control, PCI CDE): [`usage-va-pt.md`](usage-va-pt.md)
- Hardening integrasi: [`integrations-hardening.md`](integrations-hardening.md)
- Scanner connectors: [`scanner-connectors.md`](scanner-connectors.md)
- Template env: [`../.env.example`](../.env.example)
