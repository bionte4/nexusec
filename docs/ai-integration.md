# Integrasi AI di NexuSec

Panduan menyambungkan LLM OpenAI-compatible untuk **AI remediation**, false-positive analysis, NIST mapping suggestions, dan SOC ChatOps.

## 1. Ringkas arsitektur

| Fitur | Endpoint | Env utama |
|-------|----------|-----------|
| Remediation / patch draft | `POST /api/v1/vulnerabilities/{id}/generate-ai-patch` | `AI_*` |
| Bulk remediation | `POST /api/v1/vulnerabilities/bulk-generate-ai-patch` | `AI_*` |
| False-positive triage | `POST /api/v1/vulnerabilities/{id}/analyze-fp` | `AI_*` / `OPENAI_*` |
| NIST control suggest | `POST /api/v1/vulnerabilities/{id}/suggest-nist-controls` | `AI_*` |
| SOC ChatOps | `POST /api/v1/soc/chat` | `AI_*` |

Tanpa API key, layanan memakai **mock deterministik** (aman untuk demo/CI). Mock remediation menyesuaikan title/port/CWE (Redis vs TLS vs SQLi, dll.).

Status wiring (Admin / health):

```bash
curl -s -H "$AUTH" "$API/api/v1/health/detailed" | python3 -c \
  'import sys,json; d=json.load(sys.stdin); print(json.dumps(d["checks"].get("ai"), indent=2))'
```

Field penting: `api_key_set`, `source` (`database` | `env` | `none`), `ai_base_url`, `ai_model`. Nilai key **tidak** pernah dikembalikan.

## 2. Konfigurasi dari UI (disarankan)

Admin → **Sistem** → kartu **Ai**:

1. (Opsional) **Pakai default Groq**
2. Isi **API key** (`gsk_…` dari console.groq.com)
3. **Simpan pengaturan** — tersimpan di Postgres (`platform_settings`), tanpa edit `.env`
4. **Uji koneksi**

API:

```bash
# Baca (key di-mask)
GET /api/v1/health/ai/settings

# Simpan
PATCH /api/v1/health/ai/settings
{ "api_key": "gsk_...", "base_url": "https://api.groq.com/openai/v1", "model": "openai/gpt-oss-20b" }

# Uji
POST /api/v1/health/ai/test
```

Prioritas kredensial: **DB/UI → env `.env` → mock fallback**.

## 3. Variabel `.env` (opsional / fallback)

```bash
# Master switch — false = fail closed (no silent template-v2)
AI_REMEDIATION_ENABLED=true
AI_REMEDIATION_FALLBACK_MOCK=false
AI_FP_FALLBACK_MOCK=false
AI_SOC_CHAT_FALLBACK_MOCK=false
AI_REMEDIATION_TIMEOUT_SECONDS=60

# Hanya dipakai jika belum ada setting di UI/DB
AI_API_KEY=
AI_BASE_URL=https://api.groq.com/openai/v1
AI_MODEL=openai/gpt-oss-20b
```

> **Produksi:** keep `*_FALLBACK_MOCK=false`. **Lab offline:** set `true` for deterministic templates without a key.

## 3. Provider contoh (rekomendasi)

| Prioritas | Provider | Cocok untuk | Catatan |
|-----------|----------|-------------|---------|
| **1 (lab)** | **Groq** | Demo / CI / latency rendah | Free tier; contoh model `openai/gpt-oss-20b` / `openai/gpt-oss-120b` |
| 2 | OpenRouter | Multi-model satu key | Bayar per token; mudah ganti model |
| 3 | OpenAI | Produksi / kualitas stabil | Perlu billing; set `AI_FORCE_JSON_RESPONSE=true` |
| 4 | Ollama (lokal) | Offline / data tidak keluar | `host.docker.internal:11434` dari container |

### Groq (direkomendasikan untuk mulai)

1. Buat akun di https://console.groq.com → **API Keys** → create key (`gsk_…`).
2. Edit `.env` (jangan commit):

```bash
AI_API_KEY=gsk_...
AI_BASE_URL=https://api.groq.com/openai/v1
AI_MODEL=openai/gpt-oss-20b
AI_REMEDIATION_FALLBACK_MOCK=false
AI_FP_FALLBACK_MOCK=false
AI_SOC_CHAT_FALLBACK_MOCK=false
```

> **Produksi:** biarkan `false` agar tidak diam-diam jatuh ke `mock/template-v2`.  
> **Lab offline:** set `true` jika ingin template deterministik tanpa API key.
3. Recreate API:

```bash
docker compose up -d --force-recreate api
```

4. Admin → **System** → kartu **Ai** → **Test connection** (atau `POST /api/v1/health/ai/test`).

### OpenRouter

```bash
AI_API_KEY=sk-or-...
AI_BASE_URL=https://openrouter.ai/api/v1
AI_MODEL=openai/gpt-4o-mini
```

### OpenAI

```bash
AI_API_KEY=sk-...
AI_BASE_URL=https://api.openai.com/v1
AI_MODEL=gpt-4o-mini
AI_FORCE_JSON_RESPONSE=true
```

### Lokal (Ollama / vLLM dengan API OpenAI-compatible)

```bash
AI_API_KEY=ollama
AI_BASE_URL=http://host.docker.internal:11434/v1
AI_MODEL=llama3.2
```

## 4. Uji cepat / Test connection

**Dari UI (Admin):** System → kartu Ai → **Test connection**. Endpoint memanggil chat completion mini dan menampilkan latency + model tanpa mengekspos API key.

```bash
curl -s -X POST -H "$AUTH" "$API/api/v1/health/ai/test" | python3 -m json.tool
```

Uji fitur remediation:

```bash
export AUTH="Authorization: Bearer $TOKEN"
export VULN_ID="<uuid-finding>"

# Satu finding
curl -s -X POST -H "$AUTH" \
  "$API/api/v1/vulnerabilities/$VULN_ID/generate-ai-patch" | python3 -m json.tool

# Massal (maks 25)
curl -s -X POST -H "$AUTH" -H 'Content-Type: application/json' \
  "$API/api/v1/vulnerabilities/bulk-generate-ai-patch" \
  -d '{"vulnerability_ids":["'"$VULN_ID"'"],"persist":true}' | python3 -m json.tool
```

Respons berisi `provider`, `model`, `explanation`, `remediation_steps`, `patch_example`. Teks markdown disimpan ke `vulnerability.remediation`.

Di UI **Remediation**:

- Detail finding → **Generate AI remediation**
- List → centang findings → **Generate AI remediation** (bulk)

## 5. Keamanan & review

- Output AI adalah **draft** — wajib review manusia sebelum apply ke produksi.
- Jangan masukkan secret target / `.env` ke prompt secara manual.
- Rate limit provider: temporarily set `AI_REMEDIATION_FALLBACK_MOCK=true` only if you accept silent template-v2 drafts; prefer retry/backoff with fallback left `false` in production.
- Bulk dibatasi **25** finding per request untuk melindungi kuota LLM.

## 6. Troubleshooting

| Gejala | Cek |
|--------|-----|
| Selalu mock / `provider=mock` | `AI_API_KEY` kosong atau tidak ter-load di container |
| 400 “not configured” | Key kosong + `AI_REMEDIATION_FALLBACK_MOCK=false` |
| 429 | Rate limit provider — tunggu atau ganti model |
| Konten generik | Pastikan API sudah di-rebuild setelah patch finding-specific; generate ulang |
| Timeout | Naikkan `AI_REMEDIATION_TIMEOUT_SECONDS` atau kurangi bulk size |

Lihat juga: [`usage-va-pt.md`](usage-va-pt.md) §7 (triage) dan [`scanner-connectors.md`](scanner-connectors.md) untuk VA berkredensial.
