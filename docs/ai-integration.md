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

Field penting: `ai_api_key_set`, `openai_api_key_set`, `ai_base_url`, `ai_model`, `remediation_fallback_mock`. Nilai key **tidak** pernah dikembalikan.

## 2. Variabel `.env`

```bash
# Master switch
AI_REMEDIATION_ENABLED=true
AI_REMEDIATION_FALLBACK_MOCK=true
AI_REMEDIATION_TIMEOUT_SECONDS=60

# OpenAI-compatible ( Groq / OpenRouter / OpenAI / lokal )
AI_API_KEY=gsk_xxxxxxxx
AI_BASE_URL=https://api.groq.com/openai/v1
AI_MODEL=llama-3.3-70b-versatile

# Opsional: paksa JSON mode (OpenAI-style)
# AI_FORCE_JSON_RESPONSE=true

# Legacy aliases (masih dibaca jika AI_* kosong)
# OPENAI_API_KEY=
# OPENAI_API_BASE=https://api.openai.com/v1
# OPENAI_MODEL=gpt-4o-mini
```

Setelah mengubah `.env`, recreate container API (dan worker bila dipakai untuk AI di background):

```bash
docker compose up -d --force-recreate api
```

## 3. Provider contoh

### Groq (cepat, gratis terbatas)

```bash
AI_API_KEY=gsk_...
AI_BASE_URL=https://api.groq.com/openai/v1
AI_MODEL=llama-3.3-70b-versatile
```

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

## 4. Uji cepat

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
- Rate limit provider: set `AI_REMEDIATION_FALLBACK_MOCK=true` agar job tidak gagal keras saat 429/timeout.
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
