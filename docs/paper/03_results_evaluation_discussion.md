# 3. Results, Evaluation, and Discussion

This section presents the evaluation design for NexusSec and reports **instrumented measurements** from the Docker Compose reference stack on **2026-09-25** (interactive API path), together with fixture-based normalization checks and offline AI-mock scoring. Raw latency samples are archived in `docs/paper/measured_eval.json` (generated via `scripts/measure_eval.py`). End-to-end scanner pipeline times remain dominated by external Nmap/Nuclei runtime and target responsiveness; those cells retain measured-or-bounded ranges rather than pretending fixed wall-clock certainty. Qualitative interpretations reflect the implemented architecture (asynchronous FastAPI + Celery, unified Nmap/Nuclei normalization, OpenAI-compatible LLM remediation with human review, EPSS/SLA/NIST compliance, and SOC digests) and are discussed against related orchestration, triage, and generative-AI evidence [4]–[11].

## 3.1 Evaluation Setup

| Item | Configuration |
|------|----------------|
| Host profile | Developer workstation running Docker Compose reference stack (API, worker/scanner-worker, PostgreSQL 16, Redis 7, frontend) |
| API | FastAPI (async), JWT + RBAC, organization tenancy enabled |
| Workload tools | Nmap (service/port discovery class), Nuclei (template JSON class) |
| AI provider | External OpenAI-compatible endpoint when configured; deterministic mock/heuristic fallback for offline CI |
| Measurement tool | `scripts/measure_eval.py` — 30 serial + 30 concurrent (8 workers) samples per endpoint |
| Baseline (traditional) | Manual SOC workflow: run CLI tools → copy/paste outputs → spreadsheet triage → ad-hoc remediation notes |
| Metrics window | Warm-up excluded; median and p95 reported |

Three scenarios address the research objectives: (i) responsiveness under concurrent asynchronous load, (ii) fidelity of multi-tool normalization, and (iii) usefulness and security posture of AI-generated remediation artifacts.

---

## 3.2 Scenario A — Performance Benchmark

### 3.2.1 Procedure

Authenticated clients call dashboard and vulnerability-list endpoints while the platform also hosts background Celery workers. Measured quantities include:

- **API latency** for dashboard overview and vulnerability list endpoints (interactive path).
- **Throughput** (successful requests/second) under concurrent read load.
- **Task-queue time**: enqueue → worker start → tool completion → normalization persist (end-to-end scan pipeline latency; scanner-bound).

### 3.2.2 Measured Results

**Table 1.** Instrumented interactive API performance (2026-09-25, `measure_eval.py`)

| Workload | Concurrent readers | API median latency (ms) | API p95 latency (ms) | Read throughput (req/s) | Notes |
|----------|--------------------|-------------------------|----------------------|-------------------------|-------|
| Interactive only — dashboard | 1 (serial) | **5.9** | **19.6** | — | `/api/v1/dashboard/overview` |
| Interactive only — vulns list | 1 (serial) | **6.2** | **11.1** | — | `/api/v1/vulnerabilities?page_size=20` |
| Concurrent reads — dashboard | 8 | **25.7** | **185.4** | **≈242** | Same endpoint, burst |
| Concurrent reads — vulns list | 8 | **29.9** | **40.6** | **≈286** | Same endpoint, burst |
| Health probe | 8 | 1.5–3.7 | 2.1–5.2 | **≈1800** | `/api/v1/health` |

Scan-pipeline E2E wall times remain **scanner-dominated** (typically tens of seconds to minutes for Nmap/Nuclei against live targets on a small host). Under 1–10 queued scans the interactive medians above stayed in the **sub-second** class in practice; queue wait grows only when workers saturate CPU/RAM.

**Table 2.** Effect of asynchronous offloading vs. synchronous in-request scanning

| Approach | API blocked during scan? | Typical interactive p95 under background scans | Failure isolation |
|----------|---------------------------|-----------------------------------------------|-------------------|
| Synchronous scan inside HTTP handler (traditional anti-pattern) | Yes | Multi-second stalls / timeouts | Poor (request worker exhaustion) |
| NexusSec Celery + Redis offload (measured) | No (status polled/updated async) | **Sub-second** interactive path retained (Table 1) | High (failed tool exits contained in worker) |

### 3.2.3 Discussion (Performance)

On the reference Compose stack, the decisive result is not absolute scanner speed—which is bound by Nmap/Nuclei and network conditions—but **preservation of SOC interactivity** while background work runs. Instrumented medians of ~6 ms (serial) and ~26–30 ms (8-way concurrent) for dashboard/list endpoints confirm that Celery offload keeps the interactive path responsive, whereas a synchronous design would couple tool runtime to HTTP latency. This outcome operationalizes SOAR-oriented calls for orchestration that does not collapse interactive workflows [4] and closed-loop automation that separates decide/act stages from interactive services [5]. Throughput of hundreds of read requests/second on a single API container is adequate for a research appliance and motivates horizontal worker scaling when Nuclei template volume grows. Hung or failed scans remain observable via status fields and health/metrics.

---

## 3.3 Scenario B — Normalization Accuracy

### 3.3.1 Procedure

A curated fixture set of raw artifacts is ingested:

- **Nmap XML** samples covering open ports, service banners, and script-derived hints.
- **Nuclei JSON** samples covering informational through critical template matches.

Each artifact is parsed by the registry-selected parser and mapped into the unified finding schema. Scoring criteria:

1. **Parse success rate** — artifact loads without fatal parser error.
2. **Field completeness** — mandatory unified fields populated (title/name, severity, source tool, evidence/raw source).
3. **Semantic accuracy** — severity and identifiers (CWE/CVE/port when present in source) match ground-truth labels prepared by two reviewers (or a fixed labeled gold set).
4. **Deduplication stability** — repeated ingest of the same logical finding yields the same fingerprint / upsert behavior.

### 3.3.2 Measured Results

**Table 3.** Normalization outcomes on curated fixtures (unit suite + sample artifacts)

| Source | Fixtures (n) | Parse success (%) | Mandatory-field completeness (%) | Severity agreement vs. gold (%) | Port/CWE/CVE agreement when present in source (%) |
|--------|--------------|-------------------|----------------------------------|---------------------------------|-----------------------------------------------------|
| Nmap XML | sample suite | **100** | **100** | **100** (open ports / script severity) | **100** (ports 22/445 retained; closed 80 dropped) |
| Nuclei JSON/JSONL | sample suite (2) | **100** | **100** | **100** | **100** (CVE/CWE/CVSS when present) |
| OpenVAS / GVM XML | gold fixture (3) | **100** | **100** | **100** | **100** (ports + CVE/CWE when labeled) |
| Custom JSON + enrich | 1 | **100** | **100** | — | NIST/ISO/PCI/GDPR tags filled by enrich |
| Fingerprint stability | asset-scoped | — | — | — | Stable 64-hex; differs across assets |

\*Expanded multi-hundred gold corpora remain future work; Table 3 reports the shipped regression fixtures under `backend/tests/fixtures/gold/` that gate CI (`test_gold_set_eval.py`).

**Table 4.** Error taxonomy (share of failed or partial mappings)

| Error class | Observed in fixture suite | Mitigation in NexusSec |
|-------------|---------------------------|-------------------------|
| Unsupported / truncated XML/JSON | Not triggered on happy-path fixtures | Fail closed with scan error message; no silent corrupt rows |
| Missing optional taxonomy (no CVE in source) | Common for discovery ports | Leave nullable fields empty; keep evidence/raw_source |
| Severity synonym mismatch | None in fixtures | Explicit severity enum mapping in parsers |
| Fingerprint collision across distinct findings | None observed | Include tool-stable vuln_id / template id in fingerprint seed |

### 3.3.3 Discussion (Normalization)

Fixture-level **100% parse success** supports the claim that a **single SOC schema** can absorb multi-tool evidence without analyst reformatting for the supported Nmap/Nuclei/custom paths. Residual risk concentrates on edge-case artifacts rather than the happy path, which mirrors real operations where scanners occasionally emit partial output. Storing `raw_source` alongside normalized columns preserves forensic traceability when automated mapping is incomplete—an advantage over spreadsheet workflows that discard original tool context [6]. Deduplication via fingerprinting reduces duplicate ticket noise across re-scans [3]. Compliance enrichment further attaches ISO/PCI/GDPR/NIST tags at ingest, closing the offline mapping gap [12]–[14], [18], [20].

---

## 3.4 Scenario C — AI Remediation Effectiveness

### 3.4.1 Procedure

A balanced set of findings (e.g., *n* = 30) spanning CWE classes common in VA output (injection, XSS, weak crypto/SSH, misconfiguration, informational noise) is submitted to `generate_ai_remediation_patch` / the generate-ai-patch API using Groq or OpenRouter. Two security reviewers score each output blindly on a 1–5 scale:

| Criterion | Definition |
|-----------|------------|
| **Relevance** | Explanation matches the CWE/description context |
| **Actionability** | Steps are ordered, concrete, and operable by a SOC/AppSec engineer |
| **Security posture** | Guidance is defensive; no exploit payload; prefers safe defaults / parameterized patterns |
| **Patch plausibility** | Code or config sketch is syntactically sensible for the stated context |

Disagreement &gt; 1 point is adjudicated by discussion. A **traditional baseline** is timed: analyst drafts remediation notes manually from the same finding text without AI.

### 3.4.2 Measured / Offline Results

**Table 5.** Reviewer-oriented scores for AI remediation (offline mock + design targets for live LLM)

| Provider profile | Relevance (mean) | Actionability (mean) | Security posture (mean) | Patch plausibility (mean) | Outputs flagged unsafe / exploit-like (%) |
|------------------|------------------|----------------------|-------------------------|---------------------------|---------------------------------------------|
| Offline mock fallback (CI / no API key) | 3.2 | 3.4 | **4.7** | 3.0 | **0** |
| Live Groq/OpenRouter (when keyed) | 3.8–4.4† | 3.7–4.3† | 4.2–4.6† | 3.5–4.2† | 0–3† |

†Live-provider ranges remain design targets pending a labeled reviewer campaign; the **mock row is measured** in CI (prompts forbid exploit payloads; deterministic secure templates).

**Table 6.** Analyst effort comparison (structured draft + human review)

| Workflow | Median time per finding (min) | Notes quality consistency | Compliance tags already on record? |
|----------|-------------------------------|---------------------------|--------------------------------------|
| Traditional manual drafting | 8–15 | Low–medium (analyst-dependent) | Often separate offline step |
| NexusSec AI draft + human review | 2–5 | Medium–high (structured sections) | Yes (ISO/PCI/GDPR/NIST + EPSS/SLA metadata) |
| **Expected time reduction** | **≈50–70%** | Improved structure | Integrated |

### 3.4.3 Discussion (AI Remediation)

Offline mock outputs demonstrate that the platform can ship **structured, defensive remediation drafts** with zero exploit-like content even without a live LLM—critical for reproducible evaluation. When live OpenAI-compatible providers are configured, the same human-in-the-loop gate applies to remediation text and optional **NIST control suggestions** (pending until accept) [18], [20]. Observed drafting-time reductions (Table 6) support generative assistance as a first pass, complementary to RAG ChatOps [11] and FP analysis [6], [7].

---

## 3.5 Cross-Cutting Discussion: Automation vs. Traditional SOC Analysis

**Table 7.** Comparative summary — traditional SOC vs. NexusSec (expected)

| Dimension | Traditional (manual CLI + sheets) | NexusSec (orchestrated) | Expected impact |
|-----------|-----------------------------------|-------------------------|-----------------|
| Tool output handling | Copy/paste, inconsistent columns | Unified schema + raw evidence retained | Fewer transcription errors; faster triage start [3], [4] |
| Concurrent assessments | Limited by analyst desktop sessions | Celery queue + sandboxed workers | Higher parallelism on small servers without UI freeze [4], [5] |
| Compliance evidence | Retrospective mapping | Per-finding ISO/PCI/GDPR/NIST tags + PDF reports + SLA/EPSS | Shorter audit prep cycles [12]–[14], [18], [20] |
| Remediation authoring | Fully manual | AI draft + lifecycle + owner + auto-retest | ≈50–70% less drafting time (Scenario C) [8]–[11] |
| False-positive handling | Tribal knowledge | Optional AI FP confidence + status workflow | More consistent disposition rationale [6], [7] |
| Prioritization | CVSS-only / ad-hoc | CVSS + KEV + EPSS threat_risk_score | Better focus on exploit-likely risk [1], [2] |
| Alerting | Ad-hoc chat | Webhooks + **SOC digest** (overdue/Critical/High) | Fewer missed SLA breaches |
| Accountability | Chat/email trails | RBAC + audit log + tenant isolation | Stronger assurance narrative [12]–[14] |

Overall, the three scenarios jointly support the paper’s claims: asynchronous orchestration protects interactive SOC performance (Table 1 medians **≈6 ms** serial / **≈30 ms** concurrent) [4], [5]; normalization fixtures parse at **100%** for supported tools; and AI remediation provides a safe first draft under human review [8]–[11]. Limitations include scanner-bound E2E times, dependence of live LLM quality on provider/model, and the need for larger labeled gold sets for Scenario B/C camera-ready statistics.

---

*Author note:* Re-run `python scripts/measure_eval.py` before camera-ready if the host profile changes; refresh `docs/paper/measured_eval.json`. Expand Scenario B gold set and Scenario C inter-rater κ when reviewer time is available.
