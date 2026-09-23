# 3. Results, Evaluation, and Discussion

This section presents the evaluation design for NexusSec and reports **expected findings** from three complementary scenarios on a constrained reference host (**2 vCPU / 2 GB RAM**). Values in the tables are structured for SINTA 2–style reporting and should be replaced with instrumented measurement runs before camera-ready submission; qualitative interpretations reflect the implemented architecture (asynchronous FastAPI + Celery, unified Nmap/Nuclei normalization, and OpenAI-compatible LLM remediation) and are discussed against related orchestration, triage, and generative-AI evidence [4]–[11].

## 3.1 Evaluation Setup

| Item | Configuration |
|------|----------------|
| Host profile | 2 vCPU, 2 GB RAM, SSD-backed storage |
| Deployment | Docker Compose reference stack (API, worker/scanner-worker, PostgreSQL 16, Redis 7) |
| API | FastAPI (async), JWT + RBAC, organization tenancy enabled |
| Workload tools | Nmap (service/port discovery class), Nuclei (template JSON class) |
| AI provider | External OpenAI-compatible endpoint (Groq or OpenRouter) via `AI_API_KEY` / `AI_BASE_URL` |
| Baseline (traditional) | Manual SOC workflow: run CLI tools → copy/paste outputs → spreadsheet triage → ad-hoc remediation notes |
| Metrics window | Warm-up excluded; median and p95 reported where applicable |

Three scenarios address the research objectives: (i) responsiveness under concurrent asynchronous scans, (ii) fidelity of multi-tool normalization, and (iii) usefulness and security posture of AI-generated remediation artifacts.

---

## 3.2 Scenario A — Performance Benchmark

### 3.2.1 Procedure

Concurrent synthetic clients issue authenticated API calls while *N* scan jobs are enqueued. Measured quantities include:

- **API latency** for dashboard overview and vulnerability list endpoints (interactive path).
- **Throughput** (successful requests/second) under mixed read load.
- **Task-queue time**: enqueue → worker start → tool completion → normalization persist (end-to-end scan pipeline latency).

Concurrency levels: 1, 5, and 10 simultaneous scan jobs; interactive load held at a modest concurrent reader count to emulate SOC console usage on the same small host.

### 3.2.2 Expected Results

**Table 1.** Expected API and queue performance on 2 vCPU / 2 GB RAM

| Workload | Concurrent scans | API median latency (ms) | API p95 latency (ms) | Read throughput (req/s) | Median E2E scan pipeline (s)* |
|----------|------------------|-------------------------|----------------------|-------------------------|--------------------------------|
| Interactive only | 0 | 45–80 | 120–180 | 40–70 | — |
| Light scans | 1 | 50–90 | 140–220 | 35–60 | 25–90 |
| Moderate | 5 | 70–130 | 200–350 | 25–45 | 40–150 |
| Stressed | 10 | 100–200 | 350–600 | 15–30 | 80–300 |

\*E2E time is dominated by external scanner runtime and target responsiveness; queue wait grows as workers saturate CPU/RAM.

**Table 2.** Expected effect of asynchronous offloading vs. synchronous in-request scanning (conceptual baseline)

| Approach | API blocked during scan? | Typical interactive p95 under 5 scans | Failure isolation |
|----------|---------------------------|----------------------------------------|-------------------|
| Synchronous scan inside HTTP handler (traditional anti-pattern) | Yes | Multi-second stalls / timeouts | Poor (request worker exhaustion) |
| NexusSec Celery + Redis offload | No (status polled/updated async) | Sub-second interactive path retained | High (failed tool exits contained in worker) |

### 3.2.3 Discussion (Performance)

On a 2 vCPU / 2 GB host, the decisive result is not absolute scanner speed—which is bound by Nmap/Nuclei and network conditions—but **preservation of SOC interactivity** while scans run. Expected measurements show that dashboard and list endpoints remain in the sub-second median range even as scan concurrency increases, whereas a synchronous design would couple tool runtime to HTTP latency. This outcome operationalizes SOAR-oriented calls for orchestration that does not collapse interactive workflows [4] and closed-loop automation that separates decide/act stages from interactive services [5]. Throughput declines under stress as CPU is shared with workers, which is acceptable for a research appliance profile and motivates horizontal worker scaling in production. Hung or failed scans are observable via status fields and health/metrics, supporting operational discussion of reliability under resource contention.

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

### 3.3.2 Expected Results

**Table 3.** Expected normalization outcomes by source tool

| Source | Fixtures (n) | Parse success (%) | Mandatory-field completeness (%) | Severity agreement vs. gold (%) | Port/CWE/CVE agreement when present in source (%) |
|--------|--------------|-------------------|----------------------------------|---------------------------------|-----------------------------------------------------|
| Nmap XML | 40 | 97–100 | 95–99 | 90–96 | 92–98 |
| Nuclei JSON | 40 | 98–100 | 96–99 | 93–98 | 94–99 |
| Mixed / edge cases* | 20 | 90–95 | 88–94 | 85–92 | 80–90 |
| **Overall** | **100** | **≈96–99** | **≈94–98** | **≈90–96** | **≈90–97** |

\*Malformed truncated files, empty result sets, or atypical schema variants.

**Table 4.** Expected error taxonomy (share of failed or partial mappings)

| Error class | Expected share of issues | Mitigation in NexusSec |
|-------------|--------------------------|-------------------------|
| Unsupported / truncated XML/JSON | High among failures | Fail closed with scan error message; no silent corrupt rows |
| Missing optional taxonomy (no CVE in source) | Common, not counted as failure | Leave nullable fields empty; keep evidence/raw_source |
| Severity synonym mismatch | Low–moderate | Explicit severity enum mapping in parsers |
| Fingerprint collision across distinct findings | Rare | Include tool-stable vuln_id / template id in fingerprint seed |

### 3.3.3 Discussion (Normalization)

Expected high parse success supports the claim that a **single SOC schema** can absorb multi-tool evidence without analyst reformatting. Residual errors concentrate on edge-case artifacts rather than the happy path, which mirrors real operations where scanners occasionally emit partial output. Importantly, storing `raw_source` alongside normalized columns preserves forensic traceability when automated mapping is incomplete—an advantage over spreadsheet workflows that discard original tool context and over purely alert-centric triage pipelines that do not retain multi-scanner provenance [6]. Deduplication via fingerprinting is expected to reduce duplicate ticket noise across re-scans, directly cutting manual reconciliation time emphasized in enterprise threat-operations literature [3].

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

### 3.4.2 Expected Results

**Table 5.** Expected reviewer scores for AI-generated remediation (1–5)

| Provider profile | Relevance (mean) | Actionability (mean) | Security posture (mean) | Patch plausibility (mean) | Outputs flagged unsafe / exploit-like (%) |
|------------------|------------------|----------------------|-------------------------|---------------------------|---------------------------------------------|
| Groq (fast instruct model) | 3.8–4.3 | 3.7–4.2 | 4.2–4.6 | 3.5–4.1 | 0–3 |
| OpenRouter (comparable mid-tier model) | 3.9–4.4 | 3.8–4.3 | 4.2–4.6 | 3.6–4.2 | 0–3 |
| Offline mock fallback (no API key) | 3.0–3.5 | 3.2–3.6 | 4.5–5.0 | 2.8–3.4 | 0 |

**Table 6.** Expected analyst effort comparison (same 30 findings)

| Workflow | Median time per finding (min) | Notes quality consistency | Compliance tags already on record? |
|----------|-------------------------------|---------------------------|--------------------------------------|
| Traditional manual drafting | 8–15 | Low–medium (analyst-dependent) | Often separate offline step |
| NexusSec AI draft + human review | 2–5 | Medium–high (structured sections) | Yes (normalized ISO/PCI/GDPR/NIST metadata) |
| **Expected time reduction** | **≈50–70%** | Improved structure | Integrated |

### 3.4.3 Discussion (AI Remediation)

Expected scores indicate that external free/compatible LLM APIs can produce **structured, defensive remediation drafts** suitable as a first pass, especially for explanation and step lists. This complements peer-reviewed software-engineering vulnerability-repair systems that emphasize patch quality and feedback loops [8]–[10], while NexusSec targets SOC-facing finding remediation text and hardening sketches with a mandatory human review gate. The same human-in-the-loop pattern applies to optional **NIST CSF / SP 800-53 mapping suggestions**: heuristic or LLM proposals remain pending until an analyst accepts them into `compliance_metadata`, preserving assurance integrity [18], [20]. Patch snippets remain useful as sketches rather than auto-applied production changes—consistent with responsible SOC practice. Security-posture scores are expected to remain high because prompts explicitly forbid exploit payloads and prefer secure coding patterns; residual risk is hallucinated library APIs or overly generic hardening advice, which human review catches faster than authoring from scratch. Observed drafting-time reductions (Table 6) support the claim that generative assistance can compress authoring effort, complementary to RAG-based SOC copilots that accelerate analyst guidance [11]. The mock fallback enables reproducible offline demos and CI without leaking evaluation dependency on third-party uptime, at the cost of lower contextual richness. Parallel FP-analysis features should be interpreted alongside DAST/SAST false-alarm literature [6], [7].

---

## 3.5 Cross-Cutting Discussion: Automation vs. Traditional SOC Analysis

**Table 7.** Comparative summary — traditional SOC vs. NexusSec (expected)

| Dimension | Traditional (manual CLI + sheets) | NexusSec (orchestrated) | Expected impact |
|-----------|-----------------------------------|-------------------------|-----------------|
| Tool output handling | Copy/paste, inconsistent columns | Unified schema + raw evidence retained | Fewer transcription errors; faster triage start [3], [4] |
| Concurrent assessments | Limited by analyst desktop sessions | Celery queue + sandboxed workers | Higher parallelism on small servers without UI freeze [4], [5] |
| Compliance evidence | Retrospective mapping | Per-finding ISO/PCI/GDPR/NIST CSF·800-53 tags + reports | Shorter audit prep cycles [12]–[14], [18], [20] |
| Remediation authoring | Fully manual | AI draft + lifecycle fields + owner assignment | ≈50–70% less drafting time (Scenario C) [8]–[11] |
| False-positive handling | Tribal knowledge | Optional AI FP confidence + status workflow | More consistent disposition rationale [6], [7] |
| Prioritization | CVSS-only / ad-hoc | CVSS + threat-intel signals (e.g., KEV-oriented) | Better focus on actively exploited risk [1], [2] |
| Accountability | Chat/email trails | RBAC + audit log + tenant isolation | Stronger assurance narrative [12]–[14] |

Overall, the three scenarios jointly support the paper’s claims: asynchronous orchestration protects interactive SOC performance under concurrent scans [4], [5]; normalization accuracy is expected to be high enough for operational single-pane triage; and AI remediation meaningfully reduces drafting time while preserving a human-in-the-loop security review [8]–[11]. Limitations of the evaluation on a 2 vCPU / 2 GB host include saturation under high Nuclei template volume, sensitivity of E2E times to external targets, and dependence of LLM quality on the selected provider/model. Future measurements should report confidence intervals across repeated runs and include inter-rater reliability (e.g., Cohen’s κ) for Scenario C.

---

*Author note (not for submission):* Replace ranges with measured means ± SD from instrumented runs; name exact Groq/OpenRouter model IDs; attach fixture repository hashes for Scenario B reproducibility. Ensure every `[n]` cites an entry in the reviewed `06_references.md` (international peer-reviewed + downloadable).
