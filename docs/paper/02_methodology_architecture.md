# 2. Research Methodology and System Architecture

## 2.1 System Development Methodology

NexusSec was developed using an **iterative prototyping methodology** combined with principles of **agile system engineering**. The approach is appropriate for security orchestration research platforms because requirements span heterogeneous integrations (scanners, databases, LLM providers, compliance taxonomies) that are best validated through successive, working increments rather than a single waterfall specification—consistent with orchestration and closed-loop automation research that emphasizes iterative tooling evolution [4], [5].

Development proceeded in capability-oriented increments aligned with operational SOC value:

1. **Foundation increment** — core domain model (organizations, users/RBAC, assets, scans, vulnerabilities), asynchronous FastAPI API, PostgreSQL persistence, JWT authentication, and audit logging.
2. **Orchestration increment** — Celery workers, Redis broker/result backend, secure wrappers for third-party CLI scanners, and Docker-based isolation for tool execution.
3. **Intelligence increment** — unified normalization parsers, fingerprint-based deduplication, compliance metadata enrichment, and compliance report generation (ISO 27001, PCI-DSS, GDPR views).
4. **Decision-support increment** — threat-intelligence enrichment (e.g., KEV/NVD-oriented signals) beyond static CVSS alone [1], [2], AI remediation via OpenAI-compatible LLM APIs [8]–[10], false-positive analysis [6], [7], and retrieval-augmented SOC ChatOps [11].
5. **Hardening increment** — multi-tenancy controls, observability (health checks, Prometheus metrics), and reproducible Docker Compose deployment.

Each increment produced a deployable slice of the platform that could be exercised through automated tests and API-level acceptance checks. Design decisions were constrained by secure-by-design rules: role-based access control on mutating endpoints, tenant scoping of queries, avoidance of unsafe shell interpolation when wrapping external tools, and exclusion of secrets/PII from application logs. This methodology yields both a research artifact suitable for evaluation and an engineering baseline that can evolve toward production operations.

## 2.2 System Architecture

NexusSec follows a **modular, microservices-ready layered architecture**. Logically, the system separates (i) the interactive API gateway and business services, (ii) asynchronous workers for long-running and potentially unsafe work, (iii) stateful data stores, and (iv) optional AI/provider integrations. Physically, the reference deployment packages these layers as containerized services (API, worker/scanner-worker, PostgreSQL, Redis, and a React SOC frontend).

### 2.2.1 Core Backend API (FastAPI, PostgreSQL, Redis)

The control plane is implemented in **Python FastAPI** using asynchronous request handlers and **SQLAlchemy** asynchronous sessions against **PostgreSQL**. The API exposes versioned REST resources under `/api/v1`, including authentication, organization/tenant administration, asset inventory, scan lifecycle, vulnerability remediation tracking, dashboard aggregations, compliance reports, threat-intelligence views, health/metrics, and AI-assisted SOC endpoints.

PostgreSQL stores the normalized operational state: multi-tenant organizations and users, assets (IP, domain, cloud resource) with PCI-DSS Cardholder Data Environment (CDE) flags, scan jobs and associations, vulnerabilities with evidence JSON, remediation ownership/status history, comments, and threat-intel enrichment fields. **Redis** serves dual roles: low-latency caching/broker responsibilities and the **Celery** message broker / result backend channels used to dispatch scan and enrichment tasks without blocking HTTP workers.

Cross-cutting concerns enforced at the API layer include:

- **Authentication and RBAC** — JWT-based sessions with roles such as Super Admin, Admin, Pentester, and SOC Analyst.
- **Multi-tenancy** — organization-scoped data access (with controlled cross-tenant privileges for platform administrators).
- **Audit trails** — recording security-relevant actions for accountability.
- **Observability** — readiness/liveness-style health aggregation and Prometheus instrumentation for operational monitoring.

### 2.2.2 Distributed Task Queue and Docker Sandbox Execution

Long-running VA/PT activities are executed outside the API process via **Celery workers** consuming jobs from Redis. When an analyst creates or starts a scan, the API persists the scan record (status `pending`/`queued`) and enqueues a worker task. Workers update progress and terminal status (`running`, `completed`, `failed`) and attach errors when tools exit non-successfully. This design responds to SOAR literature calling for more holistic orchestration beyond single-layer tooling [4] and to closed-loop automation frameworks that separate decision/act stages from interactive services [5].

Third-party scanners (notably **Nmap** and **Nuclei**, with extension points for additional engines) are invoked through dedicated **tool wrappers**. Wrappers construct argument vectors programmatically rather than interpolating untrusted strings into a shell, reducing command-injection risk. In the reference architecture, scanner execution is isolated in **Dockerized worker/sandbox containers**, limiting filesystem and network blast radius relative to the API host and enabling reproducible tool availability checks. This separation ensures that interactive SOC operations (dashboard queries, status updates, AI triage calls) remain responsive while concurrent scans execute asynchronously.

Scheduled worker jobs additionally perform threat-intelligence synchronization and enrichment, keeping actively exploited / public-exploit indicators attached to findings without manual analyst refresh cycles, in line with evidence that exploit-oriented prioritization outperforms CVSS-only ranking [1], [2] and with enterprise threat-operations surveys emphasizing proactive, intelligence-driven defense [3].

### 2.2.3 Unified Normalization Parser Engine

Scanner outputs are heterogeneous (e.g., Nmap XML, Nuclei JSON, custom JSON). NexusSec therefore implements a **normalization pipeline** that:

1. Selects a parser based on source tool / content type (registry of parsers).
2. Converts raw tool artifacts into a **unified finding schema** (canonical fields such as title, description, severity, CWE/CVE, CVSS, affected component, port/protocol, evidence, source tool, and raw source payload).
3. Computes a stable **fingerprint** per asset–finding pair to support upsert semantics (deduplicate re-scans while refreshing `last_seen` timestamps).
4. Persists normalized vulnerabilities into PostgreSQL for SOC consumption.

This design treats multi-tool assessment as a single analytical stream: analysts interact with one finding model regardless of whether evidence originated from network discovery, template-based HTTP checks, or custom connectors. The unified JSON-oriented schema is also the substrate for compliance tagging, threat enrichment, AI remediation prompts, and ChatOps retrieval.

### 2.2.4 Compliance-Mapping Engine

During and after normalization, NexusSec attaches **compliance metadata** to findings so that technical risk and assurance evidence share one record. The mapping engine links vulnerabilities to:

- **ISO/IEC 27001:2022** — Annex A–oriented control references (e.g., management of technical vulnerabilities), stored as structured tags on each finding [12].
- **PCI DSS v4.0** — requirements associated with vulnerability management and testing (notably **Requirement 11** themes), complemented by asset-level **CDE scope** flags used in SOC queries and reports [13].
- **GDPR** — risk flags and tags highlighting potential personal-data confidentiality impact (e.g., PII leakage indicators), supporting privacy-oriented remediation prioritization under security-of-processing obligations [14].

Compliance report services aggregate active findings into auditor-oriented views (ISO, PCI-DSS, GDPR), while the SOC dashboard and ChatOps retrieval can filter CDE-scoped assets and compliance-tagged vulnerabilities. This closes the gap between scanner output and continuous compliance narratives without a separate offline spreadsheet mapping step [12]–[14].

### 2.2.5 AI Decision-Support Services

AI features are implemented as backend services that consume normalized finding/asset context and call **OpenAI-compatible LLM APIs** (configurable base URL and API key for providers such as Groq, OpenRouter, or OpenAI), with deterministic mock fallbacks for offline evaluation:

- **Remediation / patch generation** — produces explanation, mitigation steps, and secure patch or hardening examples grounded in CWE/description context, following peer-reviewed automated vulnerability-repair research while targeting SOC finding artifacts rather than only source repositories [8]–[10]; results persist to the vulnerability remediation field.
- **False-positive analysis** — returns structured confidence, likely-FP boolean, and analyst reasoning, stored in finding metadata for review dashboards, analogous to ML/transformer FP triage studied for DAST/SAST alerts [6], [7].
- **SOC ChatOps (lightweight RAG)** — classifies query intent, retrieves tenant-scoped rows from PostgreSQL (assets, scans, vulnerabilities), injects context into a system prompt, and returns concise operational answers with cited sources, comparable in spirit to RAG-driven SOC copilots [11].

These services are additive: they accelerate analyst workflows but do not replace RBAC, auditability, or human disposition of high-impact findings.

## 2.3 Architecture and Data-Flow Diagram

Figure 1 (ASCII) summarizes the end-to-end flow from scan execution through normalization, SOC presentation, and AI remediation.

```
                         +----------------------+
                         |  SOC Analyst / UI    |
                         |  (React Console)     |
                         +----------+-----------+
                                    |
                         HTTPS / JWT + RBAC
                                    |
                         +----------v-----------+
                         |  NexusSec API        |
                         |  FastAPI (async)     |
                         |  Tenancy · Audit     |
                         |  Dashboard · Reports |
                         +----+-----+-----+-----+
                              |     |     |
               create/start   |     |     |  AI remediation /
               scan, status   |     |     |  FP analysis / ChatOps
                              |     |     |
                              |     |     +----------->  LLM Provider
                              |     |                   (OpenAI-compatible
                              |     |                    AI_BASE_URL)
                              |     |
                              |     +----------------->  PostgreSQL
                              |                          (assets, scans,
                              |                           vulns, compliance,
                              |                           threat intel)
                              |
                    enqueue job (Redis/Celery)
                              |
                   +----------v-----------+
                   |  Celery Workers      |
                   |  (+ scanner sandbox) |
                   +----+-----------+-----+
                        |           |
              run Nmap / Nuclei     |  parse outputs
              (arg-safe wrappers)   |
                        |           |
                        v           v
                   +----+-----------+-----+
                   | Normalization Engine |
                   | parsers · fingerprint|
                   | compliance tagging   |
                   +----------+-----------+
                              |
                              v
                   +----------+-----------+
                   | PostgreSQL findings  |
                   +----------+-----------+
                              |
         +--------------------+--------------------+
         |                    |                    |
         v                    v                    v
  SOC Dashboard         Compliance Reports    AI Services
  (severity/risk)       (ISO / PCI / GDPR)    (patch · FP · RAG)
```

**Narrative flow.** (1) An authenticated analyst registers assets and starts a scan via the API. (2) The API records the job and publishes a Celery task. (3) A sandboxed worker executes the selected scanner through a secure wrapper and captures raw output. (4) The normalization engine converts tool-specific artifacts into the unified schema, applies fingerprints, and attaches ISO 27001 / PCI-DSS / GDPR metadata [12]–[14]. (5) Findings appear on the SOC dashboard and in compliance reports. (6) Optionally, the analyst invokes AI remediation or false-positive analysis, or asks ChatOps questions that retrieve live database context before generation [6]–[11]. Threat-intelligence workers enrich findings asynchronously to improve prioritization (e.g., actively exploited indicators) [1], [2].

This architecture directly supports the research objectives stated in the Introduction: isolating scan concurrency from API latency, guaranteeing a single normalized evidence model across tools, and enabling measurable AI-assisted remediation and triage on top of compliance-aware SOC data [3]–[5], [11].
