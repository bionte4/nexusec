# Role & Context
You are a Principal Security Software Engineer, System Architect, and Expert in Cybersecurity Platform Development. We are building an enterprise-grade Vulnerability Assessment (VA), Penetration Testing (PT), and Security Operations Center (SOC) Orchestration Platform from scratch.

The platform uses a hybrid approach:
1. A custom-built high-performance scanner engine.
2. An orchestration layer that wraps and manages third-party security tools (e.g., Nmap, Nuclei, OpenVAS).
3. A centralized SOC dashboard for real-time monitoring, correlation, and remediation tracking.

# Technical Stack
- **Backend Core / API:** Python (FastAPI) with strict async patterns and type hinting.
- **Scanner Engine / Workers:** Go or Python (asyncio) for high-performance concurrent processing.
- **Database & State:** PostgreSQL (Primary storage with a normalized vulnerability schema) and Redis (Caching & real-time message broker).
- **Task Queue:** Celery or Redis Queue (RQ) for handling long-running, distributed scan jobs.
- **Infrastructure / Isolation:** Docker-based sandbox execution for all scanning tools.

# Compliance, Frameworks & Taxonomies
The platform must natively support and map findings to:
- **Standards:** ISO 27001 (Annex A), PCI-DSS (Req 11), and GDPR (PII / Data Leakage Risks).
- **Frameworks & Taxonomies:** NIST CSF, OWASP Top 10 / ASVS, CWE, CVSS v3.1, and MITRE ATT&CK.

# Security & Code Quality Mandates (Secure-by-Design)
1. **Never use unsafe command execution:** When wrapping CLI tools (like Nmap or Nuclei), strictly sanitize inputs, avoid raw shell=True command injection vulnerabilities, and use safe array-based process execution.
2. **Data Sanitization & Normalization:** All scanner outputs (custom or third-party) must be parsed into a unified JSON schema before database ingestion.
3. **RBAC & Audit Trail:** Every action must support Role-Based Access Control and generate immutable audit logs.
4. **No Hardcoded Secrets:** Use secure configuration and environment variables.

# Your Immediate Task
To kick off the development, please provide:
1. The recommended project folder structure (monorepo or well-separated microservices architecture) adhering to the tech stack above.
2. The initial database schema design (SQL migration draft/SQLAlchemy models) focusing on Users, Assets, Scans, and a normalized Vulnerability table that includes compliance tags (ISO, PCI-DSS, GDPR, CWE, CVSS).

Let's build this module by module, starting with the core architecture and backend foundation.

### Prompt 1
Task: Create the initial project structure and database models.
1. Create a clean monorepo structure separating:
   - /backend (FastAPI core API)
   - /workers (Celery background tasks & tool wrappers)
   - /scanners (Custom scanner engine or wrappers)
   - /database (SQLAlchemy migrations / Alembic)
2. Implement PostgreSQL database models using SQLAlchemy with strict typing for:
   - Users & RBAC Roles (Admin, Pentester, SOC Analyst)
   - Assets (IP, Domain, Cloud Resource, CDE Scope flag for PCI-DSS)
   - Scans (Scan metadata, target, status, timestamps)
   - Vulnerabilities (Normalized fields: title, severity, CVSS v3.1, CWE ID, status, and JSON metadata for compliance tags like ISO 27001, PCI-DSS, GDPR).
3. Provide the setup code for database connection and a base Alembic migration configuration.

### Prompt 2
Task: Implement Authentication, RBAC, and Audit Logging in FastAPI.
1. Implement secure JWT-based authentication (access & refresh tokens).
2. Create a Role-Based Access Control (RBAC) dependency decorator ensuring endpoints restrict access based on roles (Admin, Pentester, SOC Analyst).
3. Implement an Audit Trail middleware/logger that automatically records every critical state-changing HTTP request (who, what, when, IP address, status code) into an immutable audit log table or log file.
4. Write unit tests for authentication and permission boundaries.

### Prompt 3
Task: Set up Celery Background Workers and a Secure Tool Execution Wrapper.
1. Configure Celery with Redis as the message broker and result backend for asynchronous, long-running security scan jobs.
2. Build a secure execution wrapper service for external CLI tools (e.g., Nmap, Nuclei) inside Python. 
   - CRITICAL SECURITY REQUIREMENT: Never use `shell=True`. Use safe array-based process execution (e.g., `subprocess.run` with list arguments) to completely prevent command injection.
   - Implement proper input validation/sanitization for scan targets (IP/Domain regex checks).
   - Add timeout and resource limitation handling for hanging subprocesses.
3. Provide a sample task that triggers an asynchronous Nmap scan job and updates its status in the PostgreSQL database.

### Prompt 4
Task: Build the Unified Vulnerability Normalization & Parsing Engine.
1. Create a modular parsing system that converts raw outputs from different scanners (e.g., custom scanner, Nmap XML, Nuclei JSON output) into a single, unified JSON vulnerability schema.
2. The normalized schema must include:
   - Standard fields: `vuln_id`, `name`, `description`, `severity`, `cvss_score`, `cwe_id`.
   - Context mapping fields: `mitre_tactics` (MITRE ATT&CK mapping), `remediation_steps`.
   - Compliance mapping tags: `iso_27001_clause`, `pci_dss_requirement`, `gdpr_risk_flag`.
3. Implement a database ingestion service that saves these normalized findings securely, preventing duplicate entries for the same asset.

### Prompt 5
Task: Build SOC Dashboard and Remediation Tracker API Endpoints.
1. Create FastAPI endpoints to aggregate real-time metrics for the SOC dashboard:
   - Total active vulnerabilities by severity (Critical, High, Medium, Low).
   - Asset risk posture summary.
   - Trend analysis of open vs. resolved vulnerabilities over time.
2. Create lifecycle management endpoints for vulnerabilities:
   - Update vulnerability status (`Open`, `In Progress`, `False Positive`, `Resolved`).
   - Assign remediation owners and add tracking notes/comments.
3. Ensure all endpoints are fully protected by the RBAC system built earlier.

### Prompt 6
Task: Implement the Compliance and Audit-Ready Reporting Engine.
1. Build a report generation service that compiles vulnerability data into structured compliance summaries.
2. Implement endpoints to generate specific report views/exports (JSON or PDF-ready data structure) tailored for:
   - **ISO 27001 Audit** (mapping findings to Annex A technical controls).
   - **PCI-DSS Compliance** (focusing on Req 11 vulnerability assessment & CDE asset scope).
   - **GDPR Assessment** (highlighting data leakage risks and PII exposure points).
3. Include clear metadata in the reports: generation timestamp, auditor/user name, and total scope covered.

### Prompt 7
Task: Implement SIEM/SOAR integration, Webhook alerts, and Ticketing sync.
1. Create a notification service that sends critical or high-severity vulnerability alerts via Webhooks (compatible with Slack, Microsoft Teams, or custom endpoints).
2. Implement an automated ticketing integration module:
   - Automatically create/update tickets in Jira or ServiceNow when a new critical vulnerability is confirmed.
3. Build a SIEM forwarding service that exports normalized vulnerability logs in CEF (Common Event Format) or JSON syslog format to external SIEM tools (e.g., Elastic, Splunk).

### Prompt 8
Task: Build the High-Performance Custom Scanner Engine.
1. Create a dedicated module in Python (using `asyncio`) or Go for a custom lightweight asset/port/vulnerability scanner.
2. Implement strict safety mechanisms:
   - Rate limiting and throttling logic to prevent overwhelming target assets.
   - Built-in circuit breakers and target exclusion lists.
3. Ensure the output from this custom engine strictly follows the unified JSON normalization schema created previously so it can be ingested smoothly by the backend API.

### Prompt 9
Task: Generate Frontend Dashboard components and views (React with Vite, Tailwind CSS, and Lucide icons).
1. Create a clean, dark-mode focused SOC Dashboard layout (ideal for security operations rooms):
   - Summary cards (Total Assets, Open Critical/High Vulnerabilities, Compliance Status).
   - Real-time vulnerability trends chart (using Recharts or Chart.js).
2. Build a Vulnerability Management Table view with filtering (by severity, status, asset, compliance tag).
3. Build a Detailed Vulnerability View page showing mitigation steps, CWE descriptions, and remediation owner assignment options.

## prompt 10
Task: Prepare Docker setup, Security Hardening, and CI/CD Automation.
1. Create optimized `Dockerfile` and `docker-compose.yml` files for the entire stack:
   - Services: FastAPI backend, Celery workers, Redis, PostgreSQL, and isolated scanner worker containers.
2. Implement security hardening measures in configuration:
   - Non-root user execution inside containers.
   - Secure environment variable handling (`.env`).
3. Create a GitHub Actions CI/CD workflow (`.github/workflows/ci.yml`) that runs automated unit tests, linter checks (Flake8/Black), and security vulnerability checks on code commits.

### prompt 11
Task: Implement Threat Intelligence Enrichment (CISA KEV & NVD Integration).
1. Build a background background sync service (Celery periodic task) that periodically fetches the latest Known Exploited Vulnerabilities (KEV) catalog from CISA and NVD feeds.
2. Implement an automated scoring enrichment engine:
   - Check if any newly discovered vulnerability in the database matches active CVEs in the CISA KEV list or has public exploits available.
   - Automatically boost the risk priority or add a specific "Actively Exploited" flag to the vulnerability schema, aligning with Risk-Based Vulnerability Management (RBVM).
3. Create an API endpoint to view the threat intelligence enrichment status and list vulnerabilities currently under active cyber attack threats.

## prompt 12
Task: Implement Multi-Tenancy and Organization Scope Architecture.
1. Update the database models to support strict multi-tenancy (`Organization` or `Tenant` table).
2. Ensure all primary entities (Assets, Scans, Vulnerabilities, Users, Audit Logs) are tied to a specific `organization_id`.
3. Implement database query filters or middleware ensuring users can only access data belonging to their authorized organization (unless they hold a Super Admin cross-tenant role).
4. Create tenant management endpoints for Admins to onboard new clients, manage isolated workspace tokens, and view tenant-specific security metrics.

### Prompt 13
Task: Implement Platform Observability, Health Checks, and Prometheus Metrics.
1. Create health-check endpoints (`/health`) that monitor the status of core dependencies: PostgreSQL connection, Redis broker, Celery worker responsiveness, and active Docker sandbox daemon.
2. Implement Prometheus metrics instrumentation (using `prometheus-fastapi-instrumentator`) to expose backend performance metrics (request latency, error rates, active scans count).
3. Build a worker node status monitor to track whether custom scanners or third-party wrappers (Nmap, Nuclei) are hanging or failing due to resource exhaustion.

### Prompt 14
Task: Implement an AI-powered Vulnerability Remediation and Patch Generator Service.
1. Create a service module in backend/app/services/ai_remediation.py that integrates with an LLM API (support OpenAI or Anthropic SDK, with fallback configuration via environment variables).
2. The service should accept vulnerability details (title, description, cwe_id, severity, and affected asset type) and prompt the LLM to generate:
   - A clear explanation of why the vulnerability occurs.
   - Step-by-step secure remediation guidance.
   - A secure code snippet/patch example tailored to the context.
3. Update the vulnerability lifecycle or create an API endpoint (POST /api/v1/vulnerabilities/{id}/generate-ai-patch) that triggers this generation and automatically saves the AI response to the vulnerability's remediation field.

### Prompt 15
Task: Implement an AI-Driven False Positive Analysis Engine.
1. Create a service module in backend/app/services/ai_filter.py that evaluates scan outputs and asset context.
2. Build an API endpoint (POST /api/v1/vulnerabilities/{id}/analyze-fp) that sends the vulnerability context, port details, and banner info to an LLM.
3. The LLM should return a structured JSON response containing:
   - `confidence_score` (float between 0 and 1)
   - `is_likely_false_positive` (boolean)
   - `reasoning` (brief explanation for the SOC analyst)
4. Save this AI evaluation metadata into the vulnerability record or display it on the review dashboard.

### prompt 16
Task: Build an AI SOC ChatOps / RAG Assistant API.
1. Create an API endpoint (POST /api/v1/soc/chat) that accepts a natural language query from a SOC analyst (e.g., "Which assets currently violate PCI-DSS requirements?" or "Summarize critical vulnerabilities this week").
2. Implement a lightweight RAG (Retrieval-Augmented Generation) pipeline:
   - Fetch relevant assets, scan summaries, and vulnerabilities from the PostgreSQL database based on keywords in the query.
   - Inject this database context into a system prompt for the LLM.
3. Return a concise, professional security summary and actionable answers back to the analyst via the API.

### Prompt 17
Task: Implement External Free LLM API Integration for AI-Powered Vulnerability Remediation in FastAPI.

1. Create a service module in `backend/app/services/ai_remediation.py` using the standard `openai` Python SDK package. Configure it to be compatible with external free LLM providers (such as Groq or OpenRouter) by supporting customizable environment variables: `AI_API_KEY` and `AI_BASE_URL`.

2. Implement a core function `generate_ai_remediation_patch(cwe_id: str, description: str) -> str` that:
   - Sends a structured prompt to the LLM.
   - Instructs the model to act as a secure coding assistant for a SOC platform.
   - Requests a clear explanation of the vulnerability, step-by-step mitigation guidance, and a secure code patch snippet.

3. Create a FastAPI endpoint (`POST /api/v1/vulnerabilities/{vulnerability_id}/generate-ai-patch`) that:
   - Fetches the vulnerability details from the database using SQLAlchemy.
   - Calls the `generate_ai_remediation_patch` service function.
   - Saves the generated AI response into the vulnerability's remediation field and returns the result to the client.

4. Ensure robust error handling (e.g., catching API rate-limit errors or connection timeouts gracefully) and update `.env.example` to include `AI_API_KEY` and `AI_BASE_URL`.



