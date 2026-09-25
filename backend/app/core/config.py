"""Integration settings — webhooks, ticketing, SIEM (no secrets in code)."""

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "NexuSec"
    app_env: str = "development"
    debug: bool = False
    api_v1_prefix: str = "/api/v1"
    secret_key: str = Field(default="insecure-dev-key-change-me", min_length=8)

    # JWT
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7

    database_url: str = "postgresql+asyncpg://nexusec:nexusec_dev_password@localhost:5432/nexusec"

    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"

    cors_origins: str = "http://localhost:3000,http://localhost:5173"

    # --- Integrations (Prompt 7) ---
    webhook_enabled: bool = False
    webhook_urls: str = ""  # comma-separated
    webhook_provider: str = "generic"  # generic | slack | teams
    webhook_min_severity: str = "high"  # high | critical

    # Daily / periodic SOC digest (overdue + critical/high summary)
    digest_enabled: bool = True
    digest_interval_hours: int = 24
    digest_send_when_empty: bool = False

    ticket_provider: str = "none"  # none | jira | servicenow
    ticket_enabled: bool = False
    ticket_min_severity: str = "critical"  # critical | high | medium
    jira_base_url: str = ""
    jira_email: str = ""
    jira_api_token: str = ""
    jira_project_key: str = "SEC"
    jira_issue_type: str = "Bug"

    servicenow_instance_url: str = ""
    servicenow_username: str = ""
    servicenow_password: str = ""
    servicenow_table: str = "incident"

    siem_enabled: bool = False
    siem_format: str = "json"  # json | cef
    siem_webhook_url: str = ""  # HTTP collector (Elastic/Splunk HEC-compatible JSON)
    siem_hec_token: str = ""

    # --- Threat intelligence (Prompt 11) ---
    kev_catalog_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    nvd_api_key: str = ""  # optional — higher NVD rate limits
    nvd_rate_limit_sleep: float = 0.65
    threat_intel_sync_enabled: bool = True
    threat_intel_kev_interval_hours: int = 6
    threat_intel_enrich_interval_hours: int = 1
    epss_api_url: str = "https://api.first.org/data/v1/epss"
    epss_enabled: bool = True
    epss_timeout_seconds: float = 20.0

    # --- Remediation SLA (days from first open / status re-open) ---
    sla_days_critical: int = 7
    sla_days_high: int = 14
    sla_days_medium: int = 30
    sla_days_low: int = 90
    sla_days_info: int = 180

    # --- Auto-retest when finding marked remediated ---
    auto_retest_enabled: bool = True
    auto_retest_engine: str = "nuclei"  # nmap | nuclei | nexusec
    auto_retest_scan_type: str = "va"

    # --- Observability (Prompt 13) ---
    health_check_timeout_seconds: float = 3.0
    docker_socket_path: str = "/var/run/docker.sock"
    worker_hang_threshold_minutes: int = 45
    prometheus_metrics_enabled: bool = True

    # --- AI remediation (Prompt 14 / 17) ---
    ai_remediation_enabled: bool = True
    ai_remediation_provider: str = "auto"  # auto | openai | mock
    ai_remediation_fallback_mock: bool = True
    ai_remediation_timeout_seconds: float = 60.0
    # OpenAI-compatible free providers (Groq, OpenRouter, …) — Prompt 17
    ai_api_key: str = ""  # AI_API_KEY
    ai_base_url: str = ""  # AI_BASE_URL e.g. https://api.groq.com/openai/v1
    ai_model: str = ""  # AI_MODEL e.g. llama-3.3-70b-versatile
    ai_force_json_response: bool = False  # set true if provider supports response_format

    # --- AI false-positive analysis (Prompt 15) ---
    ai_fp_enabled: bool = True
    ai_fp_provider: str = "auto"  # auto | openai | anthropic | mock
    ai_fp_fallback_mock: bool = True
    ai_fp_timeout_seconds: float = 60.0

    # --- AI SOC ChatOps / RAG (Prompt 16) ---
    ai_soc_chat_enabled: bool = True
    ai_soc_chat_provider: str = "auto"  # auto | openai | anthropic | mock
    ai_soc_chat_fallback_mock: bool = True
    ai_soc_chat_timeout_seconds: float = 90.0
    ai_soc_chat_retrieval_limit: int = 25
    ai_soc_chat_max_sources: int = 40
    ai_soc_chat_max_query_chars: int = 4000

    # Shared / legacy LLM credentials (Prompts 14–16; still used by FP + ChatOps)
    openai_api_key: str = ""
    openai_api_base: str = "https://api.openai.com/v1"
    openai_model: str = "gpt-4o-mini"
    anthropic_api_key: str = ""
    anthropic_api_base: str = "https://api.anthropic.com"
    anthropic_model: str = "claude-3-5-haiku-latest"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def webhook_url_list(self) -> list[str]:
        return [u.strip() for u in self.webhook_urls.split(",") if u.strip()]

    @property
    def sync_database_url(self) -> str:
        """Alembic / sync drivers need psycopg URL, not asyncpg."""
        return self.database_url.replace("postgresql+asyncpg://", "postgresql+psycopg://")


@lru_cache
def get_settings() -> Settings:
    return Settings()
