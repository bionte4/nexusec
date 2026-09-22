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

    ticket_provider: str = "none"  # none | jira | servicenow
    ticket_enabled: bool = False
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
