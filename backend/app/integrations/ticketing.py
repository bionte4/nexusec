"""Ticketing providers — create/update issues for critical findings."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Optional

import httpx

from app.core.config import get_settings

logger = logging.getLogger(__name__)


@dataclass
class TicketResult:
    provider: str
    action: str  # created | updated | skipped
    key: Optional[str] = None
    url: Optional[str] = None
    raw: Optional[dict[str, Any]] = None
    error: Optional[str] = None


class TicketClient(ABC):
    provider: str

    @abstractmethod
    def create_or_update(
        self, finding: dict[str, Any], *, existing_key: Optional[str] = None
    ) -> TicketResult:
        raise NotImplementedError


class NullTicketClient(TicketClient):
    provider = "none"

    def create_or_update(
        self, finding: dict[str, Any], *, existing_key: Optional[str] = None
    ) -> TicketResult:
        return TicketResult(provider=self.provider, action="skipped", error="ticketing disabled")


class JiraTicketClient(TicketClient):
    provider = "jira"

    def __init__(self) -> None:
        settings = get_settings()
        self.base_url = settings.jira_base_url.rstrip("/")
        self.email = settings.jira_email
        self.token = settings.jira_api_token
        self.project_key = settings.jira_project_key
        self.issue_type = settings.jira_issue_type

    def create_or_update(
        self, finding: dict[str, Any], *, existing_key: Optional[str] = None
    ) -> TicketResult:
        if not (self.base_url and self.email and self.token):
            return TicketResult(
                provider=self.provider, action="skipped", error="jira not configured"
            )

        auth = (self.email, self.token)
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        summary = f"[NexuSec][{finding.get('severity', '').upper()}] {finding.get('title')}"
        description = (
            f"Asset: {finding.get('asset_name')}\n"
            f"Severity: {finding.get('severity')}\n"
            f"CVE: {finding.get('cve_id') or 'n/a'}\n"
            f"CWE: {finding.get('cwe_id') or 'n/a'}\n"
            f"Vulnerability ID: {finding.get('vulnerability_id')}\n"
            f"Status: {finding.get('status')}\n\n"
            f"{finding.get('description') or ''}"
        )

        with httpx.Client(timeout=20.0) as client:
            if existing_key:
                resp = client.put(
                    f"{self.base_url}/rest/api/3/issue/{existing_key}",
                    auth=auth,
                    headers=headers,
                    json={
                        "fields": {
                            "summary": summary,
                            "description": _jira_adf(description),
                        }
                    },
                )
                if 200 <= resp.status_code < 300:
                    return TicketResult(
                        provider=self.provider,
                        action="updated",
                        key=existing_key,
                        url=f"{self.base_url}/browse/{existing_key}",
                    )
                return TicketResult(
                    provider=self.provider,
                    action="updated",
                    key=existing_key,
                    error=f"HTTP {resp.status_code}",
                )

            resp = client.post(
                f"{self.base_url}/rest/api/3/issue",
                auth=auth,
                headers=headers,
                json={
                    "fields": {
                        "project": {"key": self.project_key},
                        "summary": summary,
                        "description": _jira_adf(description),
                        "issuetype": {"name": self.issue_type},
                        "labels": ["nexusec", "vulnerability", str(finding.get("severity"))],
                    }
                },
            )
            if resp.status_code not in {200, 201}:
                return TicketResult(
                    provider=self.provider,
                    action="created",
                    error=f"HTTP {resp.status_code}: {resp.text[:200]}",
                )
            data = resp.json()
            key = data.get("key")
            return TicketResult(
                provider=self.provider,
                action="created",
                key=key,
                url=f"{self.base_url}/browse/{key}" if key else None,
                raw={"id": data.get("id"), "key": key},
            )


class ServiceNowTicketClient(TicketClient):
    provider = "servicenow"

    def __init__(self) -> None:
        settings = get_settings()
        self.base_url = settings.servicenow_instance_url.rstrip("/")
        self.username = settings.servicenow_username
        self.password = settings.servicenow_password
        self.table = settings.servicenow_table

    def create_or_update(
        self, finding: dict[str, Any], *, existing_key: Optional[str] = None
    ) -> TicketResult:
        if not (self.base_url and self.username and self.password):
            return TicketResult(
                provider=self.provider,
                action="skipped",
                error="servicenow not configured",
            )

        auth = (self.username, self.password)
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        short_description = (
            f"[NexuSec][{str(finding.get('severity', '')).upper()}] {finding.get('title')}"
        )
        description = (
            f"Asset: {finding.get('asset_name')}\n"
            f"Vulnerability ID: {finding.get('vulnerability_id')}\n"
            f"CVE: {finding.get('cve_id') or 'n/a'}\n"
            f"{finding.get('description') or ''}"
        )
        payload = {
            "short_description": short_description[:160],
            "description": description,
            "urgency": "1" if finding.get("severity") == "critical" else "2",
            "impact": "1" if finding.get("severity") == "critical" else "2",
            "category": "Security",
            "subcategory": "Vulnerability",
        }

        with httpx.Client(timeout=20.0) as client:
            if existing_key:
                resp = client.patch(
                    f"{self.base_url}/api/now/table/{self.table}/{existing_key}",
                    auth=auth,
                    headers=headers,
                    json=payload,
                )
                if 200 <= resp.status_code < 300:
                    return TicketResult(
                        provider=self.provider,
                        action="updated",
                        key=existing_key,
                        url=f"{self.base_url}/nav_to.do?uri={self.table}.do?sys_id={existing_key}",
                    )
                return TicketResult(
                    provider=self.provider,
                    action="updated",
                    key=existing_key,
                    error=f"HTTP {resp.status_code}",
                )

            resp = client.post(
                f"{self.base_url}/api/now/table/{self.table}",
                auth=auth,
                headers=headers,
                json=payload,
            )
            if resp.status_code not in {200, 201}:
                return TicketResult(
                    provider=self.provider,
                    action="created",
                    error=f"HTTP {resp.status_code}: {resp.text[:200]}",
                )
            result = resp.json().get("result") or {}
            sys_id = result.get("sys_id")
            number = result.get("number")
            return TicketResult(
                provider=self.provider,
                action="created",
                key=sys_id,
                url=(
                    f"{self.base_url}/nav_to.do?uri={self.table}.do?sys_id={sys_id}"
                    if sys_id
                    else None
                ),
                raw={"sys_id": sys_id, "number": number},
            )


def get_ticket_client() -> TicketClient:
    settings = get_settings()
    if not settings.ticket_enabled:
        return NullTicketClient()
    provider = settings.ticket_provider.lower()
    if provider == "jira":
        return JiraTicketClient()
    if provider == "servicenow":
        return ServiceNowTicketClient()
    return NullTicketClient()


_SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
    "unknown": 0,
}


def sync_ticket(
    finding: dict[str, Any], *, existing_key: Optional[str] = None
) -> TicketResult:
    """Create/update a ticket when finding meets configured severity/status gates."""
    settings = get_settings()
    sev = str(finding.get("severity", "")).lower()
    min_sev = (settings.ticket_min_severity or "critical").lower()
    if _SEVERITY_RANK.get(sev, 0) < _SEVERITY_RANK.get(min_sev, 4):
        return TicketResult(
            provider=settings.ticket_provider,
            action="skipped",
            error=f"severity below ticket_min_severity ({min_sev})",
        )
    if str(finding.get("status", "")).lower() not in {
        "confirmed",
        "open",
        "in_progress",
        "reopened",
        "remediated",
    }:
        return TicketResult(
            provider=settings.ticket_provider,
            action="skipped",
            error="status not eligible for ticketing",
        )
    return get_ticket_client().create_or_update(finding, existing_key=existing_key)


def sync_critical_ticket(
    finding: dict[str, Any], *, existing_key: Optional[str] = None
) -> TicketResult:
    """Backward-compatible alias for sync_ticket."""
    return sync_ticket(finding, existing_key=existing_key)


def _jira_adf(text: str) -> dict[str, Any]:
    """Minimal Atlassian Document Format paragraph."""
    return {
        "type": "doc",
        "version": 1,
        "content": [
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": text[:5000]}],
            }
        ],
    }
