"""Orchestrate webhook + ticketing + SIEM for vulnerability events."""

from __future__ import annotations

from typing import Any, Optional
from uuid import UUID

from app.core.enums import FindingStatus, Severity
from app.integrations.common import finding_payload
from app.integrations.siem import SiemForwarder
from app.integrations.ticketing import TicketResult, sync_critical_ticket
from app.integrations.webhooks import WebhookNotifier


def build_finding_event(
    *,
    vulnerability_id: UUID,
    title: str,
    severity: Severity,
    status: FindingStatus,
    asset_id: UUID,
    asset_name: str,
    cve_id: Optional[str] = None,
    cwe_id: Optional[str] = None,
    cvss_score: Optional[float] = None,
    source_tool: Optional[str] = None,
    description: Optional[str] = None,
) -> dict[str, Any]:
    return finding_payload(
        vulnerability_id=vulnerability_id,
        title=title,
        severity=severity,
        status=status,
        asset_id=asset_id,
        asset_name=asset_name,
        cve_id=cve_id,
        cwe_id=cwe_id,
        cvss_score=cvss_score,
        source_tool=source_tool,
        description=description,
    )


def dispatch_integrations(
    finding: dict[str, Any],
    *,
    existing_ticket_key: Optional[str] = None,
    send_webhook: bool = True,
    sync_ticket: bool = True,
    forward_siem: bool = True,
) -> dict[str, Any]:
    """
    Synchronous dispatch used by Celery workers / API dry-runs.

    - Webhook: critical/high (configurable)
    - Ticket: critical + confirmed/open/in_progress
    - SIEM: always when enabled
    """
    result: dict[str, Any] = {"finding_id": finding.get("vulnerability_id")}

    if send_webhook:
        result["webhook"] = WebhookNotifier().send(finding)

    ticket: Optional[TicketResult] = None
    if sync_ticket:
        ticket = sync_critical_ticket(finding, existing_key=existing_ticket_key)
        result["ticket"] = {
            "provider": ticket.provider,
            "action": ticket.action,
            "key": ticket.key,
            "url": ticket.url,
            "error": ticket.error,
        }

    if forward_siem:
        result["siem"] = SiemForwarder().forward(finding)

    return result
