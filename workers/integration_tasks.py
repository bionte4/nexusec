"""Celery tasks for SIEM/SOAR integrations."""

from __future__ import annotations

import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy.orm import selectinload

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.integrations import build_finding_event, dispatch_integrations  # noqa: E402
from app.models.vulnerability import Vulnerability  # noqa: E402
from workers.celery_app import celery_app  # noqa: E402
from workers.db import session_scope  # noqa: E402

logger = logging.getLogger(__name__)


@celery_app.task(name="integrations.dispatch_finding", bind=True, max_retries=2)
def dispatch_finding_integrations(
    self,
    vulnerability_id: str,
    *,
    send_webhook: bool = True,
    sync_ticket: bool = True,
    forward_siem: bool = True,
) -> dict[str, Any]:
    """Load finding from DB and dispatch webhook / ticket / SIEM."""
    try:
        vuln_uuid = UUID(vulnerability_id)
    except ValueError:
        return {"ok": False, "error": "invalid vulnerability_id"}

    with session_scope() as session:
        vuln = (
            session.query(Vulnerability)
            .options(selectinload(Vulnerability.asset))
            .filter(Vulnerability.id == vuln_uuid)
            .one_or_none()
        )
        if vuln is None:
            return {"ok": False, "error": "vulnerability not found"}

        asset_name = vuln.asset.name if vuln.asset is not None else str(vuln.asset_id)
        event = build_finding_event(
            vulnerability_id=vuln.id,
            title=vuln.title,
            severity=vuln.severity,
            status=vuln.status,
            asset_id=vuln.asset_id,
            asset_name=asset_name,
            cve_id=vuln.cve_id,
            cwe_id=vuln.cwe_id,
            cvss_score=vuln.cvss_score,
            source_tool=vuln.source_tool,
            description=vuln.description,
        )
        result = dispatch_integrations(
            event,
            existing_ticket_key=vuln.external_ticket_key,
            send_webhook=send_webhook,
            sync_ticket=sync_ticket,
            forward_siem=forward_siem,
        )

        ticket = result.get("ticket") or {}
        if ticket.get("key"):
            vuln.external_ticket_system = ticket.get("provider")
            vuln.external_ticket_key = ticket.get("key")
            vuln.external_ticket_url = ticket.get("url")
        if send_webhook and not (result.get("webhook") or [{}])[0].get("skipped"):
            vuln.last_alerted_at = datetime.now(timezone.utc)
        session.add(vuln)

        result["ok"] = True
        return result


@celery_app.task(name="integrations.forward_siem_batch")
def forward_siem_batch(vulnerability_ids: list[str]) -> dict[str, Any]:
    outcomes = []
    for vid in vulnerability_ids:
        outcomes.append(
            dispatch_finding_integrations(
                vid, send_webhook=False, sync_ticket=False, forward_siem=True
            )
        )
    return {"count": len(outcomes), "results": outcomes}
