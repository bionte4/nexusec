"""Shared helpers for integration payloads."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional
from uuid import UUID

from app.core.enums import FindingStatus, Severity


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def finding_payload(
    *,
    vulnerability_id: UUID,
    title: str,
    severity: Severity | str,
    status: FindingStatus | str,
    asset_name: str,
    asset_id: UUID,
    cve_id: Optional[str] = None,
    cwe_id: Optional[str] = None,
    cvss_score: Optional[float] = None,
    source_tool: Optional[str] = None,
    description: Optional[str] = None,
) -> dict[str, Any]:
    sev = severity.value if isinstance(severity, Severity) else str(severity)
    st = status.value if isinstance(status, FindingStatus) else str(status)
    return {
        "vulnerability_id": str(vulnerability_id),
        "title": title,
        "severity": sev,
        "status": st,
        "asset_id": str(asset_id),
        "asset_name": asset_name,
        "cve_id": cve_id,
        "cwe_id": cwe_id,
        "cvss_score": cvss_score,
        "source_tool": source_tool,
        "description": description,
        "event_time": utc_now_iso(),
        "product": "NexuSec",
    }


def severity_rank(severity: Severity | str) -> int:
    order = {
        "info": 0,
        "unknown": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }
    key = severity.value if isinstance(severity, Severity) else str(severity).lower()
    return order.get(key, 0)
