"""Remediation SLA helpers — due dates from severity policy."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from app.core.config import Settings, get_settings
from app.core.enums import Severity


def sla_days_for_severity(
    severity: Severity,
    settings: Optional[Settings] = None,
) -> int:
    s = settings or get_settings()
    mapping = {
        Severity.CRITICAL: s.sla_days_critical,
        Severity.HIGH: s.sla_days_high,
        Severity.MEDIUM: s.sla_days_medium,
        Severity.LOW: s.sla_days_low,
        Severity.INFO: s.sla_days_info,
        Severity.UNKNOWN: s.sla_days_medium,
    }
    return max(1, int(mapping.get(severity, s.sla_days_medium)))


def compute_remediation_due_at(
    severity: Severity,
    *,
    from_time: Optional[datetime] = None,
    settings: Optional[Settings] = None,
) -> datetime:
    base = from_time or datetime.now(timezone.utc)
    if base.tzinfo is None:
        base = base.replace(tzinfo=timezone.utc)
    return base + timedelta(days=sla_days_for_severity(severity, settings))
