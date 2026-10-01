"""Shared severity string / numeric → Severity enum mapping."""

from __future__ import annotations

from app.core.enums import Severity

_TEXT = {
    "critical": Severity.CRITICAL,
    "crit": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "med": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "note": Severity.INFO,
    "none": Severity.INFO,
    "unknown": Severity.UNKNOWN,
    # SARIF levels
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    # Burp
    "severe": Severity.HIGH,
    "firm": Severity.MEDIUM,
    "tentative": Severity.LOW,
}

# Nessus plugin severity 0–4
_NESSUS_NUMERIC = {
    0: Severity.INFO,
    1: Severity.LOW,
    2: Severity.MEDIUM,
    3: Severity.HIGH,
    4: Severity.CRITICAL,
}

# Trivy often uses UNKNOWN/LOW/MEDIUM/HIGH/CRITICAL
_TRIVY_NUMERIC = {
    0: Severity.UNKNOWN,
    1: Severity.LOW,
    2: Severity.MEDIUM,
    3: Severity.HIGH,
    4: Severity.CRITICAL,
}


def map_severity(raw: object, *, default: Severity = Severity.UNKNOWN) -> Severity:
    if raw is None or raw == "":
        return default
    if isinstance(raw, bool):
        return default
    if isinstance(raw, (int, float)):
        n = int(raw)
        if n in _NESSUS_NUMERIC and 0 <= n <= 4:
            return _NESSUS_NUMERIC[n]
        return default
    text = str(raw).strip().lower()
    if text.isdigit():
        return map_severity(int(text), default=default)
    return _TEXT.get(text, default)
