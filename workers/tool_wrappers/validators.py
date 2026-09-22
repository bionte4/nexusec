"""Validate scan targets to prevent command injection via crafted hosts."""

from __future__ import annotations

import ipaddress
import re

# FQDN: labels 1-63 chars, TLD alpha, total length <= 253
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)" r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+" r"[a-zA-Z]{2,63}$"
)


class TargetValidationError(ValueError):
    """Raised when a scan target fails validation."""


def validate_ip(value: str) -> str:
    raw = (value or "").strip()
    if not raw or any(ch.isspace() for ch in raw):
        raise TargetValidationError(f"Invalid IP address: {value!r}")
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError as exc:
        raise TargetValidationError(f"Invalid IP address: {value!r}") from exc


def validate_domain(value: str) -> str:
    raw = (value or "").strip().lower().rstrip(".")
    if not raw or "://" in raw or "/" in raw or any(ch.isspace() for ch in raw):
        raise TargetValidationError(f"Invalid domain: {value!r}")
    # Block shell / argv metacharacters
    if any(ch in raw for ch in ";|&$`<>\\\"'"):
        raise TargetValidationError(f"Invalid domain: {value!r}")
    if not _DOMAIN_RE.match(raw):
        raise TargetValidationError(f"Invalid domain: {value!r}")
    return raw


def validate_target(value: str) -> str:
    """Accept a single IPv4/IPv6 address or FQDN."""
    raw = (value or "").strip()
    if not raw:
        raise TargetValidationError("Target must not be empty")
    try:
        return validate_ip(raw)
    except TargetValidationError:
        return validate_domain(raw)


def validate_targets(values: list[str]) -> list[str]:
    if not values:
        raise TargetValidationError("At least one target is required")
    return [validate_target(v) for v in values]
