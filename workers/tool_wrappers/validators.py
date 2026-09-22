"""Validate scan targets to prevent command injection via crafted hosts."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

# FQDN: labels 1-63 chars, TLD alpha, total length <= 253
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)


class TargetValidationError(ValueError):
    """Raised when a scan target fails validation."""


def coerce_host(value: str) -> str:
    """
    Extract a bare host/IP from a user-supplied domain or URL.

    Accepts ``example.com``, ``https://example.com/path``, trailing slashes, etc.
    """
    raw = (value or "").strip()
    if not raw:
        raise TargetValidationError("Target must not be empty")
    if any(ch in raw for ch in ";|&$`<>\\\"'"):
        raise TargetValidationError(f"Invalid target: {value!r}")

    if "://" in raw or raw.startswith("//"):
        parsed = urlparse(raw if "://" in raw else f"https:{raw}")
        if not parsed.hostname:
            raise TargetValidationError(f"Invalid URL host: {value!r}")
        candidate = parsed.hostname
    else:
        # Strip path/query if pasted without scheme: example.com/path
        candidate = raw.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if "@" in candidate:
            candidate = candidate.rsplit("@", 1)[-1]
        if ":" in candidate and candidate.count(":") == 1:
            host_part, _, port_part = candidate.partition(":")
            if port_part.isdigit():
                candidate = host_part

    candidate = candidate.strip().lower().rstrip(".")
    if not candidate or any(ch.isspace() for ch in candidate):
        raise TargetValidationError(f"Invalid target: {value!r}")
    return candidate


def validate_ip(value: str) -> str:
    try:
        raw = coerce_host(value)
    except TargetValidationError:
        raw = (value or "").strip()
    if not raw or any(ch.isspace() for ch in raw):
        raise TargetValidationError(f"Invalid IP address: {value!r}")
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError as exc:
        raise TargetValidationError(f"Invalid IP address: {value!r}") from exc


def validate_domain(value: str) -> str:
    raw = coerce_host(value)
    if any(ch in raw for ch in ";|&$`<>\\\"'"):
        raise TargetValidationError(f"Invalid domain: {value!r}")
    if not _DOMAIN_RE.match(raw):
        raise TargetValidationError(f"Invalid domain: {value!r}")
    return raw


def validate_target(value: str) -> str:
    """Accept a single IPv4/IPv6 address or FQDN (URL wrappers are stripped)."""
    raw = (value or "").strip()
    if not raw:
        raise TargetValidationError("Target must not be empty")
    host = coerce_host(raw)
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return validate_domain(host)


def validate_targets(values: list[str]) -> list[str]:
    if not values:
        raise TargetValidationError("At least one target is required")
    return [validate_target(v) for v in values]
