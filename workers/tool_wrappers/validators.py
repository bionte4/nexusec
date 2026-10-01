"""Validate scan targets to prevent command injection via crafted hosts."""

from __future__ import annotations

import ipaddress
import os
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


def block_private_targets() -> bool:
    """Block RFC1918 / loopback / link-local / cloud metadata targets.

    Default ON in production; override with SCAN_BLOCK_PRIVATE_TARGETS=true|false.
    """
    explicit = (os.getenv("SCAN_BLOCK_PRIVATE_TARGETS") or "").strip().lower()
    if explicit in {"1", "true", "yes", "on"}:
        return True
    if explicit in {"0", "false", "no", "off"}:
        return False
    return (os.getenv("APP_ENV") or "development").lower() in {"production", "prod"}


def _reject_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, *, original: str) -> None:
    if not block_private_targets():
        return
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        raise TargetValidationError(
            f"Target {original!r} resolves to a blocked address class "
            "(private/loopback/link-local). Set SCAN_BLOCK_PRIVATE_TARGETS=false for lab LAN scans."
        )
    # AWS/GCP/Azure metadata link-local is already link_local; also catch 169.254.169.254 explicitly
    if str(ip) in {"169.254.169.254", "fd00:ec2::254"}:
        raise TargetValidationError(f"Cloud metadata address blocked: {original!r}")


def _reject_blocked_hostname(host: str) -> None:
    lowered = host.lower().rstrip(".")
    # Always block localhost + cloud metadata hostnames (SSRF classics)
    always = {
        "localhost",
        "localhost.localdomain",
        "metadata.google.internal",
        "metadata.google.com",
        "kubernetes.default",
        "kubernetes.default.svc",
    }
    if lowered in always or lowered.endswith(".localhost"):
        raise TargetValidationError(f"Blocked hostname: {host!r}")
    if block_private_targets() and lowered.endswith(".local"):
        raise TargetValidationError(f"Blocked hostname: {host!r}")


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
        ip = ipaddress.ip_address(raw)
    except ValueError as exe:
        raise TargetValidationError(f"Invalid IP address: {value!r}") from exc
    _reject_blocked_ip(ip, original=value)
    return str(ip)


def validate_domain(value: str) -> str:
    raw = coerce_host(value)
    if any(ch in raw for ch in ";|&$`<>\\\"'"):
        raise TargetValidationError(f"Invalid domain: {value!r}")
    if not _DOMAIN_RE.match(raw):
        raise TargetValidationError(f"Invalid domain: {value!r}")
    _reject_blocked_hostname(raw)
    return raw


def validate_target(value: str) -> str:
    """Accept a single IPv4/IPv6 address or FQDN (URL wrappers are stripped)."""
    raw = (value or "").strip()
    if not raw:
        raise TargetValidationError("Target must not be empty")
    host = coerce_host(raw)
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return validate_domain(host)
    _reject_blocked_ip(ip, original=value)
    return str(ip)


def validate_targets(values: list[str]) -> list[str]:
    if not values:
        raise TargetValidationError("At least one target is required")
    return [validate_target(v) for v in values]
