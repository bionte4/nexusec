"""Passive OSINT connector — DNS resolve + Certificate Transparency (crt.sh) + RDAP.

No Amass/subfinder binary required. Uses validated domains only (no shell).
Public sources: system DNS, crt.sh JSON API, rdap.org.
"""

from __future__ import annotations

import json
import logging
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from workers.tool_wrappers.base import ExecutionResult, ToolExecutionError
from workers.tool_wrappers.validators import TargetValidationError, coerce_host, validate_domain

logger = logging.getLogger(__name__)

ALLOWED_OSINT_MODULES = frozenset({"dns", "crtsh", "rdap"})
DEFAULT_OSINT_MODULES: tuple[str, ...] = ("dns", "crtsh", "rdap")
_USER_AGENT = "NexuSec-OSINT/1.0 (+https://github.com/bionte4/nexusec)"


@dataclass
class OsintScanRequest:
    targets: list[str]
    modules: Sequence[str] = field(default_factory=lambda: list(DEFAULT_OSINT_MODULES))
    timeout_seconds: int = 60
    max_subdomains: int = 50


def _http_get_json(url: str, *, timeout: float) -> Any:
    req = Request(url, headers={"User-Agent": _USER_AGENT, "Accept": "application/json"})
    with urlopen(req, timeout=timeout) as resp:  # noqa: S310 — URL built from allowlisted hosts
        raw = resp.read(2_000_000)
    return json.loads(raw.decode("utf-8", errors="replace"))


def _dns_lookup(domain: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {"A": [], "AAAA": []}
    try:
        infos = socket.getaddrinfo(domain, None)
    except socket.gaierror as exc:
        return {"A": [], "AAAA": [], "error": [str(exc)]}  # type: ignore[dict-item]
    seen_v4: set[str] = set()
    seen_v6: set[str] = set()
    for family, _type, _proto, _canon, sockaddr in infos:
        if family == socket.AF_INET:
            ip = sockaddr[0]
            if ip not in seen_v4:
                seen_v4.add(ip)
                out["A"].append(ip)
        elif family == socket.AF_INET6:
            ip = sockaddr[0]
            if ip not in seen_v6:
                seen_v6.add(ip)
                out["AAAA"].append(ip)
    return out


def _crtsh_subdomains(domain: str, *, timeout: float, limit: int) -> list[str]:
    # crt.sh identity search; %25 = URL-encoded %
    url = f"https://crt.sh/?q=%25.{quote(domain, safe='')}&output=json"
    try:
        data = _http_get_json(url, timeout=timeout)
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        logger.info("crt.sh query failed for %s: %s", domain, exc)
        return []
    if not isinstance(data, list):
        return []
    names: set[str] = set()
    root = domain.lower().rstrip(".")
    for row in data:
        if not isinstance(row, dict):
            continue
        for key in ("name_value", "common_name"):
            val = row.get(key)
            if not isinstance(val, str):
                continue
            for part in val.replace("\n", " ").split():
                host = part.strip().lower().lstrip("*.")
                if not host or host == root:
                    continue
                if host == root or host.endswith("." + root):
                    try:
                        validate_domain(host)
                    except TargetValidationError:
                        continue
                    names.add(host)
                if len(names) >= limit:
                    break
            if len(names) >= limit:
                break
        if len(names) >= limit:
            break
    return sorted(names)[:limit]


def _rdap_summary(domain: str, *, timeout: float) -> dict[str, Any]:
    url = f"https://rdap.org/domain/{quote(domain, safe='')}"
    try:
        data = _http_get_json(url, timeout=timeout)
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        return {"error": str(exc)}
    if not isinstance(data, dict):
        return {"error": "unexpected RDAP payload"}
    # Avoid dumping full PII; keep high-level registration signals only.
    status = data.get("status")
    if not isinstance(status, list):
        status = []
    events = []
    for ev in data.get("events") or []:
        if isinstance(ev, dict) and ev.get("eventAction") in {
            "registration",
            "expiration",
            "last changed",
        }:
            events.append(
                {
                    "action": ev.get("eventAction"),
                    "date": ev.get("eventDate"),
                }
            )
    nameservers = []
    for ns in data.get("nameservers") or []:
        if isinstance(ns, dict) and isinstance(ns.get("ldhName"), str):
            nameservers.append(ns["ldhName"].lower().rstrip("."))
    return {
        "ldhName": data.get("ldhName"),
        "status": status[:10],
        "events": events[:6],
        "nameservers": nameservers[:12],
    }


def build_osint_report(
    targets: list[str],
    *,
    modules: Sequence[str],
    timeout_seconds: int = 60,
    max_subdomains: int = 50,
) -> str:
    """Build JSON report consumed by OsintJsonParser."""
    now = datetime.now(timezone.utc).isoformat()
    mods = [m for m in modules if m in ALLOWED_OSINT_MODULES]
    if not mods:
        mods = list(DEFAULT_OSINT_MODULES)
    per_target_timeout = max(5.0, min(float(timeout_seconds), 90.0) / max(len(targets), 1))

    results: list[dict[str, Any]] = []
    for raw in targets:
        host = coerce_host(raw)
        try:
            domain = validate_domain(host)
        except TargetValidationError as exc:
            results.append({"target": raw, "error": str(exc)})
            continue
        entry: dict[str, Any] = {"target": domain}
        if "dns" in mods:
            entry["dns"] = _dns_lookup(domain)
        if "crtsh" in mods:
            entry["crtsh_subdomains"] = _crtsh_subdomains(
                domain, timeout=per_target_timeout, limit=max_subdomains
            )
        if "rdap" in mods:
            entry["rdap"] = _rdap_summary(domain, timeout=per_target_timeout)
        results.append(entry)

    payload = {
        "engine": "osint",
        "version": "1.0",
        "generated_at": now,
        "modules": mods,
        "results": results,
    }
    return json.dumps(payload, indent=2)


class OsintWrapper:
    """Run passive OSINT modules and return JSON stdout."""

    def run(self, request: OsintScanRequest) -> ExecutionResult:
        if not request.targets:
            raise ToolExecutionError("No OSINT targets")
        bad = [m for m in request.modules if m not in ALLOWED_OSINT_MODULES]
        if bad:
            raise ToolExecutionError(
                f"OSINT modules not allowlisted: {bad!r} "
                f"(allowed: {', '.join(sorted(ALLOWED_OSINT_MODULES))})"
            )
        domains: list[str] = []
        for t in request.targets:
            try:
                domains.append(validate_domain(coerce_host(t)))
            except TargetValidationError as exc:
                raise ToolExecutionError(str(exc)) from exc
        if not domains:
            raise ToolExecutionError("No valid domain targets for OSINT")

        mods = list(request.modules) if request.modules else list(DEFAULT_OSINT_MODULES)
        stdout = build_osint_report(
            domains,
            modules=mods,
            timeout_seconds=request.timeout_seconds,
            max_subdomains=max(1, min(int(request.max_subdomains), 200)),
        )
        return ExecutionResult(
            command=("osint", *mods, "--", *domains),
            returncode=0,
            stdout=stdout,
            stderr=f"osint connector: modules={','.join(mods)} targets={len(domains)}",
            tool_version="nexusec-osint/1.0",
        )
