"""Map probe results → unified NormalizedFinding-compatible dicts."""

from __future__ import annotations

from typing import Any

from nexusec_scanner.probes import ProbeResult

# Ports commonly considered higher risk when exposed
_RISKY_PORTS: dict[int, tuple[str, str, float]] = {
    # port: (severity, cwe, cvss-ish heuristic)
    21: ("medium", "CWE-319", 5.0),
    23: ("high", "CWE-319", 7.5),
    445: ("high", "CWE-200", 7.0),
    3389: ("high", "CWE-287", 7.5),
    5900: ("medium", "CWE-287", 5.5),
    3306: ("medium", "CWE-284", 5.0),
    5432: ("medium", "CWE-284", 5.0),
}


def probe_to_finding(result: ProbeResult) -> dict[str, Any] | None:
    if not result.open:
        return None

    severity, cwe, cvss = _RISKY_PORTS.get(result.port, ("info", None, None))
    service_hint = _guess_service(result.port, result.banner)
    name = f"Open TCP port {result.port} ({service_hint})"
    description = f"Custom NexuSec scanner detected TCP/{result.port} open on {result.host}."
    if result.banner:
        description += f" Banner: {result.banner[:200]}"

    return {
        "vuln_id": f"nexusec:open:tcp/{result.port}/{service_hint}",
        "name": name,
        "description": description,
        "severity": severity,
        "cvss_score": cvss,
        "cwe_id": cwe,
        "mitre_tactics": ["TA0043"],
        "remediation_steps": (
            "Confirm business need for the exposed service; restrict via firewall "
            "or disable if unused; enforce strong authentication and patching."
        ),
        "iso_27001_clause": ["A.8.8", "A.8.20"],
        "pci_dss_requirement": ["1.2", "11.3.1"],
        "gdpr_risk_flag": False,
        "port": result.port,
        "protocol": "tcp",
        "affected_component": service_hint,
        "evidence": {
            "banner": result.banner,
            "latency_ms": result.latency_ms,
            "probe": "tcp_connect",
        },
        "source_tool": "nexusec",
        "raw_source": {
            "host": result.host,
            "port": result.port,
            "open": True,
            "banner": result.banner,
            "error": result.error,
        },
        "target_hint": result.host,
    }


def _guess_service(port: int, banner: str | None) -> str:
    known = {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        139: "netbios",
        443: "https",
        445: "smb",
        3306: "mysql",
        3389: "rdp",
        5432: "postgres",
        5900: "vnc",
        8080: "http-alt",
        8443: "https-alt",
    }
    if banner:
        b = banner.lower()
        if "ssh" in b:
            return "ssh"
        if "http" in b:
            return "http"
        if "smtp" in b:
            return "smtp"
    return known.get(port, "unknown")
