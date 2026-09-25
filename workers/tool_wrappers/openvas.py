"""OpenVAS / Greenbone connector wrapper.

Modes (``OPENVAS_MODE``):
- ``mock`` (default): generate deterministic OpenVAS-like XML for validated targets
  so CI / demos work without a live GVM appliance.
- ``gmp``: reserved for live Greenbone; requires appliance + ``gvm-cli``.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Sequence
from xml.sax.saxutils import escape

from workers.tool_wrappers.base import ExecutionResult, ToolExecutionError
from workers.tool_wrappers.validators import TargetValidationError, validate_targets

DEFAULT_OPENVAS_MODE = "mock"


@dataclass
class OpenVasScanRequest:
    targets: list[str]
    timeout_seconds: int = 900
    mode: Optional[str] = None
    # Optional pre-baked report XML (tests / import)
    report_xml: Optional[str] = None
    tags: Sequence[str] = field(default_factory=list)


class OpenVasWrapper:
    """Build OpenVAS report XML (mock) or refuse unsafe live GMP without config."""

    def __init__(self, *, mode: Optional[str] = None) -> None:
        self.mode = (mode or os.getenv("OPENVAS_MODE") or DEFAULT_OPENVAS_MODE).lower()

    def run(self, request: OpenVasScanRequest) -> ExecutionResult:
        if request.report_xml:
            return ExecutionResult(
                command=("openvas", "import-xml"),
                returncode=0,
                stdout=request.report_xml,
                stderr="",
            )

        try:
            targets = validate_targets(list(request.targets))
        except TargetValidationError as exc:
            raise ToolExecutionError(str(exc)) from exc
        if not targets:
            raise ToolExecutionError("No valid OpenVAS targets")

        mode = (request.mode or self.mode).lower()
        if mode == "gmp":
            return self._run_gmp(targets)
        return self._run_mock(targets)

    def _run_mock(self, targets: list[str]) -> ExecutionResult:
        xml = build_mock_openvas_report(targets)
        return ExecutionResult(
            command=("openvas", "mock", *targets),
            returncode=0,
            stdout=xml,
            stderr="openvas mock connector: generated synthetic GVM report",
        )

    def _run_gmp(self, targets: list[str]) -> ExecutionResult:
        """Best-effort gate: fall back to mock if gvm-cli is absent."""
        binary = shutil.which("gvm-cli")
        if not binary:
            result = self._run_mock(targets)
            return ExecutionResult(
                command=result.command,
                returncode=0,
                stdout=result.stdout,
                stderr=(
                    "gvm-cli not found; fell back to OpenVAS mock connector"
                ),
            )
        raise ToolExecutionError(
            "OPENVAS_MODE=gmp requires a configured Greenbone appliance; "
            "use OPENVAS_MODE=mock or pass report_xml in scan config for labs"
        )


def build_mock_openvas_report(targets: list[str]) -> str:
    """Deterministic OpenVAS-like XML for normalization + UI demos."""
    now = datetime.now(timezone.utc).isoformat()
    results: list[str] = []
    catalog = [
        (
            "1.3.6.1.4.1.25623.1.0.900658",
            "SSH Weak Encryption Algorithms Supported",
            "Medium",
            "5.0",
            "22/tcp",
            "CVE-2015-4000",
            "The remote SSH server allows weak encryption algorithms (CWE-326).",
        ),
        (
            "1.3.6.1.4.1.25623.1.0.103497",
            "SSL/TLS: Report Vulnerable Cipher Suites for HTTPS",
            "High",
            "7.5",
            "443/tcp",
            "CVE-2016-2183",
            "The remote service supports vulnerable TLS cipher suites (CWE-326).",
        ),
        (
            "1.3.6.1.4.1.25623.1.0.108597",
            "HTTP Security Headers Detection",
            "Low",
            "2.6",
            "80/tcp",
            "",
            "Missing recommended security headers on HTTP service.",
        ),
    ]
    rid = 0
    for host in targets:
        for oid, name, threat, severity, port, cve, desc in catalog:
            rid += 1
            cve_xml = escape(cve) if cve else "NOCVE"
            results.append(
                f"""
    <result id="mock-{rid}">
      <name>{escape(name)}</name>
      <host>{escape(host)}</host>
      <port>{escape(port)}</port>
      <threat>{escape(threat)}</threat>
      <severity>{escape(severity)}</severity>
      <description>{escape(desc)}</description>
      <nvt oid="{escape(oid)}">
        <name>{escape(name)}</name>
        <cve>{cve_xml}</cve>
        <xref>URL:https://nvd.nist.gov/ CWE-326</xref>
      </nvt>
    </result>"""
            )
    body = "\n".join(results)
    return f"""<?xml version="1.0"?>
<report id="nexusec-openvas-mock" format_id="XML">
  <name>NexuSec OpenVAS mock report</name>
  <creation_time>{escape(now)}</creation_time>
  <results>
{body}
  </results>
</report>
"""
