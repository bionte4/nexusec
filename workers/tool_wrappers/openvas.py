"""OpenVAS / Greenbone connector wrapper.

Modes (``OPENVAS_MODE`` / ``config.openvas_mode``):
- ``mock`` (default): synthetic GVM-like XML for labs/CI.
- ``gmp``: live Greenbone via python-gvm (Unix socket or TLS).
- import: pass ``report_xml`` to ingest an exported GVM report.
"""

from __future__ import annotations

import logging
import os
import shutil
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional, Sequence
from xml.sax.saxutils import escape

from workers.tool_wrappers.base import ExecutionResult, ToolExecutionError
from workers.tool_wrappers.validators import TargetValidationError, validate_targets

logger = logging.getLogger(__name__)

DEFAULT_OPENVAS_MODE = "mock"


@dataclass
class OpenVasScanRequest:
    targets: list[str]
    timeout_seconds: int = 900
    mode: Optional[str] = None
    report_xml: Optional[str] = None
    tags: Sequence[str] = field(default_factory=list)


@dataclass(frozen=True)
class GvmSettings:
    """Connection settings for a live Greenbone / GVM appliance."""

    username: str
    password: str
    socket_path: Optional[str] = None
    host: Optional[str] = None
    port: int = 9390
    tls_verify: bool = False
    scan_config_name: str = "Full and fast"
    port_list_name: str = "All IANA assigned TCP"
    poll_seconds: float = 5.0
    fallback_mock: bool = False

    @classmethod
    def from_env(cls) -> "GvmSettings":
        return cls(
            username=(os.getenv("GVM_USERNAME") or os.getenv("GVM_USER") or "").strip(),
            password=(os.getenv("GVM_PASSWORD") or "").strip(),
            socket_path=(os.getenv("GVM_SOCKET") or "").strip() or None,
            host=(os.getenv("GVM_HOST") or "").strip() or None,
            port=int(os.getenv("GVM_PORT") or "9390"),
            tls_verify=(os.getenv("GVM_TLS_VERIFY") or "false").lower()
            in {"1", "true", "yes"},
            scan_config_name=(
                os.getenv("GVM_SCAN_CONFIG") or "Full and fast"
            ).strip(),
            port_list_name=(
                os.getenv("GVM_PORT_LIST") or "All IANA assigned TCP"
            ).strip(),
            poll_seconds=float(os.getenv("GVM_POLL_SECONDS") or "5"),
            fallback_mock=(os.getenv("OPENVAS_GMP_FALLBACK_MOCK") or "false").lower()
            in {"1", "true", "yes"},
        )

    def configured(self) -> bool:
        if not self.username or not self.password:
            return False
        return bool(self.socket_path or self.host)


class OpenVasWrapper:
    """Build OpenVAS report XML (mock) or run a live GMP scan against Greenbone."""

    def __init__(
        self,
        *,
        mode: Optional[str] = None,
        gvm: Optional[GvmSettings] = None,
    ) -> None:
        self.mode = (mode or os.getenv("OPENVAS_MODE") or DEFAULT_OPENVAS_MODE).lower()
        self.gvm = gvm or GvmSettings.from_env()

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
            return self._run_gmp(targets, timeout_seconds=request.timeout_seconds)
        return self._run_mock(targets)

    def _run_mock(self, targets: list[str]) -> ExecutionResult:
        xml = build_mock_openvas_report(targets)
        return ExecutionResult(
            command=("openvas", "mock", *targets),
            returncode=0,
            stdout=xml,
            stderr="openvas mock connector: generated synthetic GVM report",
        )

    def _run_gmp(self, targets: list[str], *, timeout_seconds: int) -> ExecutionResult:
        if not self.gvm.configured():
            msg = (
                "OPENVAS_MODE=gmp requires GVM_USERNAME/GVM_PASSWORD and "
                "GVM_SOCKET or GVM_HOST (see docs/greenbone-gvm.md)"
            )
            if self.gvm.fallback_mock:
                result = self._run_mock(targets)
                return ExecutionResult(
                    command=result.command,
                    returncode=0,
                    stdout=result.stdout,
                    stderr=f"{msg}; fell back to mock (OPENVAS_GMP_FALLBACK_MOCK=true)",
                )
            raise ToolExecutionError(msg)

        try:
            xml, meta = run_gmp_scan(
                targets,
                settings=self.gvm,
                timeout_seconds=timeout_seconds,
            )
        except ToolExecutionError:
            raise
        except Exception as exc:  # noqa: BLE001 — surface as tool error to Celery
            logger.exception("GMP scan failed")
            if self.gvm.fallback_mock:
                result = self._run_mock(targets)
                return ExecutionResult(
                    command=result.command,
                    returncode=0,
                    stdout=result.stdout,
                    stderr=f"GMP error ({exc}); fell back to mock",
                )
            raise ToolExecutionError(f"Greenbone GMP scan failed: {exc}") from exc

        via = (
            f"socket:{self.gvm.socket_path}"
            if self.gvm.socket_path
            else f"tls:{self.gvm.host}:{self.gvm.port}"
        )
        return ExecutionResult(
            command=("openvas", "gmp", via, *targets),
            returncode=0,
            stdout=xml,
            stderr=(
                f"openvas gmp connector: task={meta.get('task_id')} "
                f"report={meta.get('report_id')} status={meta.get('status')}"
            ),
        )


def _gmp_connection(settings: GvmSettings):
    try:
        from gvm.connections import TLSConnection, UnixSocketConnection
    except ImportError as exc:
        raise ToolExecutionError(
            "python-gvm is not installed in the scanner image"
        ) from exc

    if settings.socket_path:
        return UnixSocketConnection(path=settings.socket_path)
    if not settings.host:
        raise ToolExecutionError("GVM_HOST or GVM_SOCKET is required for GMP mode")
    # Community TLS setups vary; verify off by default for lab appliances.
    return TLSConnection(
        hostname=settings.host,
        port=settings.port,
        timeout=60,
        # python-gvm uses certfile/cafile when provided; omit for password auth labs
    )


def _find_entity_id(gmp: Any, *, getters: Sequence[str], name: str) -> str:
    """Return first entity id whose <name> matches (case-insensitive)."""
    needle = name.strip().lower()
    last_exc: Optional[Exception] = None
    for getter in getters:
        try:
            response = getattr(gmp, getter)()
        except Exception as exc:  # noqa: BLE001 — try next API name
            last_exc = exc
            continue
        for el in response.xpath(".//*[@id]"):
            nm = (el.findtext("name") or "").strip().lower()
            if nm == needle:
                entity_id = el.get("id")
                if entity_id:
                    return entity_id
    detail = f" ({last_exc})" if last_exc else ""
    raise ToolExecutionError(
        f"Greenbone entity not found: name={name!r} via {list(getters)}{detail}"
    )


def _find_xml_report_format_id(gmp: Any) -> str:
    response = gmp.get_report_formats()
    for el in response.xpath(".//report_format[@id]"):
        nm = (el.findtext("name") or "").strip().lower()
        if nm in {"xml", "xml anonymized", "anonymous xml"}:
            rid = el.get("id")
            if rid:
                return rid
    # Fallback: first report format
    for el in response.xpath(".//report_format[@id]"):
        rid = el.get("id")
        if rid:
            return rid
    raise ToolExecutionError("No Greenbone report format available for XML export")


def run_gmp_scan(
    targets: list[str],
    *,
    settings: GvmSettings,
    timeout_seconds: int = 900,
) -> tuple[str, dict[str, str]]:
    """Create target+task, wait for completion, return report XML + metadata."""
    try:
        from gvm.protocols.gmp import Gmp
        from gvm.transforms import EtreeCheckCommandTransform
    except ImportError as exc:
        raise ToolExecutionError(
            "python-gvm is not installed; rebuild scanner-worker"
        ) from exc

    connection = _gmp_connection(settings)
    transform = EtreeCheckCommandTransform()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    suffix = uuid.uuid4().hex[:8]
    target_name = f"nexusec-{stamp}-{suffix}"
    task_name = f"nexusec-task-{stamp}-{suffix}"

    with Gmp(connection=connection, transform=transform) as gmp:
        gmp.authenticate(settings.username, settings.password)

        config_id = _find_entity_id(
            gmp,
            getters=("get_scan_configs", "get_configs"),
            name=settings.scan_config_name,
        )
        port_list_id = _find_entity_id(
            gmp,
            getters=("get_port_lists",),
            name=settings.port_list_name,
        )
        scanner_id = _find_entity_id(
            gmp,
            getters=("get_scanners",),
            name="OpenVAS Default",
        )

        created_target = gmp.create_target(
            name=target_name,
            hosts=targets,
            port_list_id=port_list_id,
        )
        target_id = created_target.get("id")
        if not target_id:
            raise ToolExecutionError("create_target returned no id")

        created_task = gmp.create_task(
            name=task_name,
            config_id=config_id,
            target_id=target_id,
            scanner_id=scanner_id,
        )
        task_id = created_task.get("id")
        if not task_id:
            raise ToolExecutionError("create_task returned no id")

        gmp.start_task(task_id)

        deadline = time.monotonic() + max(60, timeout_seconds)
        status = "Unknown"
        progress = "0"
        report_id: Optional[str] = None
        while time.monotonic() < deadline:
            task = gmp.get_task(task_id)
            status_el = task.find("task/status")
            status = (status_el.text if status_el is not None else "") or "Unknown"
            progress_el = task.find("task/progress")
            progress = (progress_el.text if progress_el is not None else "0") or "0"
            last_report = task.find("task/last_report/report")
            if last_report is not None and last_report.get("id"):
                report_id = last_report.get("id")
            if status in {"Done", "Stopped", "Interrupted"}:
                break
            time.sleep(max(1.0, settings.poll_seconds))

        if status != "Done":
            raise ToolExecutionError(
                f"Greenbone task did not finish (status={status}, progress={progress})"
            )
        if not report_id:
            # Some GVM versions only expose report after Done via get_task again
            task = gmp.get_task(task_id)
            last_report = task.find("task/last_report/report")
            report_id = last_report.get("id") if last_report is not None else None
        if not report_id:
            raise ToolExecutionError("Greenbone task completed but no report id found")

        format_id = _find_xml_report_format_id(gmp)
        report = gmp.get_report(
            report_id,
            report_format_id=format_id,
            ignore_pagination=True,
            details=True,
        )
        # get_report returns <get_reports_response><report>...</report>
        report_el = report.find("report")
        if report_el is None:
            report_el = report.find(".//report")
        if report_el is None:
            raise ToolExecutionError("Greenbone get_report returned empty report")

        try:
            from lxml import etree
        except ImportError as exc:
            raise ToolExecutionError("lxml required for GMP report serialization") from exc

        xml = etree.tostring(report_el, encoding="unicode")
        meta = {
            "task_id": task_id,
            "target_id": target_id,
            "report_id": report_id,
            "status": status,
            "progress": progress,
        }
        return xml, meta


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


def gvm_cli_available() -> bool:
    return shutil.which("gvm-cli") is not None
