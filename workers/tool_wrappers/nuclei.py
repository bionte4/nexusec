"""Safe Nuclei wrapper — allowlisted options only, validated HTTP(S) targets."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional, Sequence
from urllib.parse import urlparse

from workers.tool_wrappers.base import (
    ExecutionResult,
    ResourceLimits,
    SecureExecutor,
    ToolExecutionError,
)
from workers.tool_wrappers.validators import TargetValidationError, validate_target

_ALLOWED_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info", "unknown"})
_TAG_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$")

# Unauthenticated VA template packs under /opt/nuclei-templates (no full-tree OOM).
_ALLOWED_TEMPLATE_DIRS = frozenset(
    {
        "/opt/nuclei-templates/http",
        "/opt/nuclei-templates/ssl",
        "/opt/nuclei-templates/network",
        "/opt/nuclei-templates/dns",
        "/opt/nuclei-templates/tcp",
        "/opt/nuclei-templates/javascript",
    }
)
_DEFAULT_TEMPLATE_DIRS: tuple[str, ...] = (
    "/opt/nuclei-templates/http",
    "/opt/nuclei-templates/ssl",
    "/opt/nuclei-templates/network",
)


@dataclass
class NucleiScanRequest:
    targets: list[str]
    severities: Sequence[str] = ("critical", "high", "medium")
    tags: Sequence[str] = field(default_factory=tuple)
    exclude_tags: Sequence[str] = ("dos",)
    rate_limit: int = 25
    # Cap Go thread growth inside Docker pids_limit / ulimit nproc.
    concurrency: int = 10
    bulk_size: int = 10
    timeout_seconds: int = 900
    # Prefer template_dirs for multi-pack unauthenticated VA; template_dir kept for compat.
    template_dir: str = ""
    template_dirs: Sequence[str] = field(default_factory=tuple)


def validate_nuclei_target(value: str) -> str:
    """Accept http(s) URL or host/IP (normalized to https:// for bare hosts)."""
    raw = (value or "").strip()
    if not raw or any(ch.isspace() for ch in raw):
        raise TargetValidationError(f"Invalid Nuclei target: {value!r}")
    if any(ch in raw for ch in ";|&$`<>\\\"'"):
        raise TargetValidationError(f"Invalid Nuclei target: {value!r}")

    if "://" in raw:
        parsed = urlparse(raw)
        if parsed.scheme not in {"http", "https"}:
            raise TargetValidationError(f"Nuclei target must be http(s): {value!r}")
        if not parsed.netloc:
            raise TargetValidationError(f"Invalid Nuclei URL: {value!r}")
        # Reject credentials and odd ports injection via userinfo abuse beyond basics
        if "@" in parsed.netloc and parsed.username:
            raise TargetValidationError(f"URL credentials not allowed: {value!r}")
        host = parsed.hostname
        if not host:
            raise TargetValidationError(f"Invalid Nuclei URL host: {value!r}")
        validate_target(host)
        path = parsed.path or ""
        if path and any(ch in path for ch in ";|&$`<>\\\"'"):
            raise TargetValidationError(f"Invalid Nuclei URL path: {value!r}")
        # Rebuild clean URL (drop fragment/query for safety; query rarely needed for VA)
        port = f":{parsed.port}" if parsed.port else ""
        clean_path = path if path not in {"", "/"} else ""
        return f"{parsed.scheme}://{host}{port}{clean_path}"

    host = validate_target(raw)
    return f"https://{host}"


def _resolve_template_dirs(request: NucleiScanRequest) -> list[str]:
    dirs: list[str] = []
    raw_dirs = list(request.template_dirs) if request.template_dirs else []
    if not raw_dirs and request.template_dir:
        # Support comma-separated legacy field
        raw_dirs = [p.strip() for p in str(request.template_dir).split(",") if p.strip()]
    if not raw_dirs:
        raw_dirs = list(_DEFAULT_TEMPLATE_DIRS)

    seen: set[str] = set()
    for path in raw_dirs:
        cleaned = path.rstrip("/")
        if cleaned not in _ALLOWED_TEMPLATE_DIRS:
            raise ToolExecutionError(
                f"Nuclei template_dir not allowlisted: {path!r} "
                f"(allowed packs: http, ssl, network, dns, tcp, javascript)"
            )
        if cleaned not in seen:
            seen.add(cleaned)
            dirs.append(cleaned)
    return dirs


class NucleiWrapper:
    """
    Build and run Nuclei with injection-safe arguments.

    Output is JSONL on stdout (-jsonl -silent) for the NucleiJsonParser.
    """

    def __init__(
        self,
        executor: Optional[SecureExecutor] = None,
        *,
        binary: str = "nuclei",
    ) -> None:
        self.executor = executor or SecureExecutor(
            default_timeout_seconds=900,
            resource_limits=ResourceLimits(
                cpu_seconds=900,
                # Nuclei template load is memory-hungry; 1 GiB causes SIGSEGV/exit 2.
                address_space_bytes=3 * 1024 * 1024 * 1024,
                max_open_files=4096,
            ),
        )
        self.binary = binary

    def build_argv(self, request: NucleiScanRequest) -> list[str]:
        try:
            targets = [validate_nuclei_target(t) for t in request.targets]
        except TargetValidationError as exc:
            raise ToolExecutionError(str(exc)) from exc
        if not targets:
            raise ToolExecutionError("At least one Nuclei target is required")

        severities: list[str] = []
        for sev in request.severities:
            key = str(sev).strip().lower()
            if key not in _ALLOWED_SEVERITIES:
                raise ToolExecutionError(f"Nuclei severity not allowlisted: {sev!r}")
            severities.append(key)
        if not severities:
            severities = ["critical", "high", "medium"]

        tags: list[str] = []
        for tag in request.tags:
            raw = str(tag).strip().lower()
            if not _TAG_RE.match(raw):
                raise ToolExecutionError(f"Nuclei tag not allowlisted: {tag!r}")
            tags.append(raw)

        exclude_tags: list[str] = []
        for tag in request.exclude_tags:
            raw = str(tag).strip().lower()
            if not _TAG_RE.match(raw):
                raise ToolExecutionError(f"Nuclei exclude tag not allowlisted: {tag!r}")
            exclude_tags.append(raw)

        rate = int(request.rate_limit)
        if rate < 1 or rate > 300:
            raise ToolExecutionError("Nuclei rate_limit must be between 1 and 300")

        concurrency = int(request.concurrency)
        if concurrency < 1 or concurrency > 50:
            raise ToolExecutionError("Nuclei concurrency must be between 1 and 50")

        bulk_size = int(request.bulk_size)
        if bulk_size < 1 or bulk_size > 50:
            raise ToolExecutionError("Nuclei bulk_size must be between 1 and 50")

        template_dirs = _resolve_template_dirs(request)

        argv: list[str] = [
            self.binary,
            "-jsonl",
            "-silent",
            "-duc",
        ]
        for tdir in template_dirs:
            argv.extend(["-t", tdir])
        argv.extend(
            [
                "-severity",
                ",".join(severities),
                "-rate-limit",
                str(rate),
                "-c",
                str(concurrency),
                "-bulk-size",
                str(bulk_size),
            ]
        )
        if tags:
            argv.extend(["-tags", ",".join(tags)])
        if exclude_tags:
            argv.extend(["-etags", ",".join(exclude_tags)])
        for target in targets:
            argv.extend(["-u", target])
        return argv

    def run(self, request: NucleiScanRequest) -> ExecutionResult:
        argv = self.build_argv(request)
        env = {
            "HOME": "/tmp",
            "DISABLE_UPDATE_CHECK": "true",
        }
        return self.executor.run(
            argv,
            timeout_seconds=request.timeout_seconds,
            env=env,
        )
