"""Secure array-based subprocess execution for scanner CLI tools.

CRITICAL: Never use shell=True. Arguments must be a list of strings.
"""

from __future__ import annotations

import logging
import os
import resource
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import FrozenSet, Mapping, Optional, Sequence

logger = logging.getLogger(__name__)


class ToolExecutionError(Exception):
    """Base error for tool wrapper failures."""


class ToolNotFoundError(ToolExecutionError):
    """Binary not found on PATH."""


class ToolTimeoutError(ToolExecutionError):
    """Subprocess exceeded timeout."""


class ToolResourceError(ToolExecutionError):
    """Resource limit configuration failed or process killed by limits."""


@dataclass(frozen=True)
class ExecutionResult:
    command: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


@dataclass
class ResourceLimits:
    """Optional POSIX resource caps applied via preexec_fn (Unix only)."""

    cpu_seconds: Optional[int] = 300
    address_space_bytes: Optional[int] = 512 * 1024 * 1024  # 512 MiB
    max_open_files: Optional[int] = 256


@dataclass
class SecureExecutor:
    """
    Run external CLI tools safely.

    - argv is always a list (never a shell string)
    - absolute or PATH-resolved binary only
    - timeout kills the process group
    - optional RLIMIT caps on Unix
    """

    default_timeout_seconds: int = 300
    resource_limits: ResourceLimits = field(default_factory=ResourceLimits)
    env_allowlist: Optional[FrozenSet[str]] = None

    def resolve_binary(self, binary: str) -> str:
        if os.path.isabs(binary):
            if not (os.path.isfile(binary) and os.access(binary, os.X_OK)):
                raise ToolNotFoundError(f"Binary not executable: {binary}")
            return binary
        if "/" in binary or "\\" in binary:
            raise ToolNotFoundError(f"Refusing relative path binary: {binary!r}")
        resolved = shutil.which(binary)
        if not resolved:
            raise ToolNotFoundError(f"Binary not found on PATH: {binary}")
        return resolved

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout_seconds: Optional[int] = None,
        cwd: Optional[str] = None,
        env: Optional[Mapping[str, str]] = None,
        input_data: Optional[str] = None,
    ) -> ExecutionResult:
        if not argv:
            raise ToolExecutionError("Empty command")
        if not all(isinstance(a, str) for a in argv):
            raise ToolExecutionError("All argv elements must be strings")
        if any("\x00" in a for a in argv):
            raise ToolExecutionError("NUL byte in argv is not allowed")

        binary = self.resolve_binary(argv[0])
        command = (binary, *list(argv[1:]))
        timeout = timeout_seconds if timeout_seconds is not None else self.default_timeout_seconds

        run_env = self._build_env(env)
        preexec = self._make_preexec_fn() if os.name == "posix" else None

        logger.info("Executing tool: %s (timeout=%ss)", " ".join(command), timeout)

        try:
            completed = subprocess.run(  # noqa: S603 — intentional; shell=False
                list(command),
                input=input_data,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                shell=False,
                cwd=cwd,
                env=run_env,
                preexec_fn=preexec,
                start_new_session=True,  # isolate process group for kill on timeout
            )
        except subprocess.TimeoutExpired as exc:
            raise ToolTimeoutError(f"Command timed out after {timeout}s: {command[0]}") from exc
        except OSError as exc:
            raise ToolExecutionError(f"Failed to execute {command[0]}: {exc}") from exc

        return ExecutionResult(
            command=command,
            returncode=completed.returncode,
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
            timed_out=False,
        )

    def _build_env(self, extra: Optional[Mapping[str, str]]) -> dict[str, str]:
        # Minimal env — do not inherit secrets from the worker process blindly
        base = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin:/usr/local/bin"),
            "LANG": os.environ.get("LANG", "C.UTF-8"),
            "LC_ALL": "C.UTF-8",
            "HOME": os.environ.get("HOME", "/tmp"),
        }
        if self.env_allowlist:
            for key in self.env_allowlist:
                if key in os.environ:
                    base[key] = os.environ[key]
        if extra:
            base.update({k: str(v) for k, v in extra.items()})
        return base

    def _make_preexec_fn(self):
        limits = self.resource_limits

        def _apply_limits() -> None:
            try:
                if limits.cpu_seconds is not None:
                    resource.setrlimit(
                        resource.RLIMIT_CPU,
                        (limits.cpu_seconds, limits.cpu_seconds),
                    )
                if limits.address_space_bytes is not None and hasattr(resource, "RLIMIT_AS"):
                    resource.setrlimit(
                        resource.RLIMIT_AS,
                        (limits.address_space_bytes, limits.address_space_bytes),
                    )
                if limits.max_open_files is not None:
                    resource.setrlimit(
                        resource.RLIMIT_NOFILE,
                        (limits.max_open_files, limits.max_open_files),
                    )
            except (ValueError, OSError) as exc:
                # Running without caps is worse than failing closed for scanners —
                # log and continue; hard failure can break macOS/dev environments
                logger.warning("Could not apply resource limits: %s", exc)

        return _apply_limits
