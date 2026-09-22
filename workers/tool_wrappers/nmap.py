"""Safe Nmap wrapper — allowlisted flags only, validated targets."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Sequence

from workers.tool_wrappers.base import ExecutionResult, SecureExecutor, ToolExecutionError
from workers.tool_wrappers.validators import TargetValidationError, validate_targets

# Only these flags may be requested by callers (no free-form user argv).
ALLOWED_NMAP_FLAGS = frozenset(
    {
        "-sV",
        "-sT",
        "-sn",
        "-Pn",
        "-F",
        "-T2",
        "-T3",
        "-T4",
        "--open",
    }
)

DEFAULT_NMAP_FLAGS: tuple[str, ...] = ("-sV", "-Pn", "-T3")


@dataclass
class NmapScanRequest:
    targets: list[str]
    flags: Sequence[str] = DEFAULT_NMAP_FLAGS
    timeout_seconds: int = 600


class NmapWrapper:
    """
    Build and run Nmap with injection-safe arguments.

    Output format is always XML to stdout (-oX -) for later normalizers.
    """

    def __init__(
        self,
        executor: Optional[SecureExecutor] = None,
        *,
        binary: str = "nmap",
    ) -> None:
        self.executor = executor or SecureExecutor(default_timeout_seconds=600)
        self.binary = binary

    def build_argv(self, request: NmapScanRequest) -> list[str]:
        try:
            targets = validate_targets(list(request.targets))
        except TargetValidationError as exc:
            raise ToolExecutionError(str(exc)) from exc

        flags: list[str] = []
        for flag in request.flags:
            if flag not in ALLOWED_NMAP_FLAGS:
                raise ToolExecutionError(f"Nmap flag not allowlisted: {flag!r}")
            flags.append(flag)

        # Fixed safe output mode — never accept user-controlled -o* paths
        return [self.binary, *flags, "-oX", "-", *targets]

    def run(self, request: NmapScanRequest) -> ExecutionResult:
        argv = self.build_argv(request)
        return self.executor.run(argv, timeout_seconds=request.timeout_seconds)
