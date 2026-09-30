"""Safe Nmap wrapper — allowlisted flags/scripts/ports only, validated targets."""

from __future__ import annotations

from dataclasses import dataclass, field
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

# Unauthenticated NSE scripts safe for VA service fingerprinting (no brute-force).
ALLOWED_NMAP_SCRIPTS = frozenset(
    {
        "banner",
        "http-title",
        "http-server-header",
        "http-headers",
        "http-methods",
        "ssl-cert",
        "ssl-enum-ciphers",
        "ssh2-enum-algos",
        "mysql-info",
        "ms-sql-info",
        "smb-os-discovery",
    }
)

# Named port presets (unauthenticated VA coverage by role).
PORT_PRESETS: dict[str, str] = {
    "web": "80,443,8080,8443",
    "webserver": "80,443,8000,8080,8443,8888",
    "db": "1433,1521,3306,5432,6379,27017",
    "dbserver": "1433,1521,3306,5432,6379,9200,27017",
    "appserver": "22,3000,7001,8009,8080,8443,9000,9001,9990,4848,8161",
    "common_va": (
        "21,22,25,80,110,143,443,445,1433,1521,3000,3306,3389,5432,5900,"
        "6379,7001,8000,8080,8443,8888,9000,9200,9990,27017"
    ),
}

DEFAULT_NMAP_FLAGS: tuple[str, ...] = ("-sV", "-Pn", "-T3")
DEFAULT_SERVICE_SCRIPTS: tuple[str, ...] = (
    "banner",
    "http-title",
    "http-server-header",
    "ssl-cert",
    "mysql-info",
)


@dataclass
class NmapScanRequest:
    targets: list[str]
    flags: Sequence[str] = DEFAULT_NMAP_FLAGS
    scripts: Sequence[str] = field(default_factory=tuple)
    port_preset: Optional[str] = None
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

        argv: list[str] = [self.binary, *flags]

        if request.port_preset:
            key = str(request.port_preset).strip().lower()
            if key not in PORT_PRESETS:
                raise ToolExecutionError(
                    f"Nmap port_preset not allowlisted: {request.port_preset!r} "
                    f"(allowed: {', '.join(sorted(PORT_PRESETS))})"
                )
            argv.extend(["-p", PORT_PRESETS[key]])

        scripts: list[str] = []
        for script in request.scripts:
            name = str(script).strip().lower()
            if name not in ALLOWED_NMAP_SCRIPTS:
                raise ToolExecutionError(f"Nmap script not allowlisted: {script!r}")
            scripts.append(name)
        if scripts:
            argv.extend(["--script", ",".join(scripts)])

        # Fixed safe output mode — never accept user-controlled -o* paths
        argv.extend(["-oX", "-", *targets])
        return argv

    def run(self, request: NmapScanRequest) -> ExecutionResult:
        argv = self.build_argv(request)
        return self.executor.run(argv, timeout_seconds=request.timeout_seconds)
