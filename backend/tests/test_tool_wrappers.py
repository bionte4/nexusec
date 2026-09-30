"""Tests for target validation and secure Nmap argv construction."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from workers.tool_wrappers.base import (  # noqa: E402
    SecureExecutor,
    ToolExecutionError,
    ToolTimeoutError,
)
from workers.tool_wrappers.nmap import (  # noqa: E402
    NmapScanRequest,
    NmapWrapper,
)
from workers.tool_wrappers.validators import (  # noqa: E402
    TargetValidationError,
    validate_domain,
    validate_ip,
    validate_target,
    validate_targets,
)


def test_validate_ip_v4() -> None:
    assert validate_ip("10.0.0.1") == "10.0.0.1"


def test_validate_ip_rejects_injection() -> None:
    with pytest.raises(TargetValidationError):
        validate_ip("10.0.0.1; rm -rf /")


def test_validate_domain_ok() -> None:
    assert validate_domain("scan.example.com") == "scan.example.com"


def test_validate_domain_rejects_metacharacters() -> None:
    with pytest.raises(TargetValidationError):
        validate_domain("evil.com;whoami")


def test_validate_domain_strips_url_wrappers() -> None:
    assert validate_domain("https://evil.com/") == "evil.com"
    assert validate_domain("http://api.example.org/path") == "api.example.org"


def test_validate_target_accepts_ip_or_domain() -> None:
    assert validate_target("192.168.1.10") == "192.168.1.10"
    assert validate_target("api.example.org") == "api.example.org"
    assert validate_target("https://desainkuproject.web.id/") == "desainkuproject.web.id"


def test_nmap_build_argv_allowlist_and_safe_output() -> None:
    wrapper = NmapWrapper()
    argv = wrapper.build_argv(
        NmapScanRequest(targets=["10.0.0.5"], flags=["-sV", "-Pn"])
    )
    assert argv[0] == "nmap"
    assert "-oX" in argv
    assert "-" in argv  # stdout XML
    assert "10.0.0.5" in argv
    assert argv.index("-oX") < argv.index("10.0.0.5")


def test_nmap_service_scripts_and_port_preset() -> None:
    wrapper = NmapWrapper()
    argv = wrapper.build_argv(
        NmapScanRequest(
            targets=["10.0.0.5"],
            flags=["-sV", "-Pn"],
            scripts=["banner", "http-title", "mysql-info"],
            port_preset="common_va",
        )
    )
    assert "-p" in argv
    ports = argv[argv.index("-p") + 1]
    assert "80" in ports and "3306" in ports and "5432" in ports
    assert "--script" in argv
    scripts = argv[argv.index("--script") + 1]
    assert "banner" in scripts and "mysql-info" in scripts


def test_nmap_rejects_unknown_script() -> None:
    wrapper = NmapWrapper()
    with pytest.raises(ToolExecutionError, match="script not allowlisted"):
        wrapper.build_argv(
            NmapScanRequest(targets=["10.0.0.5"], scripts=["brute"])
        )


def test_nmap_role_port_presets() -> None:
    wrapper = NmapWrapper()
    for preset in ("webserver", "dbserver", "appserver"):
        argv = wrapper.build_argv(
            NmapScanRequest(targets=["10.0.0.5"], port_preset=preset)
        )
        assert "-p" in argv
        ports = argv[argv.index("-p") + 1]
        if preset == "webserver":
            assert "80" in ports and "443" in ports
        elif preset == "dbserver":
            assert "3306" in ports and "5432" in ports
        else:
            assert "8080" in ports and "7001" in ports


def test_nmap_rejects_unknown_flag() -> None:
    wrapper = NmapWrapper()
    with pytest.raises(ToolExecutionError, match="not allowlisted"):
        wrapper.build_argv(
            NmapScanRequest(targets=["10.0.0.5"], flags=["--script=vuln"])
        )


def test_nmap_rejects_bad_target() -> None:
    wrapper = NmapWrapper()
    with pytest.raises(ToolExecutionError):
        wrapper.build_argv(
            NmapScanRequest(targets=["10.0.0.1$(reboot)"], flags=["-sV"])
        )


def test_secure_executor_never_uses_shell() -> None:
    executor = SecureExecutor(default_timeout_seconds=5)
    with patch("workers.tool_wrappers.base.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0, stdout="ok", stderr=""
        )
        with patch.object(executor, "resolve_binary", return_value="/usr/bin/nmap"):
            executor.run(["nmap", "-sV", "10.0.0.1"])

        kwargs = mock_run.call_args.kwargs
        assert kwargs.get("shell") is False
        args = mock_run.call_args.args[0]
        assert isinstance(args, list)
        assert args[0] == "/usr/bin/nmap"


def test_secure_executor_timeout_raises() -> None:
    import subprocess

    executor = SecureExecutor(default_timeout_seconds=1)
    with patch("workers.tool_wrappers.base.subprocess.run") as mock_run:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["nmap"], timeout=1)
        with patch.object(executor, "resolve_binary", return_value="/usr/bin/nmap"):
            with pytest.raises(ToolTimeoutError):
                executor.run(["nmap", "-sV", "10.0.0.1"])


def test_validate_targets_requires_non_empty() -> None:
    with pytest.raises(TargetValidationError):
        validate_targets([])
