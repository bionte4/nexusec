"""Tests for authenticated VA header builder and ROE gate."""

from __future__ import annotations

import base64
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from workers.tool_wrappers.auth_headers import (  # noqa: E402
    assert_roe_acknowledged,
    build_auth_headers,
    redact_auth_in_config,
    require_roe_for_authenticated,
)
from workers.tool_wrappers.base import ToolExecutionError  # noqa: E402
from workers.tool_wrappers.nuclei import NucleiScanRequest, NucleiWrapper  # noqa: E402


def test_roe_required_when_authenticated() -> None:
    assert require_roe_for_authenticated({"authenticated": True}) is True
    with pytest.raises(ToolExecutionError, match="roe_acknowledged"):
        assert_roe_acknowledged({"authenticated": True})
    assert_roe_acknowledged({"authenticated": True, "roe_acknowledged": True})


def test_build_bearer_and_basic_headers() -> None:
    bearer = build_auth_headers({"type": "bearer", "token": "abc.def"})
    assert bearer == [("Authorization", "Bearer abc.def")]

    basic = build_auth_headers(
        {"type": "basic", "username": "scan", "password": "s3cret"}
    )
    expected = base64.b64encode(b"scan:s3cret").decode("ascii")
    assert basic == [("Authorization", f"Basic {expected}")]


def test_build_rejects_shell_meta() -> None:
    with pytest.raises(ToolExecutionError):
        build_auth_headers({"type": "bearer", "token": "evil;id"})


def test_redact_auth_in_config() -> None:
    cfg = redact_auth_in_config(
        {
            "authenticated": True,
            "auth": {"type": "bearer", "token": "super-secret"},
        }
    )
    assert cfg["auth"]["token"] == "***"
    assert cfg["auth_configured"] is True


def test_nuclei_argv_includes_header() -> None:
    argv = NucleiWrapper().build_argv(
        NucleiScanRequest(
            targets=["https://example.com"],
            headers=[("Authorization", "Bearer tok")],
            template_dirs=["/opt/nuclei-templates/http"],
        )
    )
    assert "-H" in argv
    assert argv[argv.index("-H") + 1] == "Authorization: Bearer tok"
