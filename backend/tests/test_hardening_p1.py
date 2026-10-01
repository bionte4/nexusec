"""Tests for P1 hardening helpers (secret box, SSRF target policy, rate rules)."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from app.core.secret_box import is_sealed, open_secret, seal_secret
from app.middleware.rate_limit import _match_rule
from workers.tool_wrappers.validators import (
    TargetValidationError,
    block_private_targets,
    validate_domain,
    validate_ip,
    validate_target,
)


def test_secret_box_roundtrip() -> None:
    key = "unit-test-secret-key-please-change"
    sealed = seal_secret("gsk_live_example", key)
    assert is_sealed(sealed)
    assert open_secret(sealed, key) == "gsk_live_example"
    assert seal_secret(sealed, key) == sealed  # idempotent


def test_secret_box_plaintext_passthrough() -> None:
    assert open_secret("plain-key", "x") == "plain-key"


def test_rate_rules_match_sensitive_paths() -> None:
    assert _match_rule("POST", "/api/v1/auth/login") is not None
    assert _match_rule("POST", "/api/v1/scans") is not None
    assert _match_rule("POST", "/api/v1/vulnerabilities/abc/generate-ai-patch") is not None
    assert _match_rule("GET", "/api/v1/reports/engagement/pdf") is not None
    assert _match_rule("GET", "/api/v1/assets") is None


def test_block_private_targets_respects_env() -> None:
    with patch.dict(os.environ, {"SCAN_BLOCK_PRIVATE_TARGETS": "true", "APP_ENV": "development"}):
        assert block_private_targets() is True
    with patch.dict(os.environ, {"SCAN_BLOCK_PRIVATE_TARGETS": "false", "APP_ENV": "production"}):
        assert block_private_targets() is False


def test_private_ip_blocked_when_enabled() -> None:
    with patch.dict(os.environ, {"SCAN_BLOCK_PRIVATE_TARGETS": "true"}):
        with pytest.raises(TargetValidationError, match="blocked"):
            validate_ip("10.0.0.1")
        with pytest.raises(TargetValidationError, match="blocked"):
            validate_target("127.0.0.1")
        with pytest.raises(TargetValidationError, match="Blocked"):
            validate_domain("metadata.google.internal")
        with pytest.raises(TargetValidationError, match="Blocked"):
            validate_target("http://metadata.google.internal/latest")


def test_public_targets_ok_when_blocking() -> None:
    with patch.dict(os.environ, {"SCAN_BLOCK_PRIVATE_TARGETS": "true"}):
        assert validate_target("8.8.8.8") == "8.8.8.8"
        assert validate_domain("scan.example.com") == "scan.example.com"


def test_lab_allows_private_when_disabled() -> None:
    with patch.dict(os.environ, {"SCAN_BLOCK_PRIVATE_TARGETS": "false"}):
        assert validate_ip("10.0.0.1") == "10.0.0.1"
        assert validate_target("192.168.1.10") == "192.168.1.10"
