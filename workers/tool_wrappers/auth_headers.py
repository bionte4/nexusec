"""Safe HTTP auth header construction for authenticated VA (Nuclei, etc.).

Never log returned secret values. Reject shell metacharacters and oversize payloads.
Requires caller to enforce ROE acknowledgement before use.
"""

from __future__ import annotations

import base64
import re
from typing import Any, Optional

from workers.tool_wrappers.base import ToolExecutionError

_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9\-_]{0,62}$")
_FORBIDDEN_VALUE = re.compile(r"[\r\n\x00;|&`$<>\\\"']")
_ALLOWED_AUTH_TYPES = frozenset({"bearer", "basic", "header", "cookie"})


def _clean_secret(value: Any, *, field: str, max_len: int = 4096) -> str:
    raw = str(value or "").strip()
    if not raw:
        raise ToolExecutionError(f"Authenticated VA auth.{field} is required")
    if len(raw) > max_len:
        raise ToolExecutionError(f"Authenticated VA auth.{field} exceeds {max_len} chars")
    if _FORBIDDEN_VALUE.search(raw):
        raise ToolExecutionError(f"Authenticated VA auth.{field} contains forbidden characters")
    return raw


def build_auth_headers(auth: Optional[dict[str, Any]]) -> list[tuple[str, str]]:
    """Build Nuclei ``-H`` header pairs from scan ``config.auth``.

    Supported types:
    - ``bearer``: ``Authorization: Bearer <token>``
    - ``basic``: ``Authorization: Basic <base64(user:pass)>``
    - ``header``: ``<header_name>: <header_value>``
    - ``cookie``: ``Cookie: <cookie>``
    """
    if not auth:
        return []
    if not isinstance(auth, dict):
        raise ToolExecutionError("Authenticated VA config.auth must be an object")

    auth_type = str(auth.get("type") or auth.get("auth_type") or "").strip().lower()
    if auth_type not in _ALLOWED_AUTH_TYPES:
        raise ToolExecutionError(
            f"Authenticated VA auth.type must be one of: {', '.join(sorted(_ALLOWED_AUTH_TYPES))}"
        )

    if auth_type == "bearer":
        token = _clean_secret(auth.get("token") or auth.get("header_value"), field="token")
        return [("Authorization", f"Bearer {token}")]

    if auth_type == "basic":
        username = _clean_secret(auth.get("username"), field="username", max_len=256)
        password = _clean_secret(auth.get("password"), field="password", max_len=512)
        blob = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
        return [("Authorization", f"Basic {blob}")]

    if auth_type == "cookie":
        cookie = _clean_secret(auth.get("cookie") or auth.get("header_value"), field="cookie")
        return [("Cookie", cookie)]

    # custom header
    name = str(auth.get("header_name") or "Authorization").strip()
    if not _HEADER_NAME_RE.match(name):
        raise ToolExecutionError(f"Authenticated VA auth.header_name invalid: {name!r}")
    value = _clean_secret(auth.get("header_value") or auth.get("token"), field="header_value")
    return [(name, value)]


def require_roe_for_authenticated(cfg: dict[str, Any]) -> bool:
    """Return True if this scan config requests authenticated VA."""
    if cfg.get("authenticated") is True:
        return True
    auth = cfg.get("auth")
    return isinstance(auth, dict) and bool(auth)


def assert_roe_acknowledged(cfg: dict[str, Any]) -> None:
    if not require_roe_for_authenticated(cfg):
        return
    if cfg.get("roe_acknowledged") is not True:
        raise ToolExecutionError(
            "Authenticated VA requires config.roe_acknowledged=true "
            "(confirm Rules of Engagement / written authorization for credentialed scanning)"
        )


def redact_auth_in_config(config: Optional[dict[str, Any]]) -> dict[str, Any]:
    """Copy scan config with secrets replaced for API responses."""
    out = dict(config or {})
    auth = out.get("auth")
    if not isinstance(auth, dict):
        return out
    sensitive = {
        "password",
        "token",
        "header_value",
        "cookie",
        "secret",
        "api_key",
        "authorization",
    }
    redacted: dict[str, Any] = {}
    for key, value in auth.items():
        if str(key).lower() in sensitive:
            redacted[key] = "***" if value not in (None, "") else value
        else:
            redacted[key] = value
    out["auth"] = redacted
    out["auth_configured"] = True
    return out
