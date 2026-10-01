"""Encrypt platform secrets at rest (Fernet derived from SECRET_KEY)."""

from __future__ import annotations

import base64
import hashlib
import logging
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

_PREFIX = "enc:v1:"


def _fernet(secret_key: str) -> Fernet:
    digest = hashlib.sha256((secret_key or "nexusec-dev").encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def seal_secret(plaintext: str, secret_key: str) -> str:
    """Encrypt a secret for DB storage. Idempotent for already-sealed values."""
    value = (plaintext or "").strip()
    if not value:
        return ""
    if value.startswith(_PREFIX):
        return value
    token = _fernet(secret_key).encrypt(value.encode("utf-8")).decode("ascii")
    return f"{_PREFIX}{token}"


def open_secret(value: str, secret_key: str) -> str:
    """Decrypt sealed secret; pass through legacy plaintext."""
    raw = (value or "").strip()
    if not raw:
        return ""
    if not raw.startswith(_PREFIX):
        return raw
    token = raw[len(_PREFIX) :]
    try:
        return _fernet(secret_key).decrypt(token.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError) as exc:
        logger.error("Failed to decrypt sealed secret: %s", exc.__class__.__name__)
        return ""


def is_sealed(value: Optional[str]) -> bool:
    return bool(value and str(value).startswith(_PREFIX))
