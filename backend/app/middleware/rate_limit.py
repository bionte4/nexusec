"""Redis-backed rate limiting for sensitive API routes."""

from __future__ import annotations

import logging
import re
import time
from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.core.config import get_settings

logger = logging.getLogger(__name__)

# (method, path regex, max requests, window seconds)
_RULES: list[tuple[str, re.Pattern[str], int, int]] = [
    ("POST", re.compile(r"^/api/v1/auth/login(/form)?$"), 20, 60),
    ("POST", re.compile(r"^/api/v1/auth/register$"), 5, 3600),
    ("POST", re.compile(r"^/api/v1/auth/refresh$"), 60, 60),
    ("POST", re.compile(r"^/api/v1/scans$"), 30, 60),
    ("POST", re.compile(r"^/api/v1/scans/pipeline$"), 10, 60),
    ("POST", re.compile(r"^/api/v1/scans/[^/]+/start$"), 30, 60),
    ("POST", re.compile(r"^/api/v1/vulnerabilities/[^/]+/generate-ai-patch$"), 20, 60),
    ("POST", re.compile(r"^/api/v1/vulnerabilities/[^/]+/analyze-fp$"), 20, 60),
    ("POST", re.compile(r"^/api/v1/vulnerabilities/bulk-generate-ai-patch$"), 5, 60),
    ("GET", re.compile(r"^/api/v1/reports/engagement(/pdf)?$"), 30, 60),
    ("GET", re.compile(r"^/api/v1/reports/[^/]+(/pdf)?$"), 40, 60),
]

_memory_buckets: dict[str, list[float]] = {}


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip() or "unknown"
    if request.client:
        return request.client.host or "unknown"
    return "unknown"


def _match_rule(method: str, path: str) -> Optional[tuple[str, int, int]]:
    for rule_method, pattern, limit, window in _RULES:
        if method.upper() != rule_method:
            continue
        if pattern.match(path):
            return (pattern.pattern, limit, window)
    return None


def _redis_hit(key: str, limit: int, window: int) -> tuple[bool, int]:
    settings = get_settings()
    try:
        import redis

        client = redis.Redis.from_url(
            settings.redis_url, decode_responses=True, socket_timeout=1
        )
        count = int(client.incr(key))
        if count == 1:
            client.expire(key, window)
        ttl = int(client.ttl(key) or window)
        return count <= limit, max(ttl, 0)
    except Exception:
        logger.debug("Rate limit Redis unavailable — using memory fallback", exc_info=False)
        return _memory_hit(key, limit, window)


def _memory_hit(key: str, limit: int, window: int) -> tuple[bool, int]:
    now = time.time()
    bucket = _memory_buckets.setdefault(key, [])
    cutoff = now - window
    bucket[:] = [t for t in bucket if t >= cutoff]
    bucket.append(now)
    retry_after = int(window - (now - bucket[0])) if bucket else window
    return len(bucket) <= limit, max(retry_after, 1)


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        settings = get_settings()
        if not getattr(settings, "rate_limit_enabled", True):
            return await call_next(request)

        matched = _match_rule(request.method, request.url.path)
        if matched is None:
            return await call_next(request)

        pattern, limit, window = matched
        ip = _client_ip(request)
        key = f"nexusec:rl:{pattern}:{ip}"
        allowed, retry_after = _redis_hit(key, limit, window)
        if not allowed:
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Rate limit exceeded. Slow down and retry.",
                    "retry_after_seconds": retry_after,
                },
                headers={"Retry-After": str(retry_after)},
            )
        return await call_next(request)
