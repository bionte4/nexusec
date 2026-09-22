"""Middleware that audits state-changing HTTP requests."""

from __future__ import annotations

import logging
import re
from typing import Optional
from uuid import UUID

from jose import JWTError
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from app.core.database import AsyncSessionLocal
from app.core.security import TOKEN_TYPE_ACCESS, decode_token
from app.services.audit_service import AuditService

logger = logging.getLogger(__name__)

MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

SKIP_PATH_PREFIXES = (
    "/docs",
    "/redoc",
    "/openapi.json",
    "/favicon.ico",
)

SKIP_EXACT_PATHS = {
    "/",
    "/health",
    "/metrics",
    "/api/v1/health",
    "/api/v1/health/live",
    "/api/v1/health/ready",
    "/api/v1/auth/login",
    "/api/v1/auth/login/form",
    "/api/v1/auth/refresh",
}

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def _client_ip(request: Request) -> Optional[str]:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return None


def _actor_from_request(request: Request) -> tuple[Optional[UUID], Optional[UUID]]:
    """Return (actor_id, organization_id) from Bearer JWT."""
    auth = request.headers.get("authorization") or ""
    if not auth.lower().startswith("bearer "):
        return None, None
    token = auth.split(" ", 1)[1].strip()
    try:
        payload = decode_token(token)
        if payload.get("type") != TOKEN_TYPE_ACCESS:
            return None, None
        actor_id = UUID(str(payload["sub"]))
        org_raw = payload.get("org")
        org_id = UUID(str(org_raw)) if org_raw else None
        header_org = request.headers.get("x-organization-id")
        if header_org:
            try:
                org_id = UUID(header_org)
            except ValueError:
                pass
        return actor_id, org_id
    except (JWTError, ValueError, TypeError, KeyError):
        return None, None


def _actor_id_from_request(request: Request) -> Optional[UUID]:
    actor_id, _ = _actor_from_request(request)
    return actor_id


def _parse_resource(path: str) -> tuple[str, Optional[str]]:
    """
    /api/v1/assets/{uuid} -> ('assets', uuid)
    /api/v1/auth/register -> ('auth', 'register')
    """
    parts = [p for p in path.split("/") if p]
    if len(parts) >= 2 and parts[0] == "api" and parts[1].startswith("v"):
        parts = parts[2:]
    if not parts:
        return "root", None
    resource_type = parts[0]
    resource_id: Optional[str] = None
    if len(parts) >= 2:
        candidate = parts[1]
        resource_id = candidate if _UUID_RE.match(candidate) else candidate
    return resource_type, resource_id


class AuditTrailMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)

        if request.method not in MUTATING_METHODS:
            return response

        path = request.url.path
        if path in SKIP_EXACT_PATHS or any(path.startswith(p) for p in SKIP_PATH_PREFIXES):
            return response

        resource_type, resource_id = _parse_resource(path)
        action = f"{request.method} {path}"
        actor_id, organization_id = _actor_from_request(request)

        try:
            async with AsyncSessionLocal() as session:
                service = AuditService(session)
                await service.record(
                    action=action,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    actor_id=actor_id,
                    organization_id=organization_id,
                    details={
                        "method": request.method,
                        "path": path,
                        "query": str(request.url.query) if request.url.query else None,
                    },
                    ip_address=_client_ip(request),
                    user_agent=request.headers.get("user-agent"),
                    status_code=response.status_code,
                )
                await session.commit()
        except Exception:
            # Never fail the request because auditing failed
            logger.exception("Failed to write audit log for %s %s", request.method, path)

        return response
