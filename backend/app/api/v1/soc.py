"""SOC ChatOps / RAG assistant API."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import RequireTenant, require_roles
from app.core.enums import UserRole
from app.models.user import User
from app.schemas.soc_chat import SocChatRequest, SocChatResponse
from app.services.soc_chat import SocChatError, SocChatService

router = APIRouter(prefix="/soc", tags=["soc-chatops"])

RequireSocAnalyst = Annotated[
    User,
    Depends(
        require_roles(
            UserRole.SUPER_ADMIN,
            UserRole.ADMIN,
            UserRole.PENTESTER,
            UserRole.SOC_ANALYST,
        )
    ),
]


@router.post(
    "/chat",
    response_model=SocChatResponse,
    summary="AI SOC ChatOps / RAG assistant",
)
async def soc_chat(
    payload: SocChatRequest,
    tenant: RequireTenant,
    _: RequireSocAnalyst,
    db: AsyncSession = Depends(get_db),
) -> SocChatResponse:
    org_id = None if tenant.cross_tenant else tenant.organization_id
    service = SocChatService(db, organization_id=org_id)
    try:
        result = await service.chat(payload.query)
    except SocChatError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
    return SocChatResponse(
        answer=result.answer,
        provider=result.provider,
        model=result.model,
        intent=result.intent_flags,
        stats=result.stats,
        sources=result.sources,
        context_chars=result.context_chars,
    )
