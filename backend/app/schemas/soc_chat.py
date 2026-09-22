"""Schemas for SOC ChatOps / RAG assistant."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class SocChatRequest(BaseModel):
    query: str = Field(
        min_length=3,
        max_length=4000,
        examples=[
            "Which assets currently violate PCI-DSS requirements?",
            "Summarize critical vulnerabilities this week",
        ],
    )


class SocChatResponse(BaseModel):
    answer: str
    provider: str
    model: str
    intent: dict[str, bool] = Field(default_factory=dict)
    stats: dict[str, Any] = Field(default_factory=dict)
    sources: list[dict[str, Any]] = Field(default_factory=list)
    context_chars: int = 0
