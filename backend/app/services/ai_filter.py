"""AI-driven false-positive analysis for vulnerability findings.

Evaluates scan output + asset context via OpenAI/Anthropic (HTTP), with a
deterministic heuristic mock when no API key is configured.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx

from app.core.config import Settings, get_settings
from app.core.enums import Severity

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a senior SOC analyst specializing in vulnerability triage.
Evaluate whether a scanner finding is likely a FALSE POSITIVE given the context.

Respond with ONLY valid JSON (no markdown fences) using this exact schema:
{
  "confidence_score": 0.0,
  "is_likely_false_positive": false,
  "reasoning": "Brief explanation for the SOC analyst (2-4 sentences)."
}

Rules:
- confidence_score must be a float between 0 and 1 (how confident you are in the FP/TP judgment).
- is_likely_false_positive is true only when evidence strongly suggests a false positive
  (version mismatch, wrong service banner, informational noise, unreachable port, etc.).
- Prefer true positive when CVE/KEV context or strong exploitability signals are present.
- Be concise and actionable for SOC review. Never invent exploit payloads.
"""


@dataclass
class FPAnalysisContext:
    title: str
    description: Optional[str]
    cwe_id: Optional[str]
    severity: Severity | str
    asset_type: Optional[str] = None
    asset_name: Optional[str] = None
    asset_criticality: Optional[str] = None
    cve_id: Optional[str] = None
    affected_component: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    banner: Optional[str] = None
    source_tool: Optional[str] = None
    evidence: dict[str, Any] = field(default_factory=dict)
    is_actively_exploited: bool = False
    has_public_exploit: bool = False
    cvss_score: Optional[float] = None


@dataclass
class FPAnalysisResult:
    confidence_score: float
    is_likely_false_positive: bool
    reasoning: str
    provider: str
    model: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "confidence_score": self.confidence_score,
            "is_likely_false_positive": self.is_likely_false_positive,
            "reasoning": self.reasoning,
            "provider": self.provider,
            "model": self.model,
        }


class AIFPAnalysisError(Exception):
    def __init__(self, message: str, *, status_code: int = 502) -> None:
        super().__init__(message)
        self.status_code = status_code


def _severity_str(severity: Severity | str) -> str:
    return severity.value if isinstance(severity, Severity) else str(severity)


def extract_banner(evidence: Optional[dict[str, Any]]) -> Optional[str]:
    """Pull banner/service strings from normalized evidence JSON."""
    if not evidence:
        return None
    for key in (
        "banner",
        "service_banner",
        "server_banner",
        "product",
        "service",
        "version",
        "http_server",
        "ssl_subject",
    ):
        val = evidence.get(key)
        if val is not None and str(val).strip():
            return str(val).strip()[:500]
    nested = evidence.get("service_info") or evidence.get("nmap") or evidence.get("raw")
    if isinstance(nested, dict):
        return extract_banner(nested)
    if isinstance(nested, str) and nested.strip():
        return nested.strip()[:500]
    return None


def build_user_prompt(ctx: FPAnalysisContext) -> str:
    evidence_preview = ""
    if ctx.evidence:
        try:
            evidence_preview = json.dumps(ctx.evidence, default=str)[:1500]
        except (TypeError, ValueError):
            evidence_preview = str(ctx.evidence)[:1500]
    return (
        f"Title: {ctx.title}\n"
        f"Severity: {_severity_str(ctx.severity)}\n"
        f"CVSS: {ctx.cvss_score if ctx.cvss_score is not None else 'n/a'}\n"
        f"CWE: {ctx.cwe_id or 'unknown'}\n"
        f"CVE: {ctx.cve_id or 'n/a'}\n"
        f"Actively exploited (KEV): {ctx.is_actively_exploited}\n"
        f"Public exploit: {ctx.has_public_exploit}\n"
        f"Asset name: {ctx.asset_name or 'unknown'}\n"
        f"Asset type: {ctx.asset_type or 'unknown'}\n"
        f"Asset criticality: {ctx.asset_criticality or 'unknown'}\n"
        f"Affected component: {ctx.affected_component or 'n/a'}\n"
        f"Port: {ctx.port if ctx.port is not None else 'n/a'}\n"
        f"Protocol: {ctx.protocol or 'n/a'}\n"
        f"Banner / service info: {ctx.banner or 'n/a'}\n"
        f"Source tool: {ctx.source_tool or 'n/a'}\n"
        f"Description: {ctx.description or 'No description provided.'}\n"
        f"Evidence (truncated): {evidence_preview or 'n/a'}\n"
    )


def _extract_json(text: str) -> dict[str, Any]:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{[\s\S]*\}", text)
    if match:
        return json.loads(match.group(0))
    raise AIFPAnalysisError("LLM response was not valid JSON")


def _normalize_payload(data: dict[str, Any]) -> dict[str, Any]:
    try:
        score = float(data.get("confidence_score"))
    except (TypeError, ValueError) as exc:
        raise AIFPAnalysisError("Invalid confidence_score in LLM response") from exc
    score = max(0.0, min(1.0, score))
    is_fp = data.get("is_likely_false_positive")
    if isinstance(is_fp, str):
        is_fp = is_fp.strip().lower() in {"true", "1", "yes"}
    else:
        is_fp = bool(is_fp)
    reasoning = str(data.get("reasoning") or "").strip()
    if not reasoning:
        raise AIFPAnalysisError("LLM response missing reasoning")
    return {
        "confidence_score": round(score, 4),
        "is_likely_false_positive": is_fp,
        "reasoning": reasoning,
    }


def mock_fp_analysis(ctx: FPAnalysisContext) -> FPAnalysisResult:
    """Heuristic fallback when LLM credentials are unavailable."""
    sev = _severity_str(ctx.severity).lower()
    title_l = (ctx.title or "").lower()
    desc_l = (ctx.description or "").lower()
    banner_l = (ctx.banner or "").lower()
    soft_signals = (
        "possible",
        "potential",
        "informational",
        "best practice",
        "detection only",
        "unconfirmed",
    )
    soft = any(s in title_l or s in desc_l for s in soft_signals)

    # Strong true-positive signals
    if ctx.is_actively_exploited or ctx.has_public_exploit:
        return FPAnalysisResult(
            confidence_score=0.88,
            is_likely_false_positive=False,
            reasoning=(
                f"Finding '{ctx.title}' has active exploitation and/or public exploit "
                f"signals. Treat as a true positive pending analyst confirmation; "
                f"do not dismiss as FP without strong contradictory evidence."
            ),
            provider="mock",
            model="heuristic-v1",
        )

    if ctx.cve_id and sev in {"critical", "high"}:
        return FPAnalysisResult(
            confidence_score=0.78,
            is_likely_false_positive=False,
            reasoning=(
                f"High/critical severity with CVE {ctx.cve_id} on "
                f"{ctx.asset_name or 'the asset'} "
                f"(port {ctx.port if ctx.port is not None else 'n/a'}). "
                f"Banner: {ctx.banner or 'unavailable'}. Likely a true positive; "
                f"verify version/patch level before closing."
            ),
            provider="mock",
            model="heuristic-v1",
        )

    # Weak / noise signals → likely FP
    if sev in {"info", "unknown"} or soft:
        return FPAnalysisResult(
            confidence_score=0.72,
            is_likely_false_positive=True,
            reasoning=(
                f"'{ctx.title}' appears informational or weakly evidenced "
                f"(severity={sev}, banner={ctx.banner or 'n/a'}). "
                f"Recommend marking as candidate false positive after a quick "
                f"sanity check of the scanner fingerprint."
            ),
            provider="mock",
            model="heuristic-v1",
        )

    # Banner vs component mismatch heuristic
    component = (ctx.affected_component or "").lower()
    if banner_l and component and component not in banner_l and banner_l not in component:
        if any(tok in component for tok in ("apache", "nginx", "openssl", "openssh", "mysql")):
            if not any(tok in banner_l for tok in component.split()[:1]):
                return FPAnalysisResult(
                    confidence_score=0.65,
                    is_likely_false_positive=True,
                    reasoning=(
                        f"Possible product mismatch: finding targets '{ctx.affected_component}' "
                        f"but service banner reports '{ctx.banner}'. "
                        f"SOC should confirm the service identity before remediation."
                    ),
                    provider="mock",
                    model="heuristic-v1",
                )

    # Default: uncertain true positive
    return FPAnalysisResult(
        confidence_score=0.55,
        is_likely_false_positive=False,
        reasoning=(
            f"Insufficient contradictory signals for '{ctx.title}' "
            f"(severity={sev}, port={ctx.port}, tool={ctx.source_tool or 'n/a'}). "
            f"Defaulting to likely true positive with moderate confidence; "
            f"analyst should review evidence and banner before disposition."
        ),
        provider="mock",
        model="heuristic-v1",
    )


class AIFPAnalysisService:
    def __init__(self, settings: Optional[Settings] = None) -> None:
        self.settings = settings or get_settings()

    @property
    def provider(self) -> str:
        return (self.settings.ai_fp_provider or "auto").lower().strip()

    def resolve_provider(self) -> str:
        chosen = self.provider
        if chosen in {"openai", "anthropic", "mock"}:
            if chosen == "openai" and not self.settings.openai_api_key:
                raise AIFPAnalysisError("OPENAI_API_KEY is not configured", status_code=400)
            if chosen == "anthropic" and not self.settings.anthropic_api_key:
                raise AIFPAnalysisError("ANTHROPIC_API_KEY is not configured", status_code=400)
            return chosen
        if self.settings.openai_api_key:
            return "openai"
        if self.settings.anthropic_api_key:
            return "anthropic"
        return "mock"

    async def analyze(self, ctx: FPAnalysisContext) -> FPAnalysisResult:
        if not self.settings.ai_fp_enabled:
            raise AIFPAnalysisError("AI false-positive analysis is disabled", status_code=503)

        provider = self.resolve_provider()
        if provider == "mock":
            return mock_fp_analysis(ctx)

        user_prompt = build_user_prompt(ctx)
        try:
            if provider == "openai":
                raw, model = await self._call_openai(user_prompt)
            else:
                raw, model = await self._call_anthropic(user_prompt)
            parsed = _normalize_payload(_extract_json(raw))
            return FPAnalysisResult(
                confidence_score=parsed["confidence_score"],
                is_likely_false_positive=parsed["is_likely_false_positive"],
                reasoning=parsed["reasoning"],
                provider=provider,
                model=model,
            )
        except AIFPAnalysisError:
            raise
        except Exception as exc:
            logger.exception("AI FP analysis provider %s failed", provider)
            if self.settings.ai_fp_fallback_mock:
                logger.warning("Falling back to mock FP analysis after provider error")
                return mock_fp_analysis(ctx)
            raise AIFPAnalysisError(
                f"AI provider error: {exc.__class__.__name__}", status_code=502
            ) from exc

    async def _call_openai(self, user_prompt: str) -> tuple[str, str]:
        model = self.settings.openai_model
        url = self.settings.openai_api_base.rstrip("/") + "/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.settings.openai_api_key}",
            "Content-Type": "application/json",
        }
        body = {
            "model": model,
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
        }
        async with httpx.AsyncClient(timeout=self.settings.ai_fp_timeout_seconds) as client:
            resp = await client.post(url, headers=headers, json=body)
            if resp.status_code >= 400:
                raise AIFPAnalysisError(f"OpenAI API returned {resp.status_code}", status_code=502)
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            return str(content), model

    async def _call_anthropic(self, user_prompt: str) -> tuple[str, str]:
        model = self.settings.anthropic_model
        url = self.settings.anthropic_api_base.rstrip("/") + "/v1/messages"
        headers = {
            "x-api-key": self.settings.anthropic_api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        body = {
            "model": model,
            "max_tokens": 1024,
            "temperature": 0.1,
            "system": SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": user_prompt}],
        }
        async with httpx.AsyncClient(timeout=self.settings.ai_fp_timeout_seconds) as client:
            resp = await client.post(url, headers=headers, json=body)
            if resp.status_code >= 400:
                raise AIFPAnalysisError(
                    f"Anthropic API returned {resp.status_code}", status_code=502
                )
            data = resp.json()
            parts = data.get("content") or []
            text = "".join(str(p.get("text") or "") for p in parts if p.get("type") == "text")
            if not text:
                raise AIFPAnalysisError("Empty Anthropic response")
            return text, model
