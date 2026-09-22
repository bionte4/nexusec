"""AI SOC ChatOps / lightweight RAG assistant.

Retrieves tenant-scoped assets, scans, and vulnerabilities from PostgreSQL
based on query keywords, then answers via OpenAI/Anthropic or a deterministic mock.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from uuid import UUID

import httpx
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import Settings, get_settings
from app.core.enums import ACTIVE_FINDING_STATUSES, FindingStatus, Severity
from app.models.asset import Asset
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are NexuSec SOC ChatOps, a professional security operations assistant.
Answer the analyst's question using ONLY the provided database context.
Be concise, actionable, and compliance-aware (PCI-DSS, ISO 27001, GDPR where relevant).
If the context is insufficient, say what is missing — do not invent findings or assets.
Prefer bullet points for lists. Never include secrets, tokens, or exploit payloads.
"""


@dataclass
class RetrievalIntent:
    pci_dss: bool = False
    cde: bool = False
    critical: bool = False
    high: bool = False
    kev: bool = False
    this_week: bool = False
    false_positive: bool = False
    assets: bool = False
    scans: bool = False
    vulnerabilities: bool = True
    search_terms: list[str] = field(default_factory=list)


@dataclass
class RAGContext:
    intent: RetrievalIntent
    snippets: list[str]
    stats: dict[str, Any]
    sources: list[dict[str, Any]]

    def as_prompt_block(self) -> str:
        parts = ["## Retrieved database context", ""]
        if self.stats:
            parts.append("### Summary stats")
            for k, v in self.stats.items():
                parts.append(f"- {k}: {v}")
            parts.append("")
        if self.snippets:
            parts.append("### Details")
            parts.extend(self.snippets)
        else:
            parts.append("(No matching rows found for this query.)")
        return "\n".join(parts)


@dataclass
class SocChatResult:
    answer: str
    provider: str
    model: str
    intent_flags: dict[str, bool]
    sources: list[dict[str, Any]]
    stats: dict[str, Any]
    context_chars: int


class SocChatError(Exception):
    def __init__(self, message: str, *, status_code: int = 502) -> None:
        super().__init__(message)
        self.status_code = status_code


_STOPWORDS = frozenset(
    {
        "a",
        "an",
        "the",
        "which",
        "what",
        "who",
        "where",
        "when",
        "how",
        "are",
        "is",
        "was",
        "were",
        "do",
        "does",
        "did",
        "can",
        "could",
        "should",
        "would",
        "show",
        "list",
        "give",
        "me",
        "us",
        "please",
        "currently",
        "current",
        "this",
        "that",
        "these",
        "those",
        "of",
        "in",
        "on",
        "for",
        "to",
        "and",
        "or",
        "with",
        "from",
        "about",
        "any",
        "all",
        "our",
        "my",
        "their",
        "have",
        "has",
        "been",
        "be",
        "summarize",
        "summary",
        "report",
        "tell",
    }
)


def classify_intent(query: str) -> RetrievalIntent:
    q = query.lower()
    intent = RetrievalIntent()
    intent.pci_dss = any(x in q for x in ("pci", "pci-dss", "pci dss", "dss"))
    intent.cde = "cde" in q or "cardholder" in q
    intent.critical = "critical" in q
    intent.high = "high" in q or "high-severity" in q
    intent.kev = any(x in q for x in ("kev", "actively exploited", "known exploited"))
    intent.this_week = any(
        x in q for x in ("this week", "past week", "last 7", "last seven", "7 days")
    )
    intent.false_positive = "false positive" in q or "fp" in q.split()
    intent.assets = any(x in q for x in ("asset", "assets", "host", "hosts", "server"))
    intent.scans = any(x in q for x in ("scan", "scans", "scanning"))
    # Always pull vulns unless query is purely about assets/scans inventory
    if intent.assets and not any(
        x in q for x in ("vulnerab", "finding", "cve", "cwe", "pci", "critical", "risk")
    ):
        intent.vulnerabilities = "vulnerab" in q or "finding" in q
    else:
        intent.vulnerabilities = True

    tokens = re.findall(r"[a-z0-9][a-z0-9\-_.]{1,40}", q)
    intent.search_terms = [t for t in tokens if t not in _STOPWORDS and len(t) > 2][:12]
    return intent


def _sev_val(sev: Severity | str) -> str:
    return sev.value if isinstance(sev, Severity) else str(sev)


class SocChatService:
    def __init__(
        self,
        db: AsyncSession,
        *,
        organization_id: Optional[UUID] = None,
        settings: Optional[Settings] = None,
    ) -> None:
        self.db = db
        self.organization_id = organization_id
        self.settings = settings or get_settings()

    def _org_filter_vuln(self, *clauses):  # type: ignore[no-untyped-def]
        filters = list(clauses)
        if self.organization_id is not None:
            filters.append(Vulnerability.organization_id == self.organization_id)
        return filters

    def _org_filter_asset(self, *clauses):  # type: ignore[no-untyped-def]
        filters = list(clauses)
        if self.organization_id is not None:
            filters.append(Asset.organization_id == self.organization_id)
        return filters

    def _org_filter_scan(self, *clauses):  # type: ignore[no-untyped-def]
        filters = list(clauses)
        if self.organization_id is not None:
            filters.append(Scan.organization_id == self.organization_id)
        return filters

    @property
    def provider(self) -> str:
        return (self.settings.ai_soc_chat_provider or "auto").lower().strip()

    def resolve_provider(self) -> str:
        chosen = self.provider
        if chosen in {"openai", "anthropic", "mock"}:
            if chosen == "openai" and not self.settings.openai_api_key:
                raise SocChatError("OPENAI_API_KEY is not configured", status_code=400)
            if chosen == "anthropic" and not self.settings.anthropic_api_key:
                raise SocChatError("ANTHROPIC_API_KEY is not configured", status_code=400)
            return chosen
        if self.settings.openai_api_key:
            return "openai"
        if self.settings.anthropic_api_key:
            return "anthropic"
        return "mock"

    async def chat(self, query: str) -> SocChatResult:
        if not self.settings.ai_soc_chat_enabled:
            raise SocChatError("SOC ChatOps is disabled", status_code=503)

        cleaned = (query or "").strip()
        if len(cleaned) < 3:
            raise SocChatError("Query is too short", status_code=400)
        if len(cleaned) > self.settings.ai_soc_chat_max_query_chars:
            raise SocChatError("Query exceeds maximum length", status_code=400)

        rag = await self.retrieve(cleaned)
        provider = self.resolve_provider()
        if provider == "mock":
            answer = mock_answer(cleaned, rag)
            model = "rag-template-v1"
        else:
            try:
                if provider == "openai":
                    answer, model = await self._call_openai(cleaned, rag)
                else:
                    answer, model = await self._call_anthropic(cleaned, rag)
            except SocChatError:
                raise
            except Exception as exc:
                logger.exception("SOC chat provider %s failed", provider)
                if self.settings.ai_soc_chat_fallback_mock:
                    logger.warning("Falling back to mock SOC chat after provider error")
                    answer = mock_answer(cleaned, rag)
                    provider = "mock"
                    model = "rag-template-v1"
                else:
                    raise SocChatError(
                        f"AI provider error: {exc.__class__.__name__}", status_code=502
                    ) from exc

        return SocChatResult(
            answer=answer.strip(),
            provider=provider,
            model=model,
            intent_flags={
                "pci_dss": rag.intent.pci_dss,
                "cde": rag.intent.cde,
                "critical": rag.intent.critical,
                "high": rag.intent.high,
                "kev": rag.intent.kev,
                "this_week": rag.intent.this_week,
                "false_positive": rag.intent.false_positive,
                "assets": rag.intent.assets,
                "scans": rag.intent.scans,
                "vulnerabilities": rag.intent.vulnerabilities,
            },
            sources=rag.sources[: self.settings.ai_soc_chat_max_sources],
            stats=rag.stats,
            context_chars=len(rag.as_prompt_block()),
        )

    async def retrieve(self, query: str) -> RAGContext:
        intent = classify_intent(query)
        limit = self.settings.ai_soc_chat_retrieval_limit
        snippets: list[str] = []
        sources: list[dict[str, Any]] = []
        stats: dict[str, Any] = {}

        # Always include active severity counts for baseline posture
        sev_rows = (
            await self.db.execute(
                select(Vulnerability.severity, func.count())
                .where(
                    *self._org_filter_vuln(
                        Vulnerability.status.in_(tuple(ACTIVE_FINDING_STATUSES))
                    )
                )
                .group_by(Vulnerability.severity)
            )
        ).all()
        active_by_sev = {_sev_val(s): int(c) for s, c in sev_rows}
        stats["active_findings_by_severity"] = active_by_sev
        stats["active_findings_total"] = sum(active_by_sev.values())

        if intent.pci_dss or intent.cde:
            await self._retrieve_pci_cde(snippets, sources, stats, limit=limit)

        if intent.vulnerabilities:
            await self._retrieve_vulnerabilities(intent, snippets, sources, limit=limit)

        if intent.assets or intent.pci_dss or intent.cde:
            await self._retrieve_assets(intent, snippets, sources, limit=min(limit, 15))

        if intent.scans:
            await self._retrieve_scans(snippets, sources, limit=min(limit, 10))

        # Soft keyword search across titles when terms present
        if intent.search_terms and intent.vulnerabilities:
            await self._retrieve_keyword_hits(intent, snippets, sources, limit=8)

        return RAGContext(intent=intent, snippets=snippets, stats=stats, sources=sources)

    async def _retrieve_pci_cde(
        self,
        snippets: list[str],
        sources: list[dict[str, Any]],
        stats: dict[str, Any],
        *,
        limit: int,
    ) -> None:
        cde_count = int(
            await self.db.scalar(
                select(func.count()).select_from(Asset).where(*self._org_filter_asset(Asset.is_cde_scope.is_(True)))
            )
            or 0
        )
        stats["cde_assets"] = cde_count

        # Active findings on CDE assets
        stmt = (
            select(Vulnerability, Asset)
            .join(Asset, Asset.id == Vulnerability.asset_id)
            .where(
                *self._org_filter_vuln(
                    Asset.is_cde_scope.is_(True),
                    Vulnerability.status.in_(tuple(ACTIVE_FINDING_STATUSES)),
                )
            )
            .order_by(Vulnerability.severity.asc(), Vulnerability.cvss_score.desc().nullslast())
            .limit(limit)
        )
        rows = (await self.db.execute(stmt)).all()
        stats["active_findings_on_cde"] = len(rows)
        snippets.append(
            f"PCI-DSS / CDE: {cde_count} CDE-scoped asset(s); "
            f"{len(rows)} active finding(s) retrieved on CDE assets."
        )
        for vuln, asset in rows:
            line = (
                f"- [CDE] asset={asset.name} ({_sev_val(getattr(asset, 'asset_type', 'asset'))}) "
                f"| {_sev_val(vuln.severity)} | {vuln.title}"
                f"{f' | {vuln.cve_id}' if vuln.cve_id else ''}"
                f" | status={_sev_val(vuln.status)}"
            )
            snippets.append(line)
            sources.append(
                {
                    "type": "vulnerability",
                    "id": str(vuln.id),
                    "title": vuln.title,
                    "asset": asset.name,
                    "severity": _sev_val(vuln.severity),
                    "tag": "cde",
                }
            )

        # Also assets marked CDE without necessarily having findings
        asset_stmt = (
            select(Asset)
            .where(*self._org_filter_asset(Asset.is_cde_scope.is_(True)))
            .order_by(Asset.name.asc())
            .limit(min(limit, 20))
        )
        assets = (await self.db.execute(asset_stmt)).scalars().all()
        if assets:
            snippets.append("CDE assets:")
            for a in assets:
                snippets.append(
                    f"- {a.name} | type={_sev_val(a.asset_type)} | "
                    f"criticality={_sev_val(a.criticality)} | "
                    f"env={a.environment or 'n/a'}"
                )
                sources.append(
                    {
                        "type": "asset",
                        "id": str(a.id),
                        "name": a.name,
                        "tag": "cde",
                    }
                )

    async def _retrieve_vulnerabilities(
        self,
        intent: RetrievalIntent,
        snippets: list[str],
        sources: list[dict[str, Any]],
        *,
        limit: int,
    ) -> None:
        filters = [
            Vulnerability.status.in_(tuple(ACTIVE_FINDING_STATUSES)),
        ]
        if intent.false_positive:
            filters = [Vulnerability.status == FindingStatus.FALSE_POSITIVE]
        if intent.critical and not intent.high:
            filters.append(Vulnerability.severity == Severity.CRITICAL)
        elif intent.high and not intent.critical:
            filters.append(Vulnerability.severity.in_((Severity.HIGH, Severity.CRITICAL)))
        elif intent.critical and intent.high:
            filters.append(Vulnerability.severity.in_((Severity.CRITICAL, Severity.HIGH)))
        if intent.kev:
            filters.append(Vulnerability.is_actively_exploited.is_(True))
        if intent.this_week:
            since = datetime.now(timezone.utc) - timedelta(days=7)
            filters.append(Vulnerability.first_seen_at >= since)

        stmt = (
            select(Vulnerability)
            .options(selectinload(Vulnerability.asset))
            .where(*self._org_filter_vuln(*filters))
            .order_by(
                Vulnerability.severity.asc(),
                Vulnerability.threat_risk_score.desc().nullslast(),
                Vulnerability.cvss_score.desc().nullslast(),
            )
            .limit(limit)
        )
        vulns = (await self.db.execute(stmt)).scalars().all()
        label = "Active vulnerabilities"
        if intent.this_week:
            label = "Vulnerabilities first seen this week"
        if intent.kev:
            label = "KEV / actively exploited findings"
        if intent.false_positive:
            label = "False-positive findings"
        if intent.critical:
            label = "Critical " + label.lower()
        snippets.append(f"{label} (showing {len(vulns)}):")
        for v in vulns:
            asset_name = v.asset.name if v.asset else str(v.asset_id)
            snippets.append(
                f"- {_sev_val(v.severity)} | {v.title} | asset={asset_name}"
                f"{f' | CVE={v.cve_id}' if v.cve_id else ''}"
                f"{f' | CWE={v.cwe_id}' if v.cwe_id else ''}"
                f" | status={_sev_val(v.status)}"
                f"{' | KEV' if v.is_actively_exploited else ''}"
            )
            sources.append(
                {
                    "type": "vulnerability",
                    "id": str(v.id),
                    "title": v.title,
                    "severity": _sev_val(v.severity),
                    "asset": asset_name,
                }
            )

    async def _retrieve_assets(
        self,
        intent: RetrievalIntent,
        snippets: list[str],
        sources: list[dict[str, Any]],
        *,
        limit: int,
    ) -> None:
        # CDE inventory already emitted by _retrieve_pci_cde
        if intent.pci_dss or intent.cde:
            return
        stmt = (
            select(Asset)
            .where(*self._org_filter_asset())
            .order_by(Asset.criticality.asc(), Asset.name.asc())
            .limit(limit)
        )
        assets = (await self.db.execute(stmt)).scalars().all()
        if not assets:
            return
        snippets.append(f"Assets (showing {len(assets)}):")
        for a in assets:
            snippets.append(
                f"- {a.name} | {_sev_val(a.asset_type)} | "
                f"criticality={_sev_val(a.criticality)} | "
                f"cde={a.is_cde_scope}"
            )
            sources.append({"type": "asset", "id": str(a.id), "name": a.name})

    async def _retrieve_scans(
        self,
        snippets: list[str],
        sources: list[dict[str, Any]],
        *,
        limit: int,
    ) -> None:
        stmt = (
            select(Scan)
            .where(*self._org_filter_scan())
            .order_by(Scan.created_at.desc())
            .limit(limit)
        )
        scans = (await self.db.execute(stmt)).scalars().all()
        snippets.append(f"Recent scans (showing {len(scans)}):")
        for s in scans:
            snippets.append(
                f"- {s.name} | type={_sev_val(s.scan_type)} | "
                f"engine={_sev_val(s.engine)} | status={_sev_val(s.status)} | "
                f"progress={s.progress:.0%}"
            )
            sources.append(
                {
                    "type": "scan",
                    "id": str(s.id),
                    "name": s.name,
                    "status": _sev_val(s.status),
                }
            )

    async def _retrieve_keyword_hits(
        self,
        intent: RetrievalIntent,
        snippets: list[str],
        sources: list[dict[str, Any]],
        *,
        limit: int,
    ) -> None:
        # Skip generic severity/compliance terms already handled
        skip = {
            "critical",
            "high",
            "medium",
            "low",
            "info",
            "pci",
            "dss",
            "cde",
            "kev",
            "week",
            "days",
            "false",
            "positive",
            "asset",
            "assets",
            "scan",
            "scans",
            "vulnerabilities",
            "vulnerability",
            "finding",
            "findings",
            "summarize",
            "requirements",
            "violate",
            "violation",
        }
        terms = [t for t in intent.search_terms if t not in skip][:5]
        if not terms:
            return
        clauses = []
        for t in terms:
            like = f"%{t}%"
            clauses.append(Vulnerability.title.ilike(like))
            clauses.append(Vulnerability.description.ilike(like))
            clauses.append(Vulnerability.cve_id.ilike(like))
            clauses.append(Vulnerability.cwe_id.ilike(like))
        stmt = (
            select(Vulnerability)
            .options(selectinload(Vulnerability.asset))
            .where(*self._org_filter_vuln(or_(*clauses)))
            .order_by(Vulnerability.severity.asc())
            .limit(limit)
        )
        rows = (await self.db.execute(stmt)).scalars().all()
        if not rows:
            return
        # Deduplicate against existing source ids
        existing = {s.get("id") for s in sources if s.get("type") == "vulnerability"}
        fresh = [v for v in rows if str(v.id) not in existing]
        if not fresh:
            return
        snippets.append(f"Keyword matches ({', '.join(terms)}):")
        for v in fresh:
            asset_name = v.asset.name if v.asset else str(v.asset_id)
            snippets.append(f"- {_sev_val(v.severity)} | {v.title} | asset={asset_name}")
            sources.append(
                {
                    "type": "vulnerability",
                    "id": str(v.id),
                    "title": v.title,
                    "severity": _sev_val(v.severity),
                }
            )

    async def _call_openai(self, query: str, rag: RAGContext) -> tuple[str, str]:
        model = self.settings.openai_model
        url = self.settings.openai_api_base.rstrip("/") + "/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.settings.openai_api_key}",
            "Content-Type": "application/json",
        }
        user_content = (
            f"{rag.as_prompt_block()}\n\n"
            f"## Analyst question\n{query}\n\n"
            "Provide a concise SOC answer with actionable next steps."
        )
        body = {
            "model": model,
            "temperature": 0.2,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_content},
            ],
        }
        async with httpx.AsyncClient(timeout=self.settings.ai_soc_chat_timeout_seconds) as client:
            resp = await client.post(url, headers=headers, json=body)
            if resp.status_code >= 400:
                raise SocChatError(f"OpenAI API returned {resp.status_code}", status_code=502)
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            return str(content), model

    async def _call_anthropic(self, query: str, rag: RAGContext) -> tuple[str, str]:
        model = self.settings.anthropic_model
        url = self.settings.anthropic_api_base.rstrip("/") + "/v1/messages"
        headers = {
            "x-api-key": self.settings.anthropic_api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        user_content = (
            f"{rag.as_prompt_block()}\n\n"
            f"## Analyst question\n{query}\n\n"
            "Provide a concise SOC answer with actionable next steps."
        )
        body = {
            "model": model,
            "max_tokens": 1536,
            "temperature": 0.2,
            "system": SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": user_content}],
        }
        async with httpx.AsyncClient(timeout=self.settings.ai_soc_chat_timeout_seconds) as client:
            resp = await client.post(url, headers=headers, json=body)
            if resp.status_code >= 400:
                raise SocChatError(f"Anthropic API returned {resp.status_code}", status_code=502)
            data = resp.json()
            parts = data.get("content") or []
            text = "".join(str(p.get("text") or "") for p in parts if p.get("type") == "text")
            if not text:
                raise SocChatError("Empty Anthropic response")
            return text, model


def mock_answer(query: str, rag: RAGContext) -> str:
    """Deterministic ChatOps answer from retrieved context (no LLM)."""
    lines: list[str] = [
        "### NexuSec SOC summary (offline / mock RAG)",
        "",
        f"**Question:** {query.strip()}",
        "",
    ]
    total = rag.stats.get("active_findings_total")
    by_sev = rag.stats.get("active_findings_by_severity") or {}
    if total is not None:
        lines.append(
            f"**Active findings:** {total} "
            f"(critical={by_sev.get('critical', 0)}, high={by_sev.get('high', 0)}, "
            f"medium={by_sev.get('medium', 0)}, low={by_sev.get('low', 0)})."
        )
    if "cde_assets" in rag.stats:
        lines.append(
            f"**PCI-DSS CDE:** {rag.stats['cde_assets']} CDE asset(s); "
            f"{rag.stats.get('active_findings_on_cde', 0)} active finding(s) on CDE scope retrieved."
        )
    lines.append("")
    lines.append("**Retrieved evidence:**")
    detail = [s for s in rag.snippets if s.startswith("-")][:12]
    if detail:
        lines.extend(detail)
    else:
        lines.append("- No matching rows for the detected intent filters.")
    lines.append("")
    lines.append("**Recommended actions:**")
    if rag.intent.pci_dss or rag.intent.cde:
        lines.append(
            "1. Prioritize remediation on CDE-scoped assets (PCI-DSS Req 11 / segmentation)."
        )
        lines.append("2. Confirm compensating controls and re-scan after patches.")
    elif rag.intent.kev:
        lines.append("1. Treat KEV items as emergency change — patch or mitigate immediately.")
        lines.append("2. Validate exploitability and update threat-risk scores.")
    elif rag.intent.critical:
        lines.append("1. Assign owners to all critical findings and set SLA clocks.")
        lines.append("2. Generate AI remediation patches where applicable.")
    else:
        lines.append("1. Triage top severity findings and assign remediation owners.")
        lines.append("2. Re-query with narrower filters (severity, CDE, CVE) if needed.")
    lines.append("")
    lines.append("_Generated by NexuSec mock RAG. Configure OPENAI_API_KEY or ANTHROPIC_API_KEY for LLM answers._")
    return "\n".join(lines)
