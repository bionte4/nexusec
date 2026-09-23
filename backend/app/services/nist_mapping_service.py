"""AI / heuristic NIST control mapping suggestions (pending human review)."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import UUID

from openai import AsyncOpenAI
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.enums import Severity
from app.models.vulnerability import Vulnerability
from app.normalization.compliance import enrich_compliance
from app.normalization.schema import NormalizedFinding
from app.services.ai_remediation import (
    AIRemediationError,
    _provider_label,
    resolve_ai_credentials,
)
from app.services.vulnerability_service import VulnerabilityService

logger = logging.getLogger(__name__)


def _heuristic_suggestion(vuln: Vulnerability) -> dict[str, Any]:
    """Reuse enrich_compliance heuristics without requiring LLM."""
    severity = vuln.severity if isinstance(vuln.severity, Severity) else Severity.UNKNOWN
    seed = NormalizedFinding(
        vuln_id=(vuln.fingerprint or "nist")[:64],
        name=vuln.title,
        description=vuln.description,
        severity=severity,
        cwe_id=vuln.cwe_id,
        cve_id=vuln.cve_id,
        port=vuln.port,
        protocol=vuln.protocol,
        affected_component=vuln.affected_component,
        source_tool=vuln.source_tool or "unknown",
    )
    enriched = enrich_compliance(seed)
    return {
        "nist_csf": list(enriched.nist_csf),
        "nist_800_53": list(enriched.nist_800_53),
        "reasoning": (
            "Heuristic mapping from finding title/port/CWE to NIST CSF 2.0 categories "
            "and SP 800-53 Rev.5 controls. Review before accepting."
        ),
        "provider": "heuristic",
        "model": "nexusec-nist-v1",
    }


async def _llm_nist_suggestion(vuln: Vulnerability) -> dict[str, Any]:
    settings = get_settings()
    api_key, base_url, model = resolve_ai_credentials(settings)
    if not api_key or not settings.ai_remediation_enabled:
        return _heuristic_suggestion(vuln)

    client = AsyncOpenAI(
        api_key=api_key,
        base_url=base_url,
        timeout=settings.ai_remediation_timeout_seconds,
        max_retries=1,
    )
    user_prompt = (
        "Return JSON with keys nist_csf (string[]), nist_800_53 (string[]), reasoning (string). "
        "Use real NIST CSF 2.0 IDs (e.g. ID.RA-01, PR.PS-02) and 800-53 IDs (e.g. RA-5, SI-2).\n"
        f"Title: {vuln.title}\nSeverity: {vuln.severity}\nCWE: {vuln.cwe_id}\n"
        f"CVE: {vuln.cve_id}\nPort: {vuln.port}\n"
        f"Description: {(vuln.description or '')[:1200]}"
    )
    try:
        kwargs: dict[str, Any] = {
            "model": model,
            "temperature": 0.1,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You map vulnerability findings to NIST CSF 2.0 and SP 800-53. "
                        "Respond with JSON only."
                    ),
                },
                {"role": "user", "content": user_prompt},
            ],
        }
        if "openai.com" in base_url.lower() or settings.ai_force_json_response:
            kwargs["response_format"] = {"type": "json_object"}
        resp = await client.chat.completions.create(**kwargs)
        content = (resp.choices[0].message.content or "").strip()
        # Strip markdown fences if present
        if content.startswith("```"):
            content = content.strip("`")
            if content.startswith("json"):
                content = content[4:].strip()
        data = json.loads(content)
        csf = [str(x) for x in (data.get("nist_csf") or []) if x][:8]
        sp = [str(x) for x in (data.get("nist_800_53") or []) if x][:8]
        if not csf and not sp:
            return _heuristic_suggestion(vuln)
        base = _heuristic_suggestion(vuln)
        return {
            "nist_csf": csf or base["nist_csf"],
            "nist_800_53": sp or base["nist_800_53"],
            "reasoning": str(data.get("reasoning") or "LLM NIST control suggestion"),
            "provider": _provider_label(base_url),
            "model": model,
        }
    except Exception:
        logger.exception("NIST LLM suggestion failed; using heuristic")
        return _heuristic_suggestion(vuln)
    finally:
        await client.close()


class NISTMappingService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self.vulns = VulnerabilityService(db)

    async def suggest(
        self,
        vulnerability_id: UUID,
        *,
        organization_id: Optional[UUID] = None,
        persist: bool = True,
        use_llm: bool = True,
    ) -> dict[str, Any]:
        vuln = await self.vulns._get_or_raise(  # noqa: SLF001
            vulnerability_id, organization_id=organization_id
        )
        suggestion = (
            await _llm_nist_suggestion(vuln) if use_llm else _heuristic_suggestion(vuln)
        )
        suggestion["status"] = "pending_review"
        suggestion["suggested_at"] = datetime.now(timezone.utc).isoformat()

        if persist:
            meta = dict(vuln.threat_intel_metadata or {})
            meta["nist_mapping_suggestion"] = suggestion
            vuln.threat_intel_metadata = meta
            await self.db.flush()
            vuln = await self.vulns._get_or_raise(  # noqa: SLF001
                vulnerability_id, organization_id=organization_id
            )

        return {
            "vulnerability_id": str(vuln.id),
            **suggestion,
            "current_compliance": {
                "nist_csf": (vuln.compliance_metadata or {}).get("nist_csf") or [],
                "nist_800_53": (vuln.compliance_metadata or {}).get("nist_800_53") or [],
            },
        }

    async def accept(
        self,
        vulnerability_id: UUID,
        *,
        organization_id: Optional[UUID] = None,
        nist_csf: Optional[list[str]] = None,
        nist_800_53: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        vuln = await self.vulns._get_or_raise(  # noqa: SLF001
            vulnerability_id, organization_id=organization_id
        )
        pending = (vuln.threat_intel_metadata or {}).get("nist_mapping_suggestion") or {}
        csf = nist_csf if nist_csf is not None else list(pending.get("nist_csf") or [])
        sp = (
            nist_800_53
            if nist_800_53 is not None
            else list(pending.get("nist_800_53") or [])
        )
        if not csf and not sp:
            raise AIRemediationError(
                "No NIST controls to accept (run suggest first)", status_code=400
            )

        meta = dict(vuln.compliance_metadata or {})
        meta["nist_csf"] = list(dict.fromkeys([*(meta.get("nist_csf") or []), *csf]))
        meta["nist_800_53"] = list(
            dict.fromkeys([*(meta.get("nist_800_53") or []), *sp])
        )
        vuln.compliance_metadata = meta

        ti = dict(vuln.threat_intel_metadata or {})
        if "nist_mapping_suggestion" in ti:
            ti["nist_mapping_suggestion"] = {
                **ti["nist_mapping_suggestion"],
                "status": "accepted",
                "accepted_at": datetime.now(timezone.utc).isoformat(),
            }
            vuln.threat_intel_metadata = ti

        await self.db.flush()
        return {
            "vulnerability_id": str(vuln.id),
            "status": "accepted",
            "compliance_metadata": vuln.compliance_metadata,
        }
