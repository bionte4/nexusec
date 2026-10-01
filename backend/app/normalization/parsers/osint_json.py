"""OSINT JSON report → NormalizedFinding parser."""

from __future__ import annotations

import json
from typing import Any, Optional

from app.core.enums import Severity
from app.normalization.base import FindingParser, RawInput
from app.normalization.schema import NormalizedFinding


class OsintJsonParser(FindingParser):
    """Parse NexuSec OSINT connector JSON (dns / crt.sh / rdap)."""

    name = "osint"

    def parse(self, raw: RawInput) -> list[NormalizedFinding]:
        text = self._to_text(raw)
        if not text.strip():
            return []
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid OSINT JSON: {exc}") from exc

        results = data.get("results") if isinstance(data, dict) else None
        if not isinstance(results, list):
            return []

        findings: list[NormalizedFinding] = []
        for entry in results:
            if not isinstance(entry, dict):
                continue
            target = str(entry.get("target") or "").strip()
            if not target:
                continue
            if entry.get("error"):
                findings.append(
                    self._finding(
                        vuln_id=f"osint:error:{target}"[:128],
                        name=f"OSINT failed for {target}",
                        description=str(entry.get("error")),
                        severity=Severity.INFO,
                        target=target,
                        evidence={"error": entry.get("error")},
                    )
                )
                continue
            dns = entry.get("dns") if isinstance(entry.get("dns"), dict) else {}
            a_recs = [str(x) for x in (dns.get("A") or []) if x]
            aaaa = [str(x) for x in (dns.get("AAAA") or []) if x]
            if a_recs or aaaa:
                findings.append(
                    self._finding(
                        vuln_id=f"osint:dns:{target}"[:128],
                        name=f"DNS resolution — {target}",
                        description=(
                            f"Passive DNS lookup for {target}. "
                            f"A={', '.join(a_recs) or '—'}; "
                            f"AAAA={', '.join(aaaa) or '—'}."
                        ),
                        severity=Severity.INFO,
                        target=target,
                        evidence={"dns": {"A": a_recs, "AAAA": aaaa}},
                        remediation=(
                            "Review exposed hosts; ensure only authorized "
                            "services are published in DNS."
                        ),
                    )
                )
            subs = entry.get("crtsh_subdomains")
            if isinstance(subs, list) and subs:
                clean = [str(s).lower() for s in subs if isinstance(s, str) and s.strip()]
                findings.append(
                    self._finding(
                        vuln_id=f"osint:crtsh:{target}:{len(clean)}"[:128],
                        name=f"Certificate Transparency subdomains — {target}",
                        description=(
                            f"Found {len(clean)} subdomain name(s) via crt.sh for {target}. "
                            f"Sample: {', '.join(clean[:15])}"
                            + ("…" if len(clean) > 15 else "")
                        ),
                        severity=Severity.LOW if len(clean) >= 5 else Severity.INFO,
                        target=target,
                        evidence={"crtsh_subdomains": clean[:100]},
                        remediation=(
                            "Inventory discovered subdomains; decommission stale hosts; "
                            "monitor CT logs for unexpected certificates."
                        ),
                    )
                )
                for host in clean[:25]:
                    findings.append(
                        self._finding(
                            vuln_id=f"osint:subdomain:{host}"[:128],
                            name=f"Discovered subdomain — {host}",
                            description=(
                                f"Subdomain {host} observed in Certificate Transparency "
                                f"data for scope {target}."
                            ),
                            severity=Severity.INFO,
                            target=host,
                            evidence={"parent": target, "source": "crt.sh"},
                            remediation="Validate ownership and harden or retire unused hosts.",
                        )
                    )
            rdap = entry.get("rdap") if isinstance(entry.get("rdap"), dict) else None
            if rdap and not rdap.get("error"):
                ns = rdap.get("nameservers") or []
                findings.append(
                    self._finding(
                        vuln_id=f"osint:rdap:{target}"[:128],
                        name=f"RDAP registration summary — {target}",
                        description=(
                            f"RDAP status={rdap.get('status')!r}; "
                            f"nameservers={', '.join(ns) if isinstance(ns, list) else '—'}."
                        ),
                        severity=Severity.INFO,
                        target=target,
                        evidence={"rdap": rdap},
                        remediation=(
                            "Confirm registrar lock, expiration monitoring, and "
                            "authoritative nameserver integrity."
                        ),
                    )
                )
        return findings

    @staticmethod
    def _finding(
        *,
        vuln_id: str,
        name: str,
        description: str,
        severity: Severity,
        target: str,
        evidence: dict[str, Any],
        remediation: Optional[str] = None,
    ) -> NormalizedFinding:
        return NormalizedFinding(
            vuln_id=vuln_id,
            name=name[:512],
            description=description[:4000],
            severity=severity,
            remediation_steps=remediation,
            target_hint=target,
            affected_component=target,
            evidence={"osint": evidence},
            source_tool="osint",
            raw_source={"target": target},
            iso_27001_clause=["A.8.8"],
            nist_csf=["ID.AM-01", "ID.RA-01"],
            nist_800_53=["RA-5", "CM-8"],
            mitre_tactics=["reconnaissance"],
        )

    @staticmethod
    def _to_text(raw: RawInput) -> str:
        if isinstance(raw, bytes):
            return raw.decode("utf-8", errors="replace")
        if isinstance(raw, str):
            return raw
        raise TypeError("OsintJsonParser expects JSON string/bytes")
