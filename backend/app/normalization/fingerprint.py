"""Stable fingerprints for asset-level finding deduplication."""

from __future__ import annotations

import hashlib

from app.normalization.schema import NormalizedFinding


def compute_fingerprint(finding: NormalizedFinding, *, asset_key: str = "") -> str:
    """
    SHA-256 hex digest (64 chars) over stable finding identity fields.

    asset_key is included so the same issue on different assets does not collide
    when compared globally; DB uniqueness is still (asset_id, fingerprint).
    """
    parts = [
        asset_key.strip().lower(),
        finding.vuln_id.strip().lower(),
        finding.name.strip().lower(),
        (finding.cve_id or "").strip().upper(),
        (finding.cwe_id or "").strip().upper(),
        str(finding.port or ""),
        (finding.protocol or "").strip().lower(),
        (finding.affected_component or "").strip().lower(),
        finding.source_tool.strip().lower(),
    ]
    material = "|".join(parts)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()
