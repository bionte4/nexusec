"""Passthrough parser for already-normalized / custom scanner JSON."""

from __future__ import annotations

import json
from typing import Any

from app.normalization.base import FindingParser, RawInput
from app.normalization.schema import NormalizedFinding


class CustomJsonParser(FindingParser):
    """Accept a list/dict of NormalizedFinding-compatible objects."""

    name = "nexusec"

    def parse(self, raw: RawInput) -> list[NormalizedFinding]:
        items = self._load(raw)
        findings: list[NormalizedFinding] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            # Allow either unified schema keys or nested "finding"
            payload = item.get("finding") if "finding" in item else item
            findings.append(NormalizedFinding.model_validate(payload))
        return findings

    @staticmethod
    def _load(raw: RawInput) -> list[Any]:
        if isinstance(raw, list):
            return raw
        if isinstance(raw, dict):
            if "findings" in raw and isinstance(raw["findings"], list):
                return raw["findings"]
            return [raw]
        if isinstance(raw, bytes):
            text = raw.decode("utf-8", errors="replace")
        elif isinstance(raw, str):
            text = raw
        else:
            raise TypeError("CustomJsonParser expects JSON-compatible input")
        data = json.loads(text) if text.strip() else []
        if isinstance(data, dict):
            if "findings" in data:
                return list(data["findings"])
            return [data]
        return list(data)
