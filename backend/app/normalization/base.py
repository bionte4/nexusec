"""Parser protocol for scanner raw outputs."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Union

from app.normalization.schema import NormalizedFinding

RawInput = Union[str, bytes, dict[str, Any], list[Any]]


class FindingParser(ABC):
    """Convert vendor-specific scanner output into NormalizedFinding list."""

    name: str

    @abstractmethod
    def parse(self, raw: RawInput) -> list[NormalizedFinding]:
        raise NotImplementedError
