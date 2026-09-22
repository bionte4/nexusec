"""Vulnerability normalization & parsing engine."""

from app.normalization.registry import ParserRegistry, build_default_registry
from app.normalization.schema import NormalizedFinding
from app.normalization.ingest import AssetResolver, FindingIngestionService, IngestStats
from app.normalization.fingerprint import compute_fingerprint

__all__ = [
    "AssetResolver",
    "FindingIngestionService",
    "IngestStats",
    "NormalizedFinding",
    "ParserRegistry",
    "build_default_registry",
    "compute_fingerprint",
]
