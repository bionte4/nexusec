"""Shared enums used across models and schemas."""

from __future__ import annotations

import enum
from typing import FrozenSet, TypeVar

from sqlalchemy import Enum as SAEnum

_E = TypeVar("_E", bound=enum.Enum)


def pg_enum(enum_cls: type[_E], name: str) -> SAEnum:
    """PostgreSQL native ENUM bound to *values* (not member names)."""

    return SAEnum(
        enum_cls,
        name=name,
        native_enum=True,
        values_callable=lambda members: [item.value for item in members],
    )


class UserRole(str, enum.Enum):
    """RBAC roles — Super Admin is cross-tenant (Prompt 12)."""

    SUPER_ADMIN = "super_admin"
    ADMIN = "admin"
    PENTESTER = "pentester"
    SOC_ANALYST = "soc_analyst"


class AssetType(str, enum.Enum):
    """Primary asset categories for VA/PT scope."""

    IP = "ip"
    DOMAIN = "domain"
    CLOUD_RESOURCE = "cloud_resource"


class AssetCriticality(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanType(str, enum.Enum):
    VA = "va"
    PT = "pt"
    DISCOVERY = "discovery"
    COMPLIANCE = "compliance"
    CUSTOM = "custom"


class ScannerEngine(str, enum.Enum):
    NEXUSEC = "nexusec"
    NMAP = "nmap"
    NUCLEI = "nuclei"
    OPENVAS = "openvas"
    OTHER = "other"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class FindingStatus(str, enum.Enum):
    """Lifecycle statuses (Prompt 5 primary: open / in_progress / false_positive / resolved)."""

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    FALSE_POSITIVE = "false_positive"
    RESOLVED = "resolved"
    # retained for compatibility / richer workflow
    CONFIRMED = "confirmed"
    ACCEPTED_RISK = "accepted_risk"
    REMEDIATED = "remediated"
    REOPENED = "reopened"


ACTIVE_FINDING_STATUSES: FrozenSet[FindingStatus] = frozenset(
    {
        FindingStatus.OPEN,
        FindingStatus.IN_PROGRESS,
        FindingStatus.CONFIRMED,
        FindingStatus.REOPENED,
    }
)

RESOLVED_FINDING_STATUSES: FrozenSet[FindingStatus] = frozenset(
    {
        FindingStatus.RESOLVED,
        FindingStatus.REMEDIATED,
        FindingStatus.FALSE_POSITIVE,
        FindingStatus.ACCEPTED_RISK,
    }
)

DASHBOARD_SEVERITIES = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
)
