"""Unit tests for dashboard aggregation helpers and vuln lifecycle service."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core.enums import FindingStatus, Severity
from app.models.vulnerability import Vulnerability
from app.models.vulnerability_comment import VulnerabilityComment
from app.schemas.vulnerability import (
    AssignOwnerRequest,
    VulnerabilityCommentCreate,
    VulnerabilityUpdate,
)
from app.services.vulnerability_service import (
    VulnerabilityNotFoundError,
    VulnerabilityService,
    VulnerabilityValidationError,
)


def _vuln(**kwargs) -> Vulnerability:
    now = datetime.now(timezone.utc)
    defaults = dict(
        id=uuid.uuid4(),
        scan_id=uuid.uuid4(),
        asset_id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        fingerprint="abc",
        title="Open SSH",
        description=None,
        severity=Severity.HIGH,
        status=FindingStatus.OPEN,
        cve_id=None,
        cwe_id=None,
        cvss_score=7.5,
        cvss_vector=None,
        affected_component=None,
        port=22,
        protocol="tcp",
        evidence={},
        remediation=None,
        owasp_category=None,
        mitre_attack_techniques=[],
        compliance_metadata={},
        raw_source={},
        source_tool="nmap",
        remediation_owner_id=None,
        remediation_owner_label=None,
        status_changed_at=None,
        is_actively_exploited=False,
        has_public_exploit=False,
        kev_date_added=None,
        kev_due_date=None,
        threat_risk_score=None,
        threat_intel_metadata={},
        threat_enriched_at=None,
        first_seen_at=now,
        last_seen_at=now,
        created_at=now,
        updated_at=now,
        comments=[],
    )
    defaults.update(kwargs)
    obj = Vulnerability(**{k: v for k, v in defaults.items() if k != "comments"})
    obj.comments = defaults["comments"]
    return obj


@pytest.mark.asyncio
async def test_update_status_sets_status_changed_at() -> None:
    vuln = _vuln(status=FindingStatus.OPEN)
    db = AsyncMock()
    result = MagicMock()
    result.scalar_one_or_none.return_value = vuln
    db.execute = AsyncMock(return_value=result)
    db.get = AsyncMock(return_value=None)
    db.flush = AsyncMock()
    db.refresh = AsyncMock()

    service = VulnerabilityService(db)
    updated = await service.update(
        vuln.id, VulnerabilityUpdate(status=FindingStatus.IN_PROGRESS)
    )
    assert updated.status == FindingStatus.IN_PROGRESS
    assert vuln.status_changed_at is not None


@pytest.mark.asyncio
async def test_assign_owner_validates_user() -> None:
    vuln = _vuln()
    db = AsyncMock()
    result = MagicMock()
    result.scalar_one_or_none.return_value = vuln
    db.execute = AsyncMock(return_value=result)
    db.get = AsyncMock(return_value=None)

    service = VulnerabilityService(db)
    with pytest.raises(VulnerabilityValidationError):
        await service.assign_owner(
            vuln.id,
            AssignOwnerRequest(remediation_owner_id=uuid.uuid4()),
        )


@pytest.mark.asyncio
async def test_add_comment() -> None:
    vuln = _vuln()
    db = AsyncMock()
    result = MagicMock()
    result.scalar_one_or_none.return_value = vuln
    db.execute = AsyncMock(return_value=result)

    created: list[VulnerabilityComment] = []

    def _add(obj: VulnerabilityComment) -> None:
        obj.id = uuid.uuid4()
        obj.created_at = datetime.now(timezone.utc)
        created.append(obj)

    db.add = MagicMock(side_effect=_add)
    db.flush = AsyncMock()
    db.refresh = AsyncMock()

    # VulnerabilityService uses MagicMock-incompatible AsyncMock for add — use MagicMock db base
    db_magic = MagicMock()
    db_magic.execute = AsyncMock(return_value=result)
    db_magic.add.side_effect = _add
    db_magic.flush = AsyncMock()
    db_magic.refresh = AsyncMock()

    service = VulnerabilityService(db_magic)
    author = uuid.uuid4()
    comment = await service.add_comment(
        vuln.id,
        VulnerabilityCommentCreate(body="Investigating on jump host"),
        author_id=author,
    )
    assert comment.body == "Investigating on jump host"
    assert created[0].author_id == author


@pytest.mark.asyncio
async def test_get_not_found() -> None:
    db = AsyncMock()
    result = MagicMock()
    result.scalar_one_or_none.return_value = None
    db.execute = AsyncMock(return_value=result)
    service = VulnerabilityService(db)
    with pytest.raises(VulnerabilityNotFoundError):
        await service.get(uuid.uuid4())


def test_prompt5_statuses_exist() -> None:
    assert FindingStatus.IN_PROGRESS.value == "in_progress"
    assert FindingStatus.RESOLVED.value == "resolved"
    assert FindingStatus.FALSE_POSITIVE.value == "false_positive"
    assert FindingStatus.OPEN.value == "open"
