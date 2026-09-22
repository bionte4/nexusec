"""Pydantic schemas for asset management."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    field_validator,
    model_validator,
)

from app.core.enums import AssetCriticality, AssetType


def _normalize_ip(value: object) -> str | None:
    if value is None or value == "":
        return None
    return str(IPvAnyAddress(str(value)))


def _normalize_domain_like(value: object) -> str | None:
    """Accept bare FQDN or URL; store hostname only."""
    if value is None:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    from urllib.parse import urlparse

    candidate = raw
    if "://" in raw or raw.startswith("//"):
        parsed = urlparse(raw if "://" in raw else f"https:{raw}")
        if not parsed.hostname:
            raise ValueError(f"Invalid domain/URL: {value!r}")
        candidate = parsed.hostname
    else:
        candidate = raw.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if ":" in candidate and candidate.count(":") == 1:
            host, _, port = candidate.partition(":")
            if port.isdigit():
                candidate = host
    candidate = candidate.strip().lower().rstrip(".")
    if not candidate:
        raise ValueError(f"Invalid domain/URL: {value!r}")
    return candidate


def _normalize_url(value: object) -> str | None:
    if value is None:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    from urllib.parse import urlparse

    if "://" not in raw:
        raw = f"https://{raw.lstrip('/')}"
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"Invalid URL (http/https required): {value!r}")
    host = parsed.hostname.lower().rstrip(".")
    port = f":{parsed.port}" if parsed.port else ""
    path = parsed.path if parsed.path not in {"", "/"} else ""
    return f"{parsed.scheme}://{host}{port}{path}"


class AssetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    asset_type: AssetType
    criticality: AssetCriticality = AssetCriticality.MEDIUM
    ip_address: str | None = None
    domain: str | None = Field(default=None, max_length=255)
    cloud_resource_id: str | None = Field(default=None, max_length=512)
    cloud_provider: str | None = Field(default=None, max_length=64)
    is_cde_scope: bool = False
    hostname: str | None = Field(default=None, max_length=255)
    url: str | None = Field(default=None, max_length=2048)
    environment: str | None = Field(default=None, max_length=64)
    owner: str | None = Field(default=None, max_length=255)
    description: str | None = None
    tags: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("ip_address", mode="before")
    @classmethod
    def validate_ip_address(cls, value: object) -> str | None:
        return _normalize_ip(value)

    @field_validator("domain", "hostname", mode="before")
    @classmethod
    def validate_domain_fields(cls, value: object) -> str | None:
        if isinstance(value, str) and not value.strip():
            return None
        return _normalize_domain_like(value)

    @field_validator("url", mode="before")
    @classmethod
    def validate_url_field(cls, value: object) -> str | None:
        if isinstance(value, str) and not value.strip():
            return None
        return _normalize_url(value)

    @field_validator(
        "cloud_resource_id",
        "cloud_provider",
        "environment",
        "owner",
        "description",
        mode="before",
    )
    @classmethod
    def empty_str_to_none(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @model_validator(mode="after")
    def validate_type_identifiers(self) -> AssetCreate:
        if self.asset_type == AssetType.IP and not self.ip_address:
            raise ValueError("ip_address is required when asset_type is 'ip'")
        if self.asset_type == AssetType.DOMAIN and not self.domain:
            raise ValueError("domain is required when asset_type is 'domain'")
        if self.asset_type == AssetType.CLOUD_RESOURCE and not self.cloud_resource_id:
            raise ValueError("cloud_resource_id is required when asset_type is 'cloud_resource'")
        return self


class AssetUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    asset_type: AssetType | None = None
    criticality: AssetCriticality | None = None
    ip_address: str | None = None
    domain: str | None = Field(default=None, max_length=255)
    cloud_resource_id: str | None = Field(default=None, max_length=512)
    cloud_provider: str | None = Field(default=None, max_length=64)
    is_cde_scope: bool | None = None
    hostname: str | None = Field(default=None, max_length=255)
    url: str | None = Field(default=None, max_length=2048)
    environment: str | None = Field(default=None, max_length=64)
    owner: str | None = Field(default=None, max_length=255)
    description: str | None = None
    tags: dict[str, Any] | None = None
    metadata: dict[str, Any] | None = None

    @field_validator("ip_address", mode="before")
    @classmethod
    def validate_ip_address(cls, value: object) -> str | None:
        return _normalize_ip(value)

    @field_validator("domain", "hostname", mode="before")
    @classmethod
    def validate_domain_fields(cls, value: object) -> str | None:
        if value is None:
            return None
        if isinstance(value, str) and not value.strip():
            return None
        return _normalize_domain_like(value)

    @field_validator("url", mode="before")
    @classmethod
    def validate_url_field(cls, value: object) -> str | None:
        if value is None:
            return None
        if isinstance(value, str) and not value.strip():
            return None
        return _normalize_url(value)


class AssetRead(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    asset_type: AssetType
    criticality: AssetCriticality
    ip_address: str | None
    domain: str | None
    cloud_resource_id: str | None
    cloud_provider: str | None
    is_cde_scope: bool
    hostname: str | None
    url: str | None
    environment: str | None
    owner: str | None
    description: str | None
    tags: dict[str, Any]
    metadata: dict[str, Any] = Field(
        validation_alias=AliasChoices("metadata_", "metadata"),
    )
    created_by_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime

    @field_validator("ip_address", mode="before")
    @classmethod
    def coerce_ip_address(cls, value: object) -> str | None:
        if value is None:
            return None
        return str(value)


class AssetListResponse(BaseModel):
    items: list[AssetRead]
    total: int
    page: int
    page_size: int
    pages: int
