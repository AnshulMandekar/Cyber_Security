"""Pydantic models describing HAR analysis output."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# Re-exported: HAR findings and detection alerts share one severity scale.
from oktatrace.common.severity import Severity as Severity


class FindingKind(StrEnum):
    """What kind of secret a finding represents."""

    SESSION_COOKIE = "session_cookie"
    DEVICE_TOKEN = "device_token"
    BEARER_TOKEN = "bearer_token"
    ACCESS_TOKEN = "access_token"
    ID_TOKEN = "id_token"
    REFRESH_TOKEN = "refresh_token"
    SESSION_TOKEN = "session_token"
    API_TOKEN = "api_token"
    API_KEY = "api_key"
    BASIC_CREDENTIALS = "basic_credentials"
    PASSWORD = "password"
    CLIENT_SECRET = "client_secret"
    OAUTH_CODE = "oauth_code"
    SAML_ASSERTION = "saml_assertion"
    CSRF_TOKEN = "csrf_token"
    JWT = "jwt"
    GENERIC_SECRET = "generic_secret"


class RiskFactor(BaseModel):
    """One explainable contribution to a finding's risk score."""

    label: str
    points: int


class Occurrence(BaseModel):
    """A single place in the HAR where a secret value appeared."""

    entry_index: int = Field(description="Zero-based index into log.entries")
    location: str = Field(description="Carrier and name, e.g. 'request.cookie:sid'")
    method: str
    url: str = Field(description="Request URL with any secrets masked")
    timestamp: datetime | None


class JwtSummary(BaseModel):
    """Decoded (never verified) JWT header and claims."""

    algorithm: str | None
    signature_present: bool
    issuer: str | None
    subject: str | None
    audience: str | list[str] | None
    scopes: list[str]
    issued_at: datetime | None
    expires_at: datetime | None
    header: dict[str, Any]
    payload: dict[str, Any]


class Finding(BaseModel):
    """One distinct secret, with every place it was seen and an explained risk score."""

    id: str
    kind: FindingKind
    name: str = Field(description="Cookie, header or parameter name it was found under")
    value_preview: str = Field(description="Masked preview; never the full value")
    fingerprint: str | None = Field(
        description="Truncated SHA-256 of the value for correlation; null for passwords"
    )
    risk_score: int = Field(ge=0, le=100)
    severity: Severity
    long_lived: bool
    valid_at_capture: bool | None = Field(
        description="Whether the secret was unexpired when the HAR was captured (null if unknown)"
    )
    expires_at: datetime | None
    lifetime_seconds: int | None
    factors: list[RiskFactor]
    jwt: JwtSummary | None
    occurrence_count: int
    occurrences: list[Occurrence]
    recommendation: str


class HarSummary(BaseModel):
    """High-level facts about the analysed HAR file."""

    creator: str | None
    entry_count: int
    page_count: int
    hosts: list[str]
    first_request_at: datetime | None
    last_request_at: datetime | None


class HarStats(BaseModel):
    """Aggregate counts across all findings."""

    total_findings: int
    by_severity: dict[Severity, int]
    by_kind: dict[FindingKind, int]
    long_lived_count: int
    max_risk_score: int
    overall_severity: Severity | None


class HarAnalysisResult(BaseModel):
    """Complete output of :func:`oktatrace.har_analyzer.analyze_har`."""

    disclaimer: str
    summary: HarSummary
    stats: HarStats
    findings: list[Finding]
