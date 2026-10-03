"""Models for detection rules, their configuration and the alerts they raise."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from oktatrace.common.severity import Severity


class DetectionConfig(BaseModel):
    """Tunable thresholds. Defaults are the values documented in the README."""

    model_config = ConfigDict(frozen=True)

    require_asn_change: bool = Field(
        True, description="OT-DET-001: ignore IP changes inside the session's original ASN (NAT pools)"
    )
    max_travel_speed_kmh: float = Field(900.0, gt=0, description="OT-DET-002: faster than an airliner")
    min_travel_distance_km: float = Field(500.0, ge=0, description="OT-DET-002: ignore geo-IP jitter")
    ignore_user_agent_version: bool = Field(
        True, description="OT-DET-003: compare browser family + OS, so auto-updates are not flagged"
    )
    mfa_freshness_minutes: int = Field(60, gt=0, description="OT-DET-004: step-up MFA must be this recent")
    bulk_case_threshold: int = Field(15, ge=2, description="OT-DET-005: distinct cases in the window")
    bulk_case_window_minutes: int = Field(10, gt=0, description="OT-DET-005: sliding window length")
    business_hours_start: int = Field(7, ge=0, le=23, description="OT-DET-006: local hour work starts")
    business_hours_end: int = Field(20, ge=1, le=24, description="OT-DET-006: local hour work ends")
    service_baseline_hours: int = Field(24, gt=0, description="OT-DET-007: learning period for networks")
    suppression_minutes: int = Field(
        30, ge=0, description="Matches of one rule for the same key this close together become one alert"
    )

    @model_validator(mode="after")
    def _check_business_hours(self) -> DetectionConfig:
        if self.business_hours_start >= self.business_hours_end:
            raise ValueError("business_hours_start must be before business_hours_end")
        return self


class RuleInfo(BaseModel):
    """Static description of a rule."""

    rule_id: str
    name: str
    severity: Severity
    description: str
    rationale: str
    mitre_techniques: list[str]


@dataclass(frozen=True)
class RuleMatch:
    """One offending event (or event pair) found by a rule, before aggregation.

    Attributes:
        group_key: Matches with the same rule and key close together merge into one alert.
        flagged: UUIDs of the events judged suspicious.
        context: UUIDs of supporting events (e.g. the session's origin) that are not
            themselves suspicious.
    """

    rule_id: str
    timestamp: datetime
    group_key: str
    actor: str
    session_id: str | None
    flagged: tuple[str, ...]
    explanation: str
    context: tuple[str, ...] = ()
    details: Mapping[str, Any] = field(default_factory=dict)


class Alert(BaseModel):
    """An aggregated detection, with evidence and a plain-English explanation."""

    id: str
    rule_id: str
    rule_name: str
    severity: Severity
    first_seen: datetime
    last_seen: datetime
    actor: str
    session_fingerprint: str | None = Field(
        description="Truncated SHA-256 of the session ID; the raw (replayable) ID is never stored"
    )
    explanation: str
    match_count: int
    event_uuids: list[str] = Field(description="Events judged suspicious")
    context_event_uuids: list[str] = Field(description="Supporting events, not themselves suspicious")
    details: dict[str, Any]
    mitre_techniques: list[str]


class DetectionResult(BaseModel):
    """Output of one engine run."""

    config: DetectionConfig
    rules: list[RuleInfo]
    alerts: list[Alert]
    events_analyzed: int
