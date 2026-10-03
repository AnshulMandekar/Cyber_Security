"""Timeline entry and result models."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from oktatrace.common.severity import Severity

EntryKind = Literal["har_capture", "har_finding", "event", "inference", "alert"]
EvidenceType = Literal["event", "alert", "har_finding", "har_file"]
TimelineScope = Literal["incident", "all_alerts"]


class MitreTag(BaseModel):
    """An ATT&CK technique attached to a timeline entry."""

    technique_id: str
    name: str
    tactic: str
    url: str


class EvidenceRef(BaseModel):
    """A pointer to the artefact that supports a timeline entry."""

    type: EvidenceType
    ref: str = Field(description="Event UUID, alert ID, HAR finding ID or HAR filename")
    note: str = ""


class TimelineEntry(BaseModel):
    """One row of the reconstructed incident timeline."""

    id: str
    timestamp: datetime
    kind: EntryKind
    title: str
    description: str
    actor: str | None = None
    source_ip: str | None = None
    session_fingerprint: str | None = None
    severity: Severity | None = None
    suspicious: bool = Field(description="Flagged by an alert, a high-risk HAR finding or an inference")
    stage: str | None = Field(None, description="ATT&CK tactic of the first technique")
    mitre: list[MitreTag]
    evidence: list[EvidenceRef]
    related_alerts: list[str] = Field(default_factory=list)
    event_uuid: str | None = Field(None, description="Set for kind='event'")


class PivotSummary(BaseModel):
    """How the incident scope was derived from the HAR evidence."""

    matched_fingerprints: list[str] = Field(description="HAR finding fingerprints seen in alerts")
    actors: list[str]
    attacker_asns: list[int]
    note: str


class MitreSummaryRow(BaseModel):
    """How often a technique appears in the timeline and when first."""

    technique_id: str
    name: str
    tactic: str
    entries: int
    first_seen: datetime


class TimelineResult(BaseModel):
    """The ordered timeline plus how it was scoped."""

    scope: TimelineScope
    entries: list[TimelineEntry]
    incident_alerts: list[str]
    excluded_alerts: list[str]
    pivots: PivotSummary
    mitre_summary: list[MitreSummaryRow]
    first_timestamp: datetime | None
    last_timestamp: datetime | None
