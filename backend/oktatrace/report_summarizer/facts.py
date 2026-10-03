"""Collect the deterministic findings that the summary is written from.

Everything here is computed by Python modules 1-4. The summarizer (template
or LLM) only rephrases these facts; it never decides what is or is not a
detection. No raw secret or session ID is included: HAR findings carry masked
previews and fingerprints, and alerts carry session fingerprints.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel

from oktatrace import DISCLAIMER
from oktatrace.common.severity import Severity
from oktatrace.detection_engine import DetectionResult, EvaluationReport
from oktatrace.har_analyzer import HarAnalysisResult
from oktatrace.log_generator.models import ScenarioFacts
from oktatrace.scenario import ORG_NAME, ORG_TIMEZONE_LABEL
from oktatrace.timeline_builder import TimelineResult

KEY_ENTRY_KINDS = frozenset({"har_capture", "har_finding", "inference", "alert"})


class IncidentFacts(BaseModel):
    """The structured input to the summarizer."""

    disclaimer: str
    organisation: str
    org_timezone: str
    case_id: str
    har: dict[str, Any]
    detections: dict[str, Any]
    timeline: dict[str, Any]
    recommendations: list[str]

    def known_ids(self) -> set[str]:
        """Every evidence ID a summary may legitimately cite."""
        ids: set[str] = set()
        ids |= {f["id"] for f in self.har["findings"]}
        ids |= {a["id"] for a in self.detections["alerts"]}
        ids |= {r["rule_id"] for r in self.detections["rules"]}
        ids |= {e["id"] for e in self.timeline["key_entries"]}
        ids |= {t["technique_id"] for t in self.timeline["techniques"]}
        return ids


def _iso(value: datetime | None) -> str | None:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ") if value else None


def build_facts(
    har: HarAnalysisResult,
    detection: DetectionResult,
    evaluation: EvaluationReport,
    timeline: TimelineResult,
    scenario: ScenarioFacts,
) -> IncidentFacts:
    """Assemble the facts from the outputs of modules 1-4."""
    incident = set(timeline.incident_alerts)
    key_entries = []
    for entry in timeline.entries:
        is_admin_event = entry.kind == "event" and entry.stage in ("Persistence", "Defense Evasion")
        is_har_download = entry.kind == "event" and any(t.technique_id == "T1552.001" for t in entry.mitre)
        if entry.kind in KEY_ENTRY_KINDS or is_admin_event or is_har_download:
            key_entries.append({
                "id": entry.id,
                "time": _iso(entry.timestamp),
                "kind": entry.kind,
                "title": entry.title,
                "stage": entry.stage,
                "techniques": [t.technique_id for t in entry.mitre],
                "description": entry.description,
            })
    stages: dict[str, int] = {}
    for entry in timeline.entries:
        if entry.stage:
            stages[entry.stage] = stages.get(entry.stage, 0) + 1

    recommendations = list(dict.fromkeys(
        f.recommendation for f in har.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)
    ))
    return IncidentFacts(
        disclaimer=DISCLAIMER,
        organisation=ORG_NAME,
        org_timezone=ORG_TIMEZONE_LABEL,
        case_id=scenario.support_case_id,
        har={
            "captured_at": _iso(har.summary.first_request_at),
            "entries": har.summary.entry_count,
            "total_findings": har.stats.total_findings,
            "by_severity": {s.value: n for s, n in har.stats.by_severity.items()},
            "long_lived": har.stats.long_lived_count,
            "findings": [
                {"id": f.id, "kind": f.kind.value, "name": f.name, "severity": f.severity.value,
                 "risk_score": f.risk_score, "fingerprint": f.fingerprint, "long_lived": f.long_lived,
                 "valid_at_capture": f.valid_at_capture}
                for f in har.findings
            ],
        },
        detections={
            "rules": [{"rule_id": r.rule_id, "name": r.name, "severity": r.severity.value}
                      for r in detection.rules],
            "alerts": [
                {"id": a.id, "rule_id": a.rule_id, "severity": a.severity.value,
                 "first_seen": _iso(a.first_seen), "actor": a.actor, "in_incident": a.id in incident,
                 "events": len(a.event_uuids), "explanation": a.explanation}
                for a in detection.alerts
            ],
            "evaluation": {
                "alert_precision": evaluation.alert_level.precision,
                "event_precision": evaluation.event_level.precision,
                "event_recall": evaluation.event_level.recall,
                "event_f1": evaluation.event_level.f1,
                "false_positive_causes": evaluation.false_positive_scenarios,
                "missed_attack_steps": len(evaluation.missed_attack_steps),
            },
        },
        timeline={
            "first": _iso(timeline.first_timestamp),
            "last": _iso(timeline.last_timestamp),
            "entries": len(timeline.entries),
            "excluded_alerts": timeline.excluded_alerts,
            "matched_fingerprints": timeline.pivots.matched_fingerprints,
            "entries_by_stage": stages,
            "techniques": [
                {"technique_id": t.technique_id, "name": t.name, "tactic": t.tactic, "entries": t.entries}
                for t in timeline.mitre_summary
            ],
            "key_entries": key_entries,
        },
        recommendations=recommendations,
    )
