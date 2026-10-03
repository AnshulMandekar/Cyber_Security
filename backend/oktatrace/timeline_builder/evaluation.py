"""Check a timeline against ground truth (evaluation only; the builder never sees labels)."""

from __future__ import annotations

from collections.abc import Mapping

from pydantic import BaseModel

from oktatrace.log_generator.models import EventLabel, LabelCategory
from oktatrace.timeline_builder.models import TimelineResult


class TimelineEvaluation(BaseModel):
    """How completely and cleanly the timeline captures the attack."""

    attack_events: int
    attack_events_in_timeline: int
    coverage: float | None
    event_entries: int
    benign_event_entries: int
    benign_entries_marked_suspicious: int
    benign_entries_tagged_with_technique: int


def evaluate_timeline(result: TimelineResult, labels: Mapping[str, EventLabel]) -> TimelineEvaluation:
    """Measure attack coverage and how much benign context the timeline carries."""
    attack = {u for u, label in labels.items() if label.category is LabelCategory.ATTACK}
    event_entries = [e for e in result.entries if e.kind == "event" and e.event_uuid]
    in_timeline = {e.event_uuid for e in event_entries}
    benign = [e for e in event_entries if e.event_uuid not in attack]
    return TimelineEvaluation(
        attack_events=len(attack),
        attack_events_in_timeline=len(attack & in_timeline),
        coverage=round(len(attack & in_timeline) / len(attack), 4) if attack else None,
        event_entries=len(event_entries),
        benign_event_entries=len(benign),
        benign_entries_marked_suspicious=sum(e.suspicious for e in benign),
        benign_entries_tagged_with_technique=sum(bool(e.mitre) for e in benign),
    )
