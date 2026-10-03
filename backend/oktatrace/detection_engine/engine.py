"""Run every rule and merge their matches into alerts."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from oktatrace.common.masking import fingerprint
from oktatrace.detection_engine.context import build_context
from oktatrace.detection_engine.models import Alert, DetectionConfig, DetectionResult, RuleMatch
from oktatrace.detection_engine.rules import RULES, RULES_BY_ID
from oktatrace.log_generator.models import DirectoryEntry, SystemLogEvent


@dataclass
class _Draft:
    """An alert being assembled from one or more matches."""

    first: RuleMatch
    last_seen: datetime
    count: int = 1
    flagged: dict[str, None] = field(default_factory=dict)  # insertion-ordered set
    context: dict[str, None] = field(default_factory=dict)

    @classmethod
    def start(cls, match: RuleMatch) -> _Draft:
        draft = cls(first=match, last_seen=match.timestamp, count=0)
        draft.add(match)
        return draft

    def add(self, match: RuleMatch) -> None:
        self.count += 1
        self.last_seen = max(self.last_seen, match.timestamp)
        self.flagged.update(dict.fromkeys(match.flagged))
        self.context.update(dict.fromkeys(match.context))

    def to_alert(self, alert_id: str) -> Alert:
        info = RULES_BY_ID[self.first.rule_id].info
        explanation = self.first.explanation
        if self.count > 1:
            explanation += (
                f" {self.count} matches from {self.first.timestamp:%Y-%m-%d %H:%M} "
                f"to {self.last_seen:%H:%M} UTC were merged into this alert."
            )
        flagged = list(self.flagged)
        return Alert(
            id=alert_id,
            rule_id=info.rule_id,
            rule_name=info.name,
            severity=info.severity,
            first_seen=self.first.timestamp,
            last_seen=self.last_seen,
            actor=self.first.actor,
            session_fingerprint=fingerprint(self.first.session_id) if self.first.session_id else None,
            explanation=explanation,
            match_count=self.count,
            event_uuids=flagged,
            context_event_uuids=[u for u in self.context if u not in self.flagged],
            details=dict(self.first.details),
            mitre_techniques=list(info.mitre_techniques),
        )


def aggregate_matches(matches: Iterable[RuleMatch], suppression: timedelta) -> list[Alert]:
    """Merge matches of the same rule and group key that are within ``suppression`` of each other."""
    ordered = sorted(matches, key=lambda m: (m.timestamp, m.rule_id, m.group_key))
    drafts: list[_Draft] = []
    open_drafts: dict[tuple[str, str], _Draft] = {}
    for match in ordered:
        key = (match.rule_id, match.group_key)
        draft = open_drafts.get(key)
        if draft is not None and match.timestamp - draft.last_seen <= suppression:
            draft.add(match)
        else:
            draft = _Draft.start(match)
            open_drafts[key] = draft
            drafts.append(draft)
    drafts.sort(key=lambda d: (d.first.timestamp, d.first.rule_id, d.first.group_key))
    return [draft.to_alert(f"ALR-{i:04d}") for i, draft in enumerate(drafts, start=1)]


def run_detections(
    events: Iterable[SystemLogEvent],
    users: Sequence[DirectoryEntry],
    config: DetectionConfig | None = None,
) -> DetectionResult:
    """Run all rules over ``events`` and return the aggregated alerts.

    Args:
        events: System Log events in any order.
        users: Directory entries (for home time zones and service-account roles).
        config: Thresholds; defaults to :class:`DetectionConfig` defaults.
    """
    config = config or DetectionConfig()
    context = build_context(events, users, config)
    matches = [match for rule in RULES for match in rule.evaluate(context)]
    alerts = aggregate_matches(matches, timedelta(minutes=config.suppression_minutes))
    return DetectionResult(
        config=config,
        rules=[rule.info for rule in RULES],
        alerts=alerts,
        events_analyzed=len(context.events),
    )
