"""Score alerts against the ground truth.

This module is the only place where detections meet labels, and it runs after
the engine has finished.

Definitions:

* **Alert-level**: an alert is a true positive if any of its flagged or context
  events is an attack event. Precision = TP alerts / all alerts.
* **Event-level**: the flagged events of all alerts are the predictions;
  attack-labelled events are the positives. Gives precision, recall and F1.
* **Phase coverage**: share of each attack phase's events that were flagged.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence

from pydantic import BaseModel

from oktatrace.detection_engine.models import Alert, RuleInfo
from oktatrace.log_generator.models import AttackPhase, AttackStep, EventLabel


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


class AlertLevelMetrics(BaseModel):
    total_alerts: int
    true_positive_alerts: int
    false_positive_alerts: int
    precision: float | None


class EventLevelMetrics(BaseModel):
    attack_events: int
    flagged_events: int
    true_positive: int
    false_positive: int
    false_negative: int
    precision: float | None
    recall: float | None
    f1: float | None


class PhaseCoverage(BaseModel):
    phase: AttackPhase
    attack_events: int
    detected_events: int
    recall: float | None


class RuleMetrics(BaseModel):
    rule_id: str
    name: str
    alerts: int
    true_positive_alerts: int
    false_positive_alerts: int
    precision: float | None
    attack_events_flagged: int
    flagged_events: int


class EvaluationReport(BaseModel):
    """Precision/recall of a detection run against the labelled scenario."""

    alert_level: AlertLevelMetrics
    event_level: EventLevelMetrics
    phases: list[PhaseCoverage]
    per_rule: list[RuleMetrics]
    false_positive_scenarios: dict[str, int]
    missed_attack_steps: list[int]


def _is_true_positive(alert: Alert, attack: set[str]) -> bool:
    return any(u in attack for u in (*alert.event_uuids, *alert.context_event_uuids))


def evaluate_alerts(
    alerts: Sequence[Alert],
    labels: Mapping[str, EventLabel],
    attack_steps: Sequence[AttackStep],
    rules: Sequence[RuleInfo],
) -> EvaluationReport:
    """Compare alerts with ground truth and compute the metrics described above."""
    attack = {uuid for uuid, label in labels.items() if label.is_attack}
    flagged = {u for alert in alerts for u in alert.event_uuids}

    tp_alerts = [a for a in alerts if _is_true_positive(a, attack)]
    fp_alerts = [a for a in alerts if not _is_true_positive(a, attack)]

    tp = len(flagged & attack)
    fp = len(flagged - attack)
    fn = len(attack - flagged)
    precision, recall = _ratio(tp, tp + fp), _ratio(tp, tp + fn)
    f1 = round(2 * precision * recall / (precision + recall), 4) if precision and recall else None

    phase_events: dict[AttackPhase, list[str]] = {}
    for step in attack_steps:
        phase_events.setdefault(step.phase, []).append(step.event_uuid)
    phases = [
        PhaseCoverage(
            phase=phase,
            attack_events=len(uuids),
            detected_events=sum(u in flagged for u in uuids),
            recall=_ratio(sum(u in flagged for u in uuids), len(uuids)),
        )
        for phase, uuids in phase_events.items()
    ]

    per_rule = []
    for rule in rules:
        rule_alerts = [a for a in alerts if a.rule_id == rule.rule_id]
        rule_tp = sum(_is_true_positive(a, attack) for a in rule_alerts)
        rule_flagged = {u for a in rule_alerts for u in a.event_uuids}
        per_rule.append(
            RuleMetrics(
                rule_id=rule.rule_id,
                name=rule.name,
                alerts=len(rule_alerts),
                true_positive_alerts=rule_tp,
                false_positive_alerts=len(rule_alerts) - rule_tp,
                precision=_ratio(rule_tp, len(rule_alerts)),
                attack_events_flagged=len(rule_flagged & attack),
                flagged_events=len(rule_flagged),
            )
        )

    fp_scenarios = Counter(
        labels[a.event_uuids[0]].scenario if a.event_uuids and a.event_uuids[0] in labels else "unknown"
        for a in fp_alerts
    )
    return EvaluationReport(
        alert_level=AlertLevelMetrics(
            total_alerts=len(alerts),
            true_positive_alerts=len(tp_alerts),
            false_positive_alerts=len(fp_alerts),
            precision=_ratio(len(tp_alerts), len(alerts)),
        ),
        event_level=EventLevelMetrics(
            attack_events=len(attack),
            flagged_events=len(flagged),
            true_positive=tp,
            false_positive=fp,
            false_negative=fn,
            precision=precision,
            recall=recall,
            f1=f1,
        ),
        phases=phases,
        per_rule=per_rule,
        false_positive_scenarios=dict(sorted(fp_scenarios.items())),
        missed_attack_steps=[s.step for s in attack_steps if s.event_uuid not in flagged],
    )
