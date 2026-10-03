"""Tests for precision/recall arithmetic on hand-made alerts and labels."""

from __future__ import annotations

from oktatrace.common.severity import Severity
from oktatrace.detection_engine import Alert, RuleInfo, evaluate_alerts
from oktatrace.log_generator.models import AttackPhase, AttackStep, EventLabel, LabelCategory
from tests.log_helpers import T0

RULE_A = RuleInfo(rule_id="R-A", name="A", severity=Severity.HIGH, description="d", rationale="r",
                  mitre_techniques=["T1078"])
RULE_B = RuleInfo(rule_id="R-B", name="B", severity=Severity.LOW, description="d", rationale="r",
                  mitre_techniques=["T1078"])

LABELS = {
    "a1": EventLabel(category=LabelCategory.ATTACK, scenario="atk", phase=AttackPhase.SESSION_REPLAY),
    "a2": EventLabel(category=LabelCategory.ATTACK, scenario="atk", phase=AttackPhase.ADMIN_ATTEMPT),
    "b1": EventLabel(category=LabelCategory.BENIGN, scenario="daily_work"),
    "b2": EventLabel(category=LabelCategory.EDGE_CASE, scenario="vpn_switch"),
}
STEPS = [
    AttackStep(step=1, phase=AttackPhase.SESSION_REPLAY, event_uuid="a1", published=T0, event_type="x",
               credential="stolen_session_cookie", outcome="SUCCESS", sensitive=False, description="d"),
    AttackStep(step=2, phase=AttackPhase.ADMIN_ATTEMPT, event_uuid="a2", published=T0, event_type="y",
               credential="stolen_session_cookie", outcome="SUCCESS", sensitive=True, description="d"),
]


def alert(alert_id: str, rule: RuleInfo, flagged: list[str], context: list[str] | None = None) -> Alert:
    return Alert(id=alert_id, rule_id=rule.rule_id, rule_name=rule.name, severity=rule.severity,
                 first_seen=T0, last_seen=T0, actor="x", session_fingerprint=None, explanation="e",
                 match_count=1, event_uuids=flagged, context_event_uuids=context or [], details={},
                 mitre_techniques=[])


def test_alert_and_event_level_metrics() -> None:
    alerts = [alert("1", RULE_A, ["a1", "b1"]), alert("2", RULE_B, ["b2"])]
    report = evaluate_alerts(alerts, LABELS, STEPS, [RULE_A, RULE_B])

    assert report.alert_level.true_positive_alerts == 1
    assert report.alert_level.false_positive_alerts == 1
    assert report.alert_level.precision == 0.5

    e = report.event_level
    assert (e.attack_events, e.flagged_events) == (2, 3)
    assert (e.true_positive, e.false_positive, e.false_negative) == (1, 2, 1)
    assert e.precision == 0.3333 and e.recall == 0.5 and e.f1 == 0.4

    assert report.missed_attack_steps == [2]
    assert {p.phase: p.recall for p in report.phases} == {
        AttackPhase.SESSION_REPLAY: 1.0, AttackPhase.ADMIN_ATTEMPT: 0.0,
    }
    assert report.false_positive_scenarios == {"vpn_switch": 1}
    per_rule = {r.rule_id: r for r in report.per_rule}
    assert per_rule["R-A"].precision == 1.0 and per_rule["R-B"].precision == 0.0


def test_attack_context_makes_an_alert_a_true_positive() -> None:
    report = evaluate_alerts([alert("1", RULE_A, ["b1"], context=["a1"])], LABELS, STEPS, [RULE_A])
    assert report.alert_level.precision == 1.0
    assert report.event_level.true_positive == 0  # but the flagged event itself is still an FP


def test_no_alerts() -> None:
    report = evaluate_alerts([], LABELS, STEPS, [RULE_A])
    assert report.alert_level.precision is None
    assert report.event_level.recall == 0.0
    assert report.event_level.precision is None and report.event_level.f1 is None
    assert report.per_rule[0].precision is None
    assert report.missed_attack_steps == [1, 2]
