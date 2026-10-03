"""Tests for alert aggregation and the engine run over the full dataset."""

from __future__ import annotations

import re
from datetime import timedelta

import pytest

from oktatrace.detection_engine import (
    RULES,
    DetectionConfig,
    DetectionResult,
    EvaluationReport,
    RuleMatch,
    aggregate_matches,
    run_detections,
)
from oktatrace.detection_engine.pipeline import detect_and_evaluate
from oktatrace.har_analyzer import analyze_har
from oktatrace.har_analyzer.sample_har import build_sample_har
from oktatrace.log_generator import LabelCategory, LogDataset
from tests.log_helpers import T0, minutes


@pytest.fixture(scope="session")
def detection(dataset: LogDataset) -> tuple[DetectionResult, EvaluationReport]:
    return detect_and_evaluate(dataset)


def _match(offset_minutes: float, key: str = "k", flagged: tuple[str, ...] = ("e1",),
           rule_id: str = "OT-DET-001") -> RuleMatch:
    return RuleMatch(rule_id=rule_id, timestamp=T0 + minutes(offset_minutes), group_key=key,
                     actor="alice@acme.example", session_id="S-ALICE", flagged=flagged,
                     explanation="why", context=("ctx",))


# -- aggregation ------------------------------------------------------------------
def test_matches_within_suppression_merge_into_one_alert() -> None:
    [alert] = aggregate_matches([_match(0, flagged=("e1",)), _match(20, flagged=("e2", "e1"))],
                                timedelta(minutes=30))
    assert alert.match_count == 2
    assert alert.event_uuids == ["e1", "e2"]
    assert alert.context_event_uuids == ["ctx"]
    assert alert.last_seen - alert.first_seen == timedelta(minutes=20)
    assert "merged" in alert.explanation


def test_matches_beyond_suppression_or_with_other_keys_stay_separate() -> None:
    alerts = aggregate_matches(
        [_match(0), _match(45), _match(50, key="other"), _match(51, rule_id="OT-DET-003")],
        timedelta(minutes=30),
    )
    assert len(alerts) == 4
    assert [a.id for a in alerts] == ["ALR-0001", "ALR-0002", "ALR-0003", "ALR-0004"]
    assert [a.first_seen for a in alerts] == sorted(a.first_seen for a in alerts)


def test_suppression_chains_from_last_match() -> None:
    [alert] = aggregate_matches([_match(0), _match(25), _match(50)], timedelta(minutes=30))
    assert alert.match_count == 3


def test_alerts_store_session_fingerprint_not_session_id() -> None:
    [alert] = aggregate_matches([_match(0)], timedelta(minutes=30))
    assert alert.session_fingerprint is not None and len(alert.session_fingerprint) == 12
    assert "S-ALICE" not in alert.model_dump_json()


# -- rule catalogue ---------------------------------------------------------------
def test_rule_catalogue_is_well_formed() -> None:
    ids = [rule.info.rule_id for rule in RULES]
    assert len(ids) == len(set(ids)) == 7
    assert all(re.fullmatch(r"OT-DET-\d{3}", i) for i in ids)
    for rule in RULES:
        assert rule.info.description and rule.info.rationale
        assert all(re.fullmatch(r"T\d{4}(\.\d{3})?", t) for t in rule.info.mitre_techniques)


# -- full dataset -----------------------------------------------------------------
def test_engine_is_deterministic(dataset: LogDataset,
                                 detection: tuple[DetectionResult, EvaluationReport]) -> None:
    again = run_detections(reversed(dataset.events), dataset.users)  # input order must not matter
    assert again.model_dump() == detection[0].model_dump()


def test_every_rule_catches_part_of_the_attack(detection: tuple[DetectionResult, EvaluationReport]) -> None:
    _, evaluation = detection
    for rule in evaluation.per_rule:
        assert rule.true_positive_alerts >= 1, rule.rule_id


def test_whole_attack_is_detected(detection: tuple[DetectionResult, EvaluationReport]) -> None:
    _, evaluation = detection
    assert evaluation.event_level.recall == 1.0
    assert evaluation.missed_attack_steps == []
    assert all(p.recall == 1.0 for p in evaluation.phases)
    assert evaluation.alert_level.precision is not None and evaluation.alert_level.precision >= 0.8


def test_false_positives_come_only_from_planted_edge_cases(
    dataset: LogDataset, detection: tuple[DetectionResult, EvaluationReport]
) -> None:
    result, evaluation = detection
    assert set(evaluation.false_positive_scenarios) == {"vpn_switch", "offhours_admin"}
    flagged = {u for a in result.alerts for u in a.event_uuids}
    quiet = {"browser_update", "travel", "support_bulk", "daily_work", "case_sync"}
    noisy = [u for u in flagged if dataset.labels[u].scenario in quiet
             and dataset.labels[u].category is not LabelCategory.ATTACK]
    # Only impossible-travel "return" hops may flag a benign event, and those alerts carry attack context.
    attack = {u for u, l in dataset.labels.items() if l.is_attack}
    for alert in result.alerts:
        if any(u in noisy for u in alert.event_uuids):
            assert alert.rule_id == "OT-DET-002"
            assert set(alert.context_event_uuids + alert.event_uuids) & attack


def test_replay_alert_links_back_to_the_har(detection: tuple[DetectionResult, EvaluationReport]) -> None:
    result, _ = detection
    har = analyze_har(build_sample_har(), long_lived_threshold_seconds=8 * 3600)
    sid = next(f for f in har.findings if f.name == "sid")
    replay_alerts = [a for a in result.alerts if a.rule_id == "OT-DET-001" and a.actor.startswith("jordan")]
    assert replay_alerts
    assert {a.session_fingerprint for a in replay_alerts} == {sid.fingerprint}


def test_comparing_raw_user_agents_creates_browser_update_noise(dataset: LogDataset) -> None:
    _, strict = detect_and_evaluate(dataset, DetectionConfig(ignore_user_agent_version=False))
    assert "browser_update" in strict.false_positive_scenarios


def test_no_alert_contains_the_raw_session_id(dataset: LogDataset,
                                               detection: tuple[DetectionResult, EvaluationReport]) -> None:
    dumped = detection[0].model_dump_json()
    assert dataset.scenario.victim_session_id not in dumped
