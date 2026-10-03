"""Tests for the timeline builder (Module 4)."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from oktatrace.api.app import create_app
from oktatrace.common.mitre import TECHNIQUES
from oktatrace.config import get_settings
from oktatrace.detection_engine import RULES, DetectionResult
from oktatrace.detection_engine.pipeline import detect_and_evaluate
from oktatrace.log_generator import LogDataset, generate_dataset
from oktatrace.log_generator.attack import HAR_FILENAME
from oktatrace.storage import SqliteStore
from oktatrace.timeline_builder import TimelineResult, build_timeline, evaluate_timeline
from oktatrace.timeline_builder.__main__ import main as cli_main
from oktatrace.timeline_builder.mapping import event_techniques
from oktatrace.timeline_builder.pipeline import sample_har_evidence
from tests.log_helpers import FRANKFURT, HOSTING, log_event


@pytest.fixture(scope="session")
def detection_result(dataset: LogDataset) -> DetectionResult:
    return detect_and_evaluate(dataset)[0]


@pytest.fixture(scope="session")
def timeline(dataset: LogDataset, detection_result: DetectionResult) -> TimelineResult:
    return build_timeline(dataset.events, detection_result.alerts, sample_har_evidence(dataset.seed, 8 * 3600))


def test_entries_are_chronological_with_sequential_ids(timeline: TimelineResult) -> None:
    stamps = [e.timestamp for e in timeline.entries]
    assert stamps == sorted(stamps)
    assert [e.id for e in timeline.entries] == [f"TL-{i:04d}" for i in range(1, len(stamps) + 1)]
    assert timeline.entries[0].kind == "har_capture"


def test_incident_scope_keeps_linked_alerts_and_drops_false_positives(
    dataset: LogDataset, detection_result: DetectionResult, timeline: TimelineResult
) -> None:
    attack = {u for u, l in dataset.labels.items() if l.is_attack}
    for alert in detection_result.alerts:
        linked = bool(set(alert.event_uuids + alert.context_event_uuids) & attack)
        assert (alert.id in timeline.incident_alerts) == linked, alert.id
    assert timeline.pivots.matched_fingerprints == [dataset.scenario.victim_session_fingerprint]
    assert timeline.pivots.attacker_asns == [dataset.scenario.attacker_asn]


def test_all_alerts_scope_includes_everything(dataset: LogDataset, detection_result: DetectionResult) -> None:
    result = build_timeline(dataset.events, detection_result.alerts, sample_har_evidence(dataset.seed), "all_alerts")
    alert_ids = {e.related_alerts[0] for e in result.entries if e.kind == "alert"}
    assert alert_ids == {a.id for a in detection_result.alerts}


def test_every_attack_event_is_on_the_timeline_and_benign_context_is_untagged(
    dataset: LogDataset, timeline: TimelineResult
) -> None:
    evaluation = evaluate_timeline(timeline, dataset.labels)
    assert evaluation.coverage == 1.0
    assert evaluation.benign_entries_tagged_with_technique == 0


def test_suspicious_entries_carry_valid_techniques_and_evidence(timeline: TimelineResult) -> None:
    for entry in timeline.entries:
        assert entry.evidence, entry.id
        for tag in entry.mitre:
            assert tag.technique_id in TECHNIQUES
            assert tag.url.startswith("https://attack.mitre.org/techniques/")
        if entry.kind in ("alert", "inference", "har_finding"):
            assert entry.mitre and entry.suspicious
        if entry.mitre:
            assert entry.stage == entry.mitre[0].tactic


def test_har_findings_and_inference_link_the_artefacts(dataset: LogDataset, timeline: TimelineResult) -> None:
    findings = [e for e in timeline.entries if e.kind == "har_finding"]
    assert {e.title.split(":")[0] for e in findings} == {"HAR-011", "HAR-013"}  # sid and DT
    [inference] = [e for e in timeline.entries if e.kind == "inference"]
    assert [t.technique_id for t in inference.mitre] == ["T1539"]
    assert inference.session_fingerprint == dataset.scenario.victim_session_fingerprint
    download = next(e for e in timeline.entries if e.kind == "event" and HAR_FILENAME in e.title
                    and e.title.startswith("Download"))
    assert inference.timestamp == download.timestamp
    types = {ref.type for ref in inference.evidence}
    assert types == {"har_finding", "event", "alert"}


def test_attacker_actions_get_the_expected_techniques(timeline: TimelineResult) -> None:
    by_title = {e.title: {t.technique_id for t in e.mitre} for e in timeline.entries if e.kind == "event"}
    assert by_title["Create Okta user: it-helpdesk-svc@acme.example"] == {"T1136.003", "T1550.004"}
    assert by_title["Add user to group membership: Acme-Super-Admins"] == {"T1098", "T1550.004"}
    assert by_title["Create API token: sync-helper"] == {"T1098.001", "T1550.004"}
    assert by_title[f"Download support case attachment: {HAR_FILENAME}"] == {"T1213", "T1552.001", "T1078"}
    stages = [e.stage for e in timeline.entries if e.stage]
    assert stages.index("Initial Access") < stages.index("Lateral Movement") < stages.index("Persistence")


def test_genuine_side_of_impossible_travel_is_not_tagged() -> None:
    event = log_event()
    attacker = log_event(network=HOSTING, place=FRANKFURT)
    assert event_techniques(event, {"OT-DET-002"}, on_attacker_network=False) == []
    assert event_techniques(attacker, {"OT-DET-002"}, on_attacker_network=True) == ["T1078"]
    assert event_techniques(event, set()) == []


def test_rule_techniques_exist_in_catalogue() -> None:
    assert {t for rule in RULES for t in rule.info.mitre_techniques} <= set(TECHNIQUES)


def test_timeline_is_deterministic_and_has_no_raw_session_ids(
    dataset: LogDataset, detection_result: DetectionResult, timeline: TimelineResult
) -> None:
    again = build_timeline(dataset.events, detection_result.alerts, sample_har_evidence(dataset.seed, 8 * 3600))
    assert again.model_dump() == timeline.model_dump()
    assert dataset.scenario.victim_session_id not in timeline.model_dump_json()


def test_other_seed_still_links_har_and_log() -> None:
    other = generate_dataset(7)
    alerts = detect_and_evaluate(other)[0].alerts
    result = build_timeline(other.events, alerts, sample_har_evidence(7))
    assert result.pivots.matched_fingerprints == [other.scenario.victim_session_fingerprint]
    assert evaluate_timeline(result, other.labels).coverage == 1.0


def test_without_har_evidence_all_alerts_are_kept(dataset: LogDataset, detection_result: DetectionResult) -> None:
    result = build_timeline(dataset.events, detection_result.alerts, None)
    assert result.excluded_alerts == []
    assert not any(e.kind in ("har_capture", "har_finding", "inference") for e in result.entries)


# -- API and CLI ------------------------------------------------------------------
@pytest.fixture
def client(tmp_path: Path, dataset: LogDataset) -> Iterator[TestClient]:
    store = SqliteStore(tmp_path / "tl.db")
    store.save_dataset(dataset)
    app = create_app()
    settings = replace(get_settings(), db_path=store.path)
    app.dependency_overrides[get_settings] = lambda: settings
    with TestClient(app) as test_client:
        yield test_client


def test_timeline_endpoints(client: TestClient) -> None:
    body = client.get("/api/timeline").json()
    assert body["scope"] == "incident" and body["entries"]
    assert len(client.get("/api/timeline", params={"scope": "all_alerts"}).json()["excluded_alerts"]) == 2
    assert client.get("/api/timeline/evaluation").json()["coverage"] == 1.0
    assert client.get("/api/timeline", params={"scope": "everything"}).status_code == 422


def test_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli_main(["--db", str(tmp_path / "cli.db"), "--json", str(tmp_path / "tl.json")]) == 0
    out = capsys.readouterr().out
    assert "T1550.004" in out and "inferred" in out
    assert (tmp_path / "tl.json").exists()
