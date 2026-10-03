"""Tests for the synthetic System Log generator (Module 2)."""

from __future__ import annotations

import ipaddress
import json
from collections import Counter
from datetime import timedelta
from pathlib import Path

import pytest

from oktatrace.common.masking import fingerprint
from oktatrace.har_analyzer import FindingKind, analyze_har
from oktatrace.har_analyzer.sample_har import build_sample_har
from oktatrace.log_generator import (
    AttackPhase,
    LabelCategory,
    LogDataset,
    SystemLogEvent,
    generate_dataset,
    validate_dataset,
)
from oktatrace.log_generator import catalog
from oktatrace.log_generator.__main__ import main as cli_main
from oktatrace.log_generator.export import GROUND_TRUTH_FILENAME, LOG_FILENAME
from oktatrace.scenario import ORG_UTC_OFFSET_HOURS

DOCUMENTATION_NETWORKS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def events_with(dataset: LogDataset, *, category: LabelCategory | None = None,
                phase: AttackPhase | None = None, scenario: str | None = None) -> list[SystemLogEvent]:
    selected = []
    for event in dataset.events:
        label = dataset.labels[event.uuid]
        if category is not None and label.category is not category:
            continue
        if phase is not None and label.phase is not phase:
            continue
        if scenario is not None and label.scenario != scenario:
            continue
        selected.append(event)
    return selected


def test_volume_and_population(dataset: LogDataset) -> None:
    assert len(dataset.events) >= 5000
    roles = Counter(u.role for u in dataset.users)
    assert roles == {"employee": 42, "admin": 5, "support_engineer": 3, "service_account": 1}
    active = {e.actor.alternate_id for e in dataset.events}
    assert len(active) == len(dataset.users)


def test_same_seed_same_dataset_different_seed_different(dataset: LogDataset) -> None:
    assert generate_dataset(dataset.seed).model_dump() == dataset.model_dump()
    other = generate_dataset(dataset.seed + 1)
    assert [e.uuid for e in other.events] != [e.uuid for e in dataset.events]


def test_required_event_types_present(dataset: LogDataset) -> None:
    types = {e.event_type for e in dataset.events}
    assert {catalog.SESSION_START, catalog.MFA_VERIFY, catalog.APP_SSO, catalog.SUPPORT_CASE_VIEW} <= types
    assert types & set(catalog.ADMIN_EVENT_TYPES)


def test_dataset_invariants_hold(dataset: LogDataset) -> None:
    validate_dataset(dataset)  # raises on failure
    stamps = [e.published for e in dataset.events]
    assert stamps == sorted(stamps)
    assert all(dataset.window_start <= s < dataset.window_end for s in stamps)
    assert set(dataset.labels) == {e.uuid for e in dataset.events}


def test_attack_steps_are_ordered_and_cover_every_phase(dataset: LogDataset) -> None:
    steps = dataset.attack_steps
    assert [s.step for s in steps] == list(range(1, len(steps) + 1))
    assert [s.published for s in steps] == sorted(s.published for s in steps)
    phases = list(dict.fromkeys(s.phase for s in steps))
    assert phases == [AttackPhase.INITIAL_ACCESS, AttackPhase.HAR_EXFILTRATION, AttackPhase.SESSION_REPLAY,
                      AttackPhase.CASE_COLLECTION, AttackPhase.ADMIN_ATTEMPT]
    assert all(dataset.labels[s.event_uuid].is_attack for s in steps)


def test_replayed_session_is_the_one_leaked_in_the_har(dataset: LogDataset) -> None:
    har = analyze_har(build_sample_har(), long_lived_threshold_seconds=8 * 3600)
    sid = next(f for f in har.findings if f.name == "sid")
    device = next(f for f in har.findings if f.kind is FindingKind.DEVICE_TOKEN)
    replay = events_with(dataset, phase=AttackPhase.SESSION_REPLAY)
    assert {e.session_id for e in replay} == {dataset.scenario.victim_session_id}
    assert fingerprint(dataset.scenario.victim_session_id) == sid.fingerprint
    assert dataset.scenario.victim_device_fingerprint == device.fingerprint
    # The replayed DT cookie makes the attacker's requests carry the victim's dtHash.
    assert {e.debug_context.debug_data["dtHash"][:12] for e in replay} == {device.fingerprint}


def test_replay_comes_from_new_ip_asn_and_browser(dataset: LogDataset) -> None:
    victim = dataset.scenario.victim_login
    usual = [e for e in events_with(dataset, category=LabelCategory.BENIGN) if e.actor.alternate_id == victim]
    replay = [e for e in events_with(dataset, category=LabelCategory.ATTACK) if e.actor.alternate_id == victim]
    assert replay
    assert {e.client.ip_address for e in usual}.isdisjoint(e.client.ip_address for e in replay)
    assert {e.security_context.as_number for e in usual}.isdisjoint(
        e.security_context.as_number for e in replay)
    assert {e.client.user_agent.raw_user_agent for e in usual}.isdisjoint(
        e.client.user_agent.raw_user_agent for e in replay)
    assert not any(e.event_type == catalog.SESSION_START for e in replay)  # no sign-in, just reuse


def test_victim_is_active_in_san_francisco_minutes_before_replay(dataset: LogDataset) -> None:
    first_replay = events_with(dataset, phase=AttackPhase.SESSION_REPLAY)[0]
    victim_before = [
        e for e in dataset.events
        if e.session_id == first_replay.session_id
        and not dataset.labels[e.uuid].is_attack
        and timedelta(0) < first_replay.published - e.published <= timedelta(minutes=10)
    ]
    assert victim_before
    assert victim_before[-1].client.geographical_context.city == "San Francisco"
    assert first_replay.client.geographical_context.country == "Germany"


def test_admin_attempts_are_off_hours_without_recent_mfa(dataset: LogDataset) -> None:
    attempts = events_with(dataset, phase=AttackPhase.ADMIN_ATTEMPT)
    assert len(attempts) == 5
    session = attempts[0].session_id
    last_mfa = max(e.published for e in dataset.events
                   if e.session_id == session and e.event_type == catalog.MFA_VERIFY)
    for event in attempts:
        local_hour = (event.published + timedelta(hours=ORG_UTC_OFFSET_HOURS)).hour
        assert 0 <= local_hour < 6
        assert event.published - last_mfa > timedelta(hours=12)
    assert Counter(e.outcome.result for e in attempts) == {"SUCCESS": 4, "FAILURE": 1}


def test_bulk_case_collection_is_fast(dataset: LogDataset) -> None:
    views = events_with(dataset, phase=AttackPhase.CASE_COLLECTION)
    assert len(views) == 30
    assert all(e.event_type == catalog.SUPPORT_CASE_VIEW for e in views)
    assert views[-1].published - views[0].published < timedelta(minutes=10)


def test_service_account_abuse_comes_from_new_network(dataset: LogDataset) -> None:
    service = dataset.scenario.compromised_service_account
    normal = {e.security_context.as_number for e in events_with(dataset, category=LabelCategory.BENIGN)
              if e.actor.alternate_id == service}
    abuse = events_with(dataset, phase=AttackPhase.INITIAL_ACCESS) + events_with(
        dataset, phase=AttackPhase.HAR_EXFILTRATION)
    assert {e.actor.alternate_id for e in abuse} == {service}
    assert normal.isdisjoint(e.security_context.as_number for e in abuse)
    har_download = next(e for e in abuse if any(t.alternate_id == "support_case_00421.har" for t in e.target))
    assert har_download.published > dataset.scenario.har_uploaded_at


@pytest.mark.parametrize(
    ("scenario", "check"),
    [
        ("vpn_switch", lambda evs: len({e.security_context.as_number for e in evs}) == 2),
        ("browser_update", lambda evs: len({e.client.user_agent.raw_user_agent for e in evs}) == 2),
        ("travel", lambda evs: {e.client.geographical_context.city for e in evs} == {"San Francisco", "New York"}),
        ("offhours_admin", lambda evs: any(e.event_type in catalog.ADMIN_EVENT_TYPES for e in evs)),
        ("support_bulk", lambda evs: sum(e.event_type == catalog.SUPPORT_CASE_VIEW for e in evs) >= 25),
    ],
)
def test_edge_cases_are_present_and_benign(dataset: LogDataset, scenario: str, check) -> None:  # type: ignore[no-untyped-def]
    events = events_with(dataset, scenario=scenario)
    assert events
    assert {dataset.labels[e.uuid].category for e in events} == {LabelCategory.EDGE_CASE}
    assert check(events)


def test_benign_admin_actions_follow_recent_mfa(dataset: LogDataset) -> None:
    mfa_by_session: dict[str, list] = {}
    for event in dataset.events:
        if event.event_type == catalog.MFA_VERIFY and event.outcome.result == "SUCCESS":
            mfa_by_session.setdefault(event.session_id or "", []).append(event.published)
    for event in dataset.events:
        if event.event_type in catalog.ADMIN_EVENT_TYPES and not dataset.labels[event.uuid].is_attack:
            recent = [t for t in mfa_by_session.get(event.session_id or "", [])
                      if timedelta(0) <= event.published - t <= timedelta(minutes=20)]
            assert recent, f"benign admin action {event.uuid} lacks step-up MFA"


def test_only_synthetic_infrastructure(dataset: LogDataset) -> None:
    for event in dataset.events:
        address = ipaddress.ip_address(event.client.ip_address)
        assert any(address in network for network in DOCUMENTATION_NETWORKS)
        assert 64512 <= event.security_context.as_number <= 65534  # RFC 6996 private-use ASNs
        assert event.actor.alternate_id.endswith(".example")


def test_events_serialise_as_okta_style_json(dataset: LogDataset) -> None:
    payload = dataset.events[0].model_dump(mode="json", by_alias=True)
    assert {"uuid", "published", "eventType", "actor", "client", "authenticationContext", "outcome"} <= set(payload)
    assert "externalSessionId" in payload["authenticationContext"]
    assert payload["published"].endswith("Z")


def test_cli_writes_db_and_files(tmp_path: Path) -> None:
    assert cli_main(["--seed", "7", "--db", str(tmp_path / "t.db"), "--out-dir", str(tmp_path)]) == 0
    lines = (tmp_path / LOG_FILENAME).read_text(encoding="utf-8").splitlines()
    truth = json.loads((tmp_path / GROUND_TRUTH_FILENAME).read_text(encoding="utf-8"))
    assert len(lines) == len(truth["labels"]) >= 5000
    assert "eventType" in json.loads(lines[0])
    assert (tmp_path / "t.db").exists()
