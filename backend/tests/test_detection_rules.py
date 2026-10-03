"""Unit tests for every detection rule, with positive and negative cases."""

from __future__ import annotations

from collections.abc import Sequence

from oktatrace.detection_engine import DetectionConfig, RuleMatch
from oktatrace.detection_engine.context import build_context
from oktatrace.detection_engine.rules import (
    BulkCaseAccessRule,
    ImpossibleTravelRule,
    NewUserAgentRule,
    OffHoursAdminRule,
    Rule,
    ServiceAccountNewNetworkRule,
    SessionMultiIpRule,
    StaleMfaAdminRule,
)
from oktatrace.log_generator.models import DirectoryEntry, SystemLogEvent
from tests.log_helpers import (
    CORP,
    CORP_NAT,
    FRANKFURT,
    HOME,
    HOSTING,
    MAC_CHROME,
    MAC_CHROME_NEW,
    NYC,
    OAKLAND,
    SF,
    T0,
    VENDOR,
    WIN_FIREFOX,
    case,
    directory_entry,
    log_event,
    minutes,
)

ADMIN = "group.user_membership.add"
MFA = "user.authentication.auth_via_mfa"


def run(rule: Rule, events: Sequence[SystemLogEvent], users: Sequence[DirectoryEntry] = (),
        **config: object) -> list[RuleMatch]:
    return rule.evaluate(build_context(events, users, DetectionConfig(**config)))  # type: ignore[arg-type]


# -- OT-DET-001 session reused from another IP ----------------------------------
def test_multi_ip_flags_session_used_from_new_network() -> None:
    origin = log_event(T0, "user.session.start")
    replay = log_event(T0 + minutes(30), network=HOSTING, place=FRANKFURT)
    [match] = run(SessionMultiIpRule(), [origin, replay])
    assert match.rule_id == "OT-DET-001"
    assert match.flagged == (replay.uuid,)
    assert match.context == (origin.uuid,)
    assert match.details["new_asn"] == 65066
    assert "S-ALICE" not in match.explanation  # sessions are referred to by fingerprint


def test_multi_ip_ignores_same_ip_and_nat_pool_changes() -> None:
    events = [log_event(T0, "user.session.start"), log_event(T0 + minutes(5)),
              log_event(T0 + minutes(9), network=CORP_NAT)]
    assert run(SessionMultiIpRule(), events) == []
    assert len(run(SessionMultiIpRule(), events, require_asn_change=False)) == 1


def test_multi_ip_ignores_different_sessions() -> None:
    events = [log_event(T0, session="S1"), log_event(T0 + minutes(5), session="S2", network=HOME)]
    assert run(SessionMultiIpRule(), events) == []


# -- OT-DET-002 impossible travel -----------------------------------------------
def test_impossible_travel_flags_sf_to_frankfurt_in_minutes() -> None:
    first = log_event(T0)
    second = log_event(T0 + minutes(6), network=HOSTING, place=FRANKFURT, session="S-OTHER")
    [match] = run(ImpossibleTravelRule(), [first, second])
    assert match.flagged == (second.uuid,)
    assert match.context == (first.uuid,)
    assert match.details["distance_km"] > 9000
    assert match.details["speed_kmh"] > 900


def test_impossible_travel_allows_flights_and_nearby_moves() -> None:
    flight = [log_event(T0), log_event(T0 + minutes(12 * 60), place=NYC)]
    nearby = [log_event(T0, actor="bob@acme.example"),
              log_event(T0 + minutes(1), actor="bob@acme.example", place=OAKLAND, network=HOME)]
    assert run(ImpossibleTravelRule(), flight + nearby) == []


def test_impossible_travel_respects_speed_threshold() -> None:
    events = [log_event(T0), log_event(T0 + minutes(6), place=FRANKFURT)]
    assert run(ImpossibleTravelRule(), events, max_travel_speed_kmh=200_000) == []


# -- OT-DET-003 new user agent on a session --------------------------------------
def test_new_user_agent_flags_different_browser_and_os() -> None:
    origin = log_event(T0, "user.session.start")
    copied = log_event(T0 + minutes(10), agent=WIN_FIREFOX)
    [match] = run(NewUserAgentRule(), [origin, copied])
    assert match.flagged == (copied.uuid,)
    assert match.details == {"original_agent": "CHROME on Mac OS X", "new_agent": "FIREFOX on Windows 10"}


def test_new_user_agent_ignores_version_updates_by_default() -> None:
    events = [log_event(T0, agent=MAC_CHROME), log_event(T0 + minutes(90), agent=MAC_CHROME_NEW)]
    assert run(NewUserAgentRule(), events) == []
    assert len(run(NewUserAgentRule(), events, ignore_user_agent_version=False)) == 1


# -- OT-DET-004 admin action without recent MFA ----------------------------------
def test_stale_mfa_flags_admin_action_long_after_mfa() -> None:
    mfa = log_event(T0, MFA)
    action = log_event(T0 + minutes(16 * 60), ADMIN)
    [match] = run(StaleMfaAdminRule(), [mfa, action])
    assert match.flagged == (action.uuid,)
    assert match.context == (mfa.uuid,)
    assert match.details["mfa_age_minutes"] == 960


def test_stale_mfa_flags_session_with_no_mfa_or_failed_mfa() -> None:
    no_mfa = [log_event(T0, ADMIN, session="S1")]
    failed = [log_event(T0, MFA, session="S2", outcome="FAILURE"),
              log_event(T0 + minutes(1), ADMIN, session="S2")]
    matches = run(StaleMfaAdminRule(), no_mfa + failed)
    assert len(matches) == 2
    assert all(m.context == () for m in matches)


def test_stale_mfa_accepts_step_up_and_ignores_non_admin_events() -> None:
    events = [log_event(T0, MFA), log_event(T0 + minutes(5), ADMIN),
              log_event(T0 + minutes(300), "user.authentication.sso")]
    assert run(StaleMfaAdminRule(), events) == []


# -- OT-DET-005 bulk support-case access ------------------------------------------
def test_bulk_case_access_flags_fast_broad_access() -> None:
    views = [log_event(T0 + minutes(i * 0.5), "support.case.view", targets=(case(f"CASE-{i:05d}"),))
             for i in range(15)]
    matches = run(BulkCaseAccessRule(), views)
    assert len(matches) == 1
    assert set(matches[0].flagged) == {v.uuid for v in views}


def test_bulk_case_access_ignores_slow_triage_and_repeat_views() -> None:
    slow = [log_event(T0 + minutes(i * 4), "support.case.view", targets=(case(f"CASE-{i:05d}"),))
            for i in range(20)]
    repeat = [log_event(T0 + minutes(i * 0.2), "support.case.view", actor="bob@acme.example",
                        targets=(case("CASE-00001"),)) for i in range(25)]
    assert run(BulkCaseAccessRule(), slow + repeat) == []


# -- OT-DET-006 off-hours admin action -------------------------------------------
def test_off_hours_flags_night_and_weekend_actions() -> None:
    night = log_event(T0.replace(hour=9, minute=41), ADMIN)  # 02:41 Tuesday in SF
    weekend = log_event(T0.replace(day=7, hour=18), ADMIN)  # 11:00 Saturday in SF
    users = [directory_entry("alice@acme.example")]
    matches = run(OffHoursAdminRule(), [night, weekend], users)
    assert [m.flagged for m in matches] == [(night.uuid,), (weekend.uuid,)]
    assert matches[1].details["weekend"] is True


def test_off_hours_uses_each_users_time_zone() -> None:
    at_noon_utc = T0.replace(hour=12)
    sf_admin = log_event(at_noon_utc, ADMIN, actor="sf@acme.example")  # 05:00 local
    nyc_admin = log_event(at_noon_utc, ADMIN, actor="nyc@acme.example")  # 08:00 local
    users = [directory_entry("sf@acme.example", utc_offset_hours=-7),
             directory_entry("nyc@acme.example", utc_offset_hours=-4)]
    [match] = run(OffHoursAdminRule(), [sf_admin, nyc_admin], users)
    assert match.actor == "sf@acme.example"


def test_off_hours_ignores_business_hours_and_non_admin_events() -> None:
    events = [log_event(T0, ADMIN), log_event(T0.replace(hour=9), "user.authentication.sso")]
    assert run(OffHoursAdminRule(), events, [directory_entry("alice@acme.example")]) == []


# -- OT-DET-007 service account from a new network --------------------------------
SVC = "svc@vendor.example"


def _svc_sign_in(when, network=VENDOR, session="SVC-1"):  # type: ignore[no-untyped-def]
    return log_event(when, "user.session.start", actor=SVC, session=session, network=network)


def test_service_account_new_network_flags_whole_session() -> None:
    baseline = [_svc_sign_in(T0 + minutes(i * 360), session=f"SVC-{i}") for i in range(4)]
    rogue = _svc_sign_in(T0 + minutes(3 * 1440), network=HOSTING, session="SVC-X")
    download = log_event(rogue.published + minutes(1), "support.case.attachment.download",
                         actor=SVC, session="SVC-X", network=HOSTING)
    matches = run(ServiceAccountNewNetworkRule(), [*baseline, rogue, download],
                  [directory_entry(SVC, role="service_account")])
    assert [m.flagged for m in matches] == [(rogue.uuid,), (download.uuid,)]
    assert matches[0].details["known_asns"] == [64800]


def test_service_account_known_network_and_baseline_period_are_quiet() -> None:
    events = [_svc_sign_in(T0, session="A"),
              _svc_sign_in(T0 + minutes(60), network=HOME, session="B"),  # learned during baseline
              _svc_sign_in(T0 + minutes(3 * 1440), session="C"),
              _svc_sign_in(T0 + minutes(4 * 1440), network=HOME, session="D")]
    assert run(ServiceAccountNewNetworkRule(), events, [directory_entry(SVC, role="service_account")]) == []


def test_service_account_rule_ignores_human_accounts() -> None:
    events = [_svc_sign_in(T0), _svc_sign_in(T0 + minutes(3 * 1440), network=HOSTING, session="X")]
    assert run(ServiceAccountNewNetworkRule(), events, [directory_entry(SVC, role="employee")]) == []
