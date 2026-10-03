"""Deterministic detection rules.

Each rule inspects the event stream and returns one :class:`RuleMatch` per
offending event. The engine then merges nearby matches into alerts. Rules use
only fields present in the log (IP, ASN, geolocation, user agent, event type,
session ID) plus the directory; they never see ground-truth labels.

| ID         | Rule                                   | Severity |
|------------|----------------------------------------|----------|
| OT-DET-001 | Session token reused from another IP   | high     |
| OT-DET-002 | Impossible travel                      | high     |
| OT-DET-003 | New user agent on an existing session  | medium   |
| OT-DET-004 | Admin action without recent MFA        | high     |
| OT-DET-005 | Bulk support-case access               | medium   |
| OT-DET-006 | Off-hours admin action                 | medium   |
| OT-DET-007 | Service account from a new network     | high     |
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import deque
from datetime import timedelta
from typing import ClassVar, Final

from oktatrace.common.geo import haversine_km
from oktatrace.common.severity import Severity
from oktatrace.detection_engine.context import (
    DetectionContext,
    describe_origin,
    format_delta,
    session_label,
)
from oktatrace.detection_engine.models import RuleInfo, RuleMatch
from oktatrace.log_generator import catalog
from oktatrace.log_generator.models import SystemLogEvent

SENSITIVE_EVENT_TYPES: Final = frozenset(catalog.ADMIN_EVENT_TYPES)


def _actor(event: SystemLogEvent) -> str:
    return event.actor.alternate_id


class Rule(ABC):
    """Base class: subclasses declare :attr:`info` and implement :meth:`evaluate`."""

    info: ClassVar[RuleInfo]

    @abstractmethod
    def evaluate(self, context: DetectionContext) -> list[RuleMatch]:
        """Return a match for every offending event, in any order."""

    def match(self, event: SystemLogEvent, group_key: str, explanation: str, **kwargs: object) -> RuleMatch:
        """Build a match for ``event`` (extra keyword arguments go to :class:`RuleMatch`)."""
        return RuleMatch(
            rule_id=self.info.rule_id,
            timestamp=event.published,
            group_key=group_key,
            actor=_actor(event),
            session_id=event.session_id,
            flagged=kwargs.pop("flagged", (event.uuid,)),  # type: ignore[arg-type]
            explanation=explanation,
            **kwargs,  # type: ignore[arg-type]
        )


class SessionMultiIpRule(Rule):
    """A session is used from an IP on a different network than the one it was established on."""

    info = RuleInfo(
        rule_id="OT-DET-001",
        name="Session token reused from another IP",
        severity=Severity.HIGH,
        description=(
            "Fires when an event in an existing session comes from a different IP address, on a "
            "different autonomous system, than the session's first event, with no new sign-in."
        ),
        rationale=(
            "A stolen session cookie lets an attacker skip the password and MFA entirely; the only "
            "trace is the same session ID appearing from new infrastructure."
        ),
        mitre_techniques=["T1550.004", "T1539"],
    )

    def evaluate(self, context: DetectionContext) -> list[RuleMatch]:
        matches: list[RuleMatch] = []
        for session_id, events in context.by_session.items():
            origin = events[0]
            for event in events[1:]:
                if event.client.ip_address == origin.client.ip_address:
                    continue
                same_asn = event.security_context.as_number == origin.security_context.as_number
                if context.config.require_asn_change and same_asn:
                    continue
                explanation = (
                    f"{session_label(session_id)} for {_actor(event)} was established from "
                    f"{describe_origin(origin)} but was used from {describe_origin(event)} "
                    f"{format_delta(event.published - origin.published)} later, without a new sign-in."
                )
                matches.append(self.match(
                    event, f"{session_id}|{event.client.ip_address}", explanation,
                    context=(origin.uuid,),
                    details={"origin_ip": origin.client.ip_address,
                             "origin_asn": origin.security_context.as_number,
                             "new_ip": event.client.ip_address,
                             "new_asn": event.security_context.as_number},
                ))
        return matches


class ImpossibleTravelRule(Rule):
    """Consecutive events for one user are too far apart to travel between in the time available."""

    info = RuleInfo(
        rule_id="OT-DET-002",
        name="Impossible travel",
        severity=Severity.HIGH,
        description=(
            "Fires when two consecutive events for the same user are more than the minimum distance "
            "apart and the implied speed exceeds the maximum (default 900 km/h, airliner cruise)."
        ),
        rationale=(
            "A user cannot be in San Francisco and Frankfurt minutes apart; one of the two must be "
            "someone else using their credentials or session."
        ),
        mitre_techniques=["T1078"],
    )

    def evaluate(self, context: DetectionContext) -> list[RuleMatch]:
        cfg = context.config
        matches: list[RuleMatch] = []
        for actor, events in context.by_actor.items():
            for previous, current in zip(events, events[1:]):
                a = previous.client.geographical_context.geolocation
                b = current.client.geographical_context.geolocation
                distance = haversine_km(a.lat, a.lon, b.lat, b.lon)
                if distance < cfg.min_travel_distance_km:
                    continue
                hours = max((current.published - previous.published).total_seconds(), 1.0) / 3600
                speed = distance / hours
                if speed <= cfg.max_travel_speed_kmh:
                    continue
                origin_city = previous.client.geographical_context.city
                new_city = current.client.geographical_context.city
                explanation = (
                    f"{actor} was seen in {new_city} {format_delta(current.published - previous.published)} "
                    f"after {origin_city}: {distance:,.0f} km, an implied {speed:,.0f} km/h "
                    f"(limit {cfg.max_travel_speed_kmh:,.0f} km/h)."
                )
                matches.append(self.match(
                    current, actor, explanation, context=(previous.uuid,),
                    details={"from_city": origin_city, "to_city": new_city,
                             "distance_km": round(distance, 1), "speed_kmh": round(speed, 1)},
                ))
        return matches


class NewUserAgentRule(Rule):
    """A session continues in a different browser or operating system than it started in."""

    info = RuleInfo(
        rule_id="OT-DET-003",
        name="New user agent on an existing session",
        severity=Severity.MEDIUM,
        description=(
            "Fires when an event's browser family and OS differ from the session's first event. "
            "Version-only changes (browser auto-updates) are ignored by default."
        ),
        rationale=(
            "Session cookies are bound to a browser. The same session suddenly appearing in a "
            "different browser on a different OS means the cookie was copied."
        ),
        mitre_techniques=["T1550.004"],
    )

    @staticmethod
    def _agent(event: SystemLogEvent, ignore_version: bool) -> str:
        agent = event.client.user_agent
        return f"{agent.browser} on {agent.os}" if ignore_version else agent.raw_user_agent

    def evaluate(self, context: DetectionContext) -> list[RuleMatch]:
        ignore_version = context.config.ignore_user_agent_version
        matches: list[RuleMatch] = []
        for session_id, events in context.by_session.items():
            origin = events[0]
            expected = self._agent(origin, ignore_version)
            for event in events[1:]:
                seen = self._agent(event, ignore_version)
                if seen == expected:
                    continue
                explanation = (
                    f"{session_label(session_id)} for {_actor(event)} started in {expected} but "
                    f"continued in {seen}."
                )
                matches.append(self.match(
                    event, f"{session_id}|{seen}", explanation, context=(origin.uuid,),
                    details={"original_agent": expected, "new_agent": seen},
                ))
        return matches


class StaleMfaAdminRule(Rule):
    """A privileged change on a session whose last MFA is old or missing."""

    info = RuleInfo(
        rule_id="OT-DET-004",
        name="Admin action without recent MFA",
        severity=Severity.HIGH,
        description=(
            "Fires when an admin event (user, group, factor, token or policy change) happens on a "
            "session whose most recent successful MFA is older than the freshness limit, or absent."
        ),
        rationale=(
            "Legitimate admins step up with MFA before privileged work. A replayed session carries "
            "only the MFA from whenever the victim originally signed in."
        ),
        mitre_techniques=["T1098", "T1550.004"],
    )

    def evaluate(self, context: DetectionContext) -> list[RuleMatch]:
        freshness = timedelta(minutes=context.config.mfa_freshness_minutes)
        matches: list[RuleMatch] = []
        for session_id, events in context.by_session.items():
            last_mfa: SystemLogEvent | None = None
            for event in events:
                if event.event_type == catalog.MFA_VERIFY and event.outcome.result == "SUCCESS":
                    last_mfa = event
                    continue
                if event.event_type not in SENSITIVE_EVENT_TYPES:
                    continue
                if last_mfa is not None and event.published - last_mfa.published <= freshness:
                    continue
                if last_mfa is None:
                    age_text, age_minutes = "no MFA is recorded on this session", None
                else:
                    age = event.published - last_mfa.published
                    age_text = f"the last MFA was {format_delta(age)} earlier"
                    age_minutes = round(age.total_seconds() / 60)
                explanation = (
                    f"{event.event_type} by {_actor(event)} on {session_label(session_id)}: {age_text} "
                    f"(limit {context.config.mfa_freshness_minutes} min)."
                )
                matches.append(self.match(
                    event, session_id, explanation,
                    context=(last_mfa.uuid,) if last_mfa else (),
                    details={"event_type": event.event_type, "mfa_age_minutes": age_minutes},
                ))
        return matches


class BulkCaseAccessRule(Rule):
    """Many distinct support cases viewed by one actor in a short window."""

    info = RuleInfo(
        rule_id="OT-DET-005",
        name="Bulk support-case access",
        severity=Severity.MEDIUM,
        description=(
            "Fires when one actor views at least the threshold number of distinct support cases "
            "within the sliding window (default 15 cases in 10 minutes)."
        ),
        rationale=(
            "Support cases hold customer artefacts such as HAR files. Harvesting them shows up as "
            "rapid, broad access that normal triage does not reach."
        ),
        mitre_techniques=["T1213"],
    )

    def evaluate(self, context: DetectionContext) -> list[RuleMatch]:
        cfg = context.config
        window = timedelta(minutes=cfg.bulk_case_window_minutes)
        matches: list[RuleMatch] = []
        for actor, events in context.by_actor.items():
            recent: deque[tuple[SystemLogEvent, str]] = deque()
            for event in events:
                if event.event_type != catalog.SUPPORT_CASE_VIEW or event.outcome.result != "SUCCESS":
                    continue
                case = next((t.id for t in event.target if t.type == "SupportCase"), "unknown")
                recent.append((event, case))
                while event.published - recent[0][0].published > window:
                    recent.popleft()
                distinct = {c for _, c in recent}
                if len(distinct) < cfg.bulk_case_threshold:
                    continue
                explanation = (
                    f"{actor} viewed {len(distinct)} distinct support cases within "
                    f"{cfg.bulk_case_window_minutes} minutes (threshold {cfg.bulk_case_threshold})."
                )
                matches.append(self.match(
                    event, actor, explanation, flagged=tuple(e.uuid for e, _ in recent),
                    details={"distinct_cases": len(distinct)},
                ))
        return matches


class OffHoursAdminRule(Rule):
    """Admin changes at night or at weekends in the actor's local time."""

    info = RuleInfo(
        rule_id="OT-DET-006",
        name="Off-hours admin action",
        severity=Severity.MEDIUM,
        description=(
            "Fires when an admin event happens outside business hours (default 07:00-20:00) or at a "
            "weekend, in the actor's home time zone from the directory."
        ),
        rationale=(
            "Attackers often act while the victim sleeps to delay discovery; planned maintenance is "
            "the main benign cause, so this is a medium-severity signal."
        ),
        mitre_techniques=["T1078"],
    )

    def evaluate(self, context: DetectionContext) -> list[RuleMatch]:
        cfg = context.config
        matches: list[RuleMatch] = []
        for event in context.events:
            if event.event_type not in SENSITIVE_EVENT_TYPES:
                continue
            offset = context.utc_offset_hours(_actor(event))
            local = event.published + timedelta(hours=offset)
            weekend = local.weekday() >= 5
            if not weekend and cfg.business_hours_start <= local.hour < cfg.business_hours_end:
                continue
            when = "at the weekend" if weekend else "outside business hours"
            explanation = (
                f"{event.event_type} by {_actor(event)} at {local:%a %H:%M} local time (UTC{offset:+d}), "
                f"{when} ({cfg.business_hours_start:02d}:00-{cfg.business_hours_end:02d}:00, Mon-Fri)."
            )
            matches.append(self.match(
                event, _actor(event), explanation,
                details={"local_time": local.strftime("%Y-%m-%d %H:%M"), "weekend": weekend},
            ))
        return matches


class ServiceAccountNewNetworkRule(Rule):
    """A service account signs in from a network outside its learned baseline."""

    info = RuleInfo(
        rule_id="OT-DET-007",
        name="Service account from a new network",
        severity=Severity.HIGH,
        description=(
            "Learns the networks (ASNs) each service account signs in from during a baseline period, "
            "then flags later sign-ins from any other network and every event in those sessions."
        ),
        rationale=(
            "Service accounts run from fixed infrastructure, so a new network is a strong signal. "
            "The 2023 intrusion began with a stolen service-account credential."
        ),
        mitre_techniques=["T1078"],
    )

    def evaluate(self, context: DetectionContext) -> list[RuleMatch]:
        baseline = timedelta(hours=context.config.service_baseline_hours)
        matches: list[RuleMatch] = []
        for login, user in context.users.items():
            if user.role != "service_account":
                continue
            sign_ins = [e for e in context.by_actor.get(login, [])
                        if e.event_type == catalog.SESSION_START and e.outcome.result == "SUCCESS"]
            if not sign_ins:
                continue
            learning_ends = sign_ins[0].published + baseline
            known = {e.security_context.as_number for e in sign_ins if e.published < learning_ends}
            for sign_in in sign_ins:
                if sign_in.published < learning_ends or sign_in.security_context.as_number in known:
                    continue
                explanation = (
                    f"Service account {login} signed in from {describe_origin(sign_in)}, outside the "
                    f"networks seen in its first {context.config.service_baseline_hours}h "
                    f"(AS{', AS'.join(str(a) for a in sorted(known))})."
                )
                session_events = context.by_session.get(sign_in.session_id or "", [sign_in])
                for event in session_events:
                    matches.append(self.match(
                        event, f"{login}|{sign_in.session_id}", explanation,
                        details={"asn": sign_in.security_context.as_number, "known_asns": sorted(known)},
                    ))
        return matches


RULES: Final[tuple[Rule, ...]] = (
    SessionMultiIpRule(),
    ImpossibleTravelRule(),
    NewUserAgentRule(),
    StaleMfaAdminRule(),
    BulkCaseAccessRule(),
    OffHoursAdminRule(),
    ServiceAccountNewNetworkRule(),
)
RULES_BY_ID: Final = {rule.info.rule_id: rule for rule in RULES}
