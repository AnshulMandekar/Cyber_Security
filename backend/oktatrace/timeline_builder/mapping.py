"""Deterministic MITRE ATT&CK tagging for events, alerts and HAR findings.

Only suspicious items get techniques; benign context events stay untagged.

| Evidence                                   | Technique(s)                      |
|--------------------------------------------|-----------------------------------|
| support case view / attachment download    | T1213 (+ T1552.001 for .har files)|
| user.lifecycle.create                      | T1136.003                         |
| group/app membership, password reset       | T1098                             |
| system.api_token.create                    | T1098.001                         |
| user.mfa.factor.deactivate                 | T1556.006                         |
| policy.rule.update                         | T1484                             |
| any event in a replayed session (001/003)  | + T1550.004                       |
| event flagged by 007, or by 002 on the     | + T1078                           |
| attacker's network                         |                                   |
| HAR session cookie / session / device token| T1539                             |
| other credentials found in a HAR           | T1552.001                         |
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Final

from oktatrace.common.mitre import TECHNIQUES
from oktatrace.har_analyzer.models import FindingKind
from oktatrace.log_generator import catalog
from oktatrace.log_generator.models import SystemLogEvent
from oktatrace.timeline_builder.models import MitreTag

EVENT_TYPE_TECHNIQUES: Final[dict[str, tuple[str, ...]]] = {
    catalog.SUPPORT_CASE_VIEW: ("T1213",),
    catalog.SUPPORT_ATTACHMENT_DOWNLOAD: ("T1213",),
    "user.lifecycle.create": ("T1136.003",),
    "group.user_membership.add": ("T1098",),
    "group.user_membership.remove": ("T1098",),
    "application.user_membership.add": ("T1098",),
    "user.account.reset_password": ("T1098",),
    "user.lifecycle.deactivate": ("T1098",),
    "system.api_token.create": ("T1098.001",),
    "user.mfa.factor.deactivate": ("T1556.006",),
    "policy.rule.update": ("T1484",),
}
REPLAY_RULES: Final = frozenset({"OT-DET-001", "OT-DET-003"})
SESSION_FINDING_KINDS: Final = frozenset(
    {FindingKind.SESSION_COOKIE, FindingKind.SESSION_TOKEN, FindingKind.DEVICE_TOKEN}
)


def tags(technique_ids: Iterable[str]) -> list[MitreTag]:
    """Turn technique IDs into tags, dropping duplicates but keeping order."""
    result: list[MitreTag] = []
    for technique_id in dict.fromkeys(technique_ids):
        technique = TECHNIQUES[technique_id]
        result.append(MitreTag(technique_id=technique.technique_id, name=technique.name,
                               tactic=technique.primary_tactic, url=technique.url))
    return result


def event_techniques(
    event: SystemLogEvent, flagging_rules: set[str], *, on_attacker_network: bool = True
) -> list[str]:
    """Techniques for an event flagged by ``flagging_rules`` (empty if it was not flagged).

    Impossible travel (OT-DET-002) flags both ends of a hop and cannot tell which is the
    intruder. An event flagged *only* by that rule and not on the attacker's network is
    treated as the genuine user's side and gets no technique.
    """
    if not flagging_rules:
        return []
    if flagging_rules == {"OT-DET-002"} and not on_attacker_network:
        return []
    ids = list(EVENT_TYPE_TECHNIQUES.get(event.event_type, ()))
    if event.event_type == catalog.SUPPORT_ATTACHMENT_DOWNLOAD and any(
        t.alternate_id.lower().endswith(".har") for t in event.target
    ):
        ids.append("T1552.001")
    if flagging_rules & REPLAY_RULES:
        ids.append("T1550.004")
    if "OT-DET-007" in flagging_rules or ("OT-DET-002" in flagging_rules and on_attacker_network):
        ids.append("T1078")
    return ids


def har_finding_techniques(kind: FindingKind) -> list[str]:
    """Techniques for a secret found in a HAR file."""
    return ["T1539"] if kind in SESSION_FINDING_KINDS else ["T1552.001"]
