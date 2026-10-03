"""Merge HAR evidence, log events and alerts into one ordered incident timeline.

Scoping ("incident" mode) pivots from the leaked token, the way an analyst would:

1. **Seed**: alerts whose session fingerprint equals a fingerprint found in the HAR.
2. **Pivot**: the seed alerts' actors, plus the networks (ASNs) of events that
   OT-DET-001 flagged as coming from a new network, i.e. the replay infrastructure.
3. **Widen**: keep every alert for those actors, or with a flagged event on those
   networks. Everything else is listed as excluded (unrelated to this incident).

The timeline then holds those alerts, their flagged and context events, the HAR
upload/download events, the HAR capture, the HAR findings that reappear in the
logs, and one inferred step (cookie extraction) that no log records directly.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from oktatrace.common.masking import fingerprint
from oktatrace.common.severity import Severity
from oktatrace.detection_engine.context import describe_origin
from oktatrace.detection_engine.models import Alert
from oktatrace.har_analyzer.models import Finding, FindingKind, HarAnalysisResult
from oktatrace.log_generator import catalog
from oktatrace.log_generator.models import SystemLogEvent
from oktatrace.timeline_builder.mapping import event_techniques, har_finding_techniques, tags
from oktatrace.timeline_builder.models import (
    EvidenceRef,
    MitreSummaryRow,
    PivotSummary,
    TimelineEntry,
    TimelineResult,
    TimelineScope,
)

_KIND_ORDER = {"har_capture": 0, "har_finding": 1, "event": 2, "inference": 3, "alert": 4}
_NEW_NETWORK_RULE = "OT-DET-001"


@dataclass(frozen=True)
class HarEvidence:
    """A HAR file's analysis and where it was found."""

    analysis: HarAnalysisResult
    case_id: str
    filename: str


def _most_severe(severities: Sequence[Severity]) -> Severity | None:
    return min(severities, key=lambda s: s.rank) if severities else None


def _stage(entry_tags: list) -> str | None:  # type: ignore[type-arg]
    return entry_tags[0].tactic if entry_tags else None


def _scope_alerts(
    alerts: Sequence[Alert], events: dict[str, SystemLogEvent], har: HarEvidence | None
) -> tuple[list[str], list[str], PivotSummary]:
    har_fingerprints = {f.fingerprint for f in har.analysis.findings if f.fingerprint} if har else set()
    seeds = [a for a in alerts if a.session_fingerprint in har_fingerprints]
    if not seeds:
        return [a.id for a in alerts], [], PivotSummary(
            matched_fingerprints=[], actors=[], attacker_asns=[],
            note="No alert matched a HAR fingerprint, so every alert is kept.",
        )
    actors = {a.actor for a in seeds}
    asns = {
        events[u].security_context.as_number
        for a in seeds if a.rule_id == _NEW_NETWORK_RULE
        for u in a.event_uuids if u in events
    }
    incident, excluded = [], []
    for alert in alerts:
        alert_asns = {events[u].security_context.as_number for u in alert.event_uuids if u in events}
        (incident if alert.actor in actors or alert_asns & asns else excluded).append(alert.id)
    pivots = PivotSummary(
        matched_fingerprints=sorted({a.session_fingerprint for a in seeds if a.session_fingerprint}),
        actors=sorted(actors),
        attacker_asns=sorted(asns),
        note=(
            "Seeded from alerts whose session fingerprint matches a secret in the HAR, then widened "
            "to alerts for the same actors or with suspicious events from the replay networks."
        ),
    )
    return incident, excluded, pivots


def _event_title(event: SystemLogEvent) -> str:
    title = event.display_message
    if event.target:
        title += f": {event.target[-1].alternate_id}"
    if event.outcome.result != "SUCCESS":
        title += f" ({event.outcome.result})"
    return title


def _event_entry(event: SystemLogEvent, flagging: list[Alert], context_alerts: list[str],
                 attacker_asns: set[int]) -> TimelineEntry:
    rules = {a.rule_id for a in flagging}
    on_attacker_network = event.security_context.as_number in attacker_asns
    entry_tags = tags(event_techniques(event, rules, on_attacker_network=on_attacker_network))
    agent = event.client.user_agent
    description = (
        f"{event.actor.alternate_id} from {describe_origin(event)} using {agent.browser} on {agent.os}; "
        f"outcome {event.outcome.result}"
        + (f" ({event.outcome.reason})" if event.outcome.reason else "") + "."
    )
    if rules == {"OT-DET-002"} and not on_attacker_network:
        description += " Not on the attacker's network: likely the genuine user's side of the travel pair."
    return TimelineEntry(
        id="",
        timestamp=event.published,
        kind="event",
        title=_event_title(event),
        description=description,
        actor=event.actor.alternate_id,
        source_ip=event.client.ip_address,
        session_fingerprint=fingerprint(event.session_id) if event.session_id else None,
        severity=_most_severe([a.severity for a in flagging]),
        suspicious=bool(flagging),
        stage=_stage(entry_tags),
        mitre=entry_tags,
        evidence=[EvidenceRef(type="event", ref=event.uuid)]
        + [EvidenceRef(type="alert", ref=a.id, note="flagged by") for a in flagging],
        related_alerts=list(dict.fromkeys([a.id for a in flagging] + context_alerts)),
        event_uuid=event.uuid,
    )


def _alert_entry(alert: Alert, events: dict[str, SystemLogEvent]) -> TimelineEntry:
    entry_tags = tags(alert.mitre_techniques)
    first = events.get(alert.event_uuids[0]) if alert.event_uuids else None
    return TimelineEntry(
        id="",
        timestamp=alert.first_seen,
        kind="alert",
        title=f"{alert.rule_id} {alert.rule_name}",
        description=alert.explanation,
        actor=alert.actor,
        source_ip=first.client.ip_address if first else None,
        session_fingerprint=alert.session_fingerprint,
        severity=alert.severity,
        suspicious=True,
        stage=_stage(entry_tags),
        mitre=entry_tags,
        evidence=[EvidenceRef(type="alert", ref=alert.id)]
        + [EvidenceRef(type="event", ref=u, note="flagged") for u in alert.event_uuids],
        related_alerts=[alert.id],
    )


def _har_entries(
    har: HarEvidence,
    alerts: Sequence[Alert],
    events: dict[str, SystemLogEvent],
    timeline_events: list[SystemLogEvent],
) -> list[TimelineEntry]:
    analysis = har.analysis
    stats = analysis.stats
    entries: list[TimelineEntry] = []
    if analysis.summary.first_request_at is not None:
        entries.append(TimelineEntry(
            id="",
            timestamp=analysis.summary.first_request_at,
            kind="har_capture",
            title=f"HAR captured: {har.filename}",
            description=(
                f"Browser capture of {analysis.summary.entry_count} requests containing "
                f"{stats.total_findings} secrets ({stats.by_severity.get(Severity.CRITICAL, 0)} critical, "
                f"{stats.by_severity.get(Severity.HIGH, 0)} high), later attached to support case {har.case_id}."
            ),
            severity=stats.overall_severity,
            suspicious=False,
            mitre=[],
            evidence=[EvidenceRef(type="har_file", ref=har.filename)]
            + [EvidenceRef(type="har_finding", ref=f.id, note=f.kind.value) for f in analysis.findings],
        ))

    flagged_uuids = {u for a in alerts for u in a.event_uuids}
    for finding in analysis.findings:
        if finding.fingerprint is None:
            continue
        linked = [a for a in alerts if a.session_fingerprint == finding.fingerprint]
        if finding.kind is FindingKind.DEVICE_TOKEN:
            carriers = [e for e in timeline_events if e.uuid in flagged_uuids
                        and e.debug_context.debug_data.get("dtHash", "")[:12] == finding.fingerprint]
            if not carriers:
                continue
            link = (f"Its SHA-256 matches the dtHash on {len(carriers)} flagged events from "
                    f"{', '.join(sorted({describe_origin(e) for e in carriers}))}: the device cookie was "
                    "replayed too, so cookie-based device trust would not have stopped the attacker.")
            linked = [a for a in alerts if set(a.event_uuids) & {e.uuid for e in carriers}]
        elif linked:
            link = f"Same fingerprint as the session in {', '.join(a.id for a in linked)}."
        else:
            continue
        entry_tags = tags(har_finding_techniques(finding.kind))
        entries.append(TimelineEntry(
            id="",
            timestamp=finding.occurrences[0].timestamp or analysis.summary.first_request_at,  # type: ignore[arg-type]
            kind="har_finding",
            title=f"{finding.id}: {finding.kind.value.replace('_', ' ')} '{finding.name}' exposed in HAR",
            description=f"Fingerprint {finding.fingerprint}, risk {finding.risk_score}/100. {link}",
            session_fingerprint=finding.fingerprint if finding.kind is not FindingKind.DEVICE_TOKEN else None,
            severity=finding.severity,
            suspicious=True,
            stage=_stage(entry_tags),
            mitre=entry_tags,
            evidence=[EvidenceRef(type="har_finding", ref=finding.id), EvidenceRef(type="har_file", ref=har.filename)]
            + [EvidenceRef(type="alert", ref=a.id, note="reappears in") for a in linked],
            related_alerts=[a.id for a in linked],
        ))
        if finding.kind is not FindingKind.DEVICE_TOKEN:
            entries.append(_inference(finding, linked, har, timeline_events))
    return entries


def _inference(finding: Finding, linked: list[Alert], har: HarEvidence,
               timeline_events: list[SystemLogEvent]) -> TimelineEntry:
    downloads = [e for e in timeline_events if e.event_type == catalog.SUPPORT_ATTACHMENT_DOWNLOAD
                 and any(t.alternate_id == har.filename for t in e.target)]
    first_alert = min(linked, key=lambda a: a.first_seen)
    if downloads:
        download = downloads[0]
        when = download.published
        how = (f"after {download.actor.alternate_id} downloaded the file at {when:%Y-%m-%d %H:%M:%S} UTC "
               f"from {describe_origin(download)}")
    else:
        download, when, how = None, first_alert.first_seen, "before the first replay"
    entry_tags = tags(["T1539"])
    evidence = [EvidenceRef(type="har_finding", ref=finding.id, note=f"fingerprint {finding.fingerprint}")]
    if download is not None:
        evidence.append(EvidenceRef(type="event", ref=download.uuid, note="HAR downloaded"))
    evidence += [EvidenceRef(type="alert", ref=a.id, note="session replayed") for a in linked]
    return TimelineEntry(
        id="",
        timestamp=when,
        kind="inference",
        title=f"'{finding.name}' cookie extracted from {har.filename} (inferred)",
        description=(
            f"No log records this step. The '{finding.name}' value in {har.filename} ({finding.id}, "
            f"fingerprint {finding.fingerprint}) is the session replayed in {first_alert.id}, so it must "
            f"have been extracted {how}."
        ),
        session_fingerprint=finding.fingerprint,
        severity=Severity.HIGH,
        suspicious=True,
        stage=_stage(entry_tags),
        mitre=entry_tags,
        evidence=evidence,
        related_alerts=[a.id for a in linked],
    )


def _mitre_summary(entries: list[TimelineEntry]) -> list[MitreSummaryRow]:
    counts: Counter[str] = Counter()
    first: dict[str, datetime] = {}
    names: dict[str, tuple[str, str]] = {}
    for entry in entries:
        for tag in entry.mitre:
            counts[tag.technique_id] += 1
            first.setdefault(tag.technique_id, entry.timestamp)
            names[tag.technique_id] = (tag.name, tag.tactic)
    return sorted(
        (MitreSummaryRow(technique_id=t, name=names[t][0], tactic=names[t][1], entries=counts[t],
                         first_seen=first[t]) for t in counts),
        key=lambda row: (row.first_seen, row.technique_id),
    )


def build_timeline(
    events: Sequence[SystemLogEvent],
    alerts: Sequence[Alert],
    har: HarEvidence | None = None,
    scope: TimelineScope = "incident",
) -> TimelineResult:
    """Build the ordered, ATT&CK-tagged timeline.

    Args:
        events: All System Log events (only referenced ones end up in the timeline).
        alerts: Alerts from the detection engine.
        har: The HAR evidence for the case, if available.
        scope: ``"incident"`` keeps alerts linked to the HAR evidence;
            ``"all_alerts"`` keeps every alert.
    """
    by_uuid = {e.uuid: e for e in events}
    incident, excluded, pivots = _scope_alerts(alerts, by_uuid, har)
    chosen = [a for a in alerts if scope == "all_alerts" or a.id in incident]

    flagging: dict[str, list[Alert]] = {}
    context_of: dict[str, list[str]] = {}
    for alert in chosen:
        for uuid in alert.event_uuids:
            flagging.setdefault(uuid, []).append(alert)
        for uuid in alert.context_event_uuids:
            context_of.setdefault(uuid, []).append(alert.id)
    wanted = set(flagging) | set(context_of)
    if har is not None:
        wanted |= {
            e.uuid for e in events
            if any(t.alternate_id == har.filename for t in e.target)
            or (e.event_type == catalog.SUPPORT_CASE_CREATE and any(t.id == har.case_id for t in e.target))
        }
    timeline_events = sorted((by_uuid[u] for u in wanted if u in by_uuid), key=lambda e: (e.published, e.uuid))

    attacker_asns = set(pivots.attacker_asns)
    entries = [_event_entry(e, flagging.get(e.uuid, []), context_of.get(e.uuid, []), attacker_asns)
               for e in timeline_events]
    entries += [_alert_entry(a, by_uuid) for a in chosen]
    if har is not None:
        entries += _har_entries(har, chosen, by_uuid, timeline_events)

    entries.sort(key=lambda e: (e.timestamp, _KIND_ORDER[e.kind], e.event_uuid or e.title))
    numbered = [e.model_copy(update={"id": f"TL-{i:04d}"}) for i, e in enumerate(entries, start=1)]
    return TimelineResult(
        scope=scope,
        entries=numbered,
        incident_alerts=incident,
        excluded_alerts=excluded,
        pivots=pivots,
        mitre_summary=_mitre_summary(numbered),
        first_timestamp=numbered[0].timestamp if numbered else None,
        last_timestamp=numbered[-1].timestamp if numbered else None,
    )
