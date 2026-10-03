"""Pre-computed indexes shared by all rules during one engine run."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import timedelta

from oktatrace.common.masking import fingerprint
from oktatrace.detection_engine.models import DetectionConfig
from oktatrace.log_generator.models import DirectoryEntry, SystemLogEvent
from oktatrace.scenario import ORG_UTC_OFFSET_HOURS


@dataclass
class DetectionContext:
    """Events in chronological order plus per-session and per-actor views.

    Rules only ever receive this context, never ground-truth labels.
    """

    events: list[SystemLogEvent]
    config: DetectionConfig
    users: dict[str, DirectoryEntry]
    by_session: dict[str, list[SystemLogEvent]] = field(default_factory=dict)
    by_actor: dict[str, list[SystemLogEvent]] = field(default_factory=dict)

    def utc_offset_hours(self, login: str) -> int:
        """The actor's home UTC offset, falling back to the organisation's."""
        user = self.users.get(login)
        return user.utc_offset_hours if user is not None else ORG_UTC_OFFSET_HOURS


def build_context(
    events: Iterable[SystemLogEvent], users: Sequence[DirectoryEntry], config: DetectionConfig
) -> DetectionContext:
    """Sort events and build lookup tables."""
    ordered = sorted(events, key=lambda e: (e.published, e.uuid))
    context = DetectionContext(events=ordered, config=config, users={u.login: u for u in users})
    for event in ordered:
        context.by_actor.setdefault(event.actor.alternate_id, []).append(event)
        if event.session_id:
            context.by_session.setdefault(event.session_id, []).append(event)
    return context


def describe_origin(event: SystemLogEvent) -> str:
    """Human-readable network location, e.g. ``192.0.2.11 (AS64512 Acme Synthetic Corp, San Francisco)``."""
    sec = event.security_context
    return f"{event.client.ip_address} (AS{sec.as_number} {sec.isp}, {event.client.geographical_context.city})"


def session_label(session_id: str | None) -> str:
    """Refer to a session by fingerprint so explanations never contain a replayable ID."""
    return f"session {fingerprint(session_id)}" if session_id else "an unknown session"


def format_delta(delta: timedelta) -> str:
    """Compact duration such as ``5m40s`` or ``16h21m``."""
    seconds = int(abs(delta.total_seconds()))
    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours}h{minutes:02d}m"
    if minutes:
        return f"{minutes}m{secs:02d}s"
    return f"{secs}s"
