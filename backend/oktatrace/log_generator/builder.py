"""Construct individual System Log events and collect them with their labels."""

from __future__ import annotations

import random
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime

from oktatrace.log_generator import catalog
from oktatrace.log_generator.catalog import App
from oktatrace.log_generator.directory import DirectoryUser, Endpoint
from oktatrace.log_generator.models import (
    AuthenticationContext,
    Client,
    DebugContext,
    EventLabel,
    EventOutcome,
    GeographicalContext,
    Geolocation,
    Outcome,
    SecurityContext,
    SystemLogEvent,
    Target,
    Transaction,
    UserAgent,
)
from oktatrace.scenario import random_token


def app_target(app: App) -> Target:
    return Target(id=app.app_id, type="AppInstance", alternate_id=app.label, display_name=app.label)


def user_target(user_id: str, login: str, display_name: str) -> Target:
    return Target(id=user_id, type="User", alternate_id=login, display_name=display_name)


def group_target(name: str) -> Target:
    group_id = "00gSYN" + "".join(c for c in name if c.isalnum())[:12]
    return Target(id=group_id, type="UserGroup", alternate_id=name, display_name=name)


def case_target(case: str) -> Target:
    return Target(id=case, type="SupportCase", alternate_id=case, display_name=f"Support case {case}")


def attachment_target(case: str, filename: str) -> Target:
    return Target(id=f"{case}/{filename}", type="Attachment", alternate_id=filename, display_name=filename)


class EventFactory:
    """Creates events with seeded UUIDs, transaction IDs and request IDs."""

    def __init__(self, rng: random.Random) -> None:
        self.rng = rng

    def new_session_id(self) -> str:
        return random_token(self.rng, "102SYN", 22)

    def event(
        self,
        *,
        when: datetime,
        event_type: str,
        user: DirectoryUser,
        endpoint: Endpoint,
        session_id: str | None,
        outcome: Outcome = "SUCCESS",
        reason: str | None = None,
        targets: Sequence[Target] = (),
        credential_type: str | None = None,
        request_uri: str | None = None,
    ) -> SystemLogEvent:
        """Build one event for ``user`` acting from ``endpoint`` at ``when``."""
        place = endpoint.network.place
        debug = {
            "requestId": random_token(self.rng, "req", 20),
            "requestUri": request_uri or catalog.REQUEST_URIS.get(event_type, "/"),
        }
        if endpoint.dt_hash:
            debug["dtHash"] = endpoint.dt_hash
        return SystemLogEvent(
            uuid=str(uuid.UUID(int=self.rng.getrandbits(128), version=4)),
            published=when.replace(microsecond=when.microsecond // 1000 * 1000),  # Okta logs ms
            event_type=event_type,
            severity="INFO" if outcome == "SUCCESS" else "WARN",
            display_message=catalog.DISPLAY_MESSAGES[event_type],
            actor=user.actor,
            client=Client(
                user_agent=UserAgent(
                    raw_user_agent=endpoint.user_agent.raw,
                    os=endpoint.user_agent.os,
                    browser=endpoint.user_agent.browser,
                ),
                device=endpoint.user_agent.device,
                ip_address=endpoint.ip_address,
                geographical_context=GeographicalContext(
                    city=place.city,
                    state=place.state,
                    country=place.country,
                    geolocation=Geolocation(lat=place.lat, lon=place.lon),
                ),
            ),
            authentication_context=AuthenticationContext(
                credential_type=credential_type, external_session_id=session_id
            ),
            security_context=SecurityContext(
                as_number=endpoint.network.as_number,
                as_org=endpoint.network.as_org,
                isp=endpoint.network.isp,
                domain=endpoint.network.domain,
                is_proxy=endpoint.network.is_proxy,
            ),
            outcome=EventOutcome(result=outcome, reason=reason),
            target=list(targets),
            transaction=Transaction(id=random_token(self.rng, "W", 23)),
            debug_context=DebugContext(debug_data=debug),
        )


@dataclass
class Recorder:
    """Collects events together with their ground-truth labels."""

    events: list[SystemLogEvent] = field(default_factory=list)
    labels: dict[str, EventLabel] = field(default_factory=dict)

    def add(self, event: SystemLogEvent, label: EventLabel) -> SystemLogEvent:
        self.events.append(event)
        self.labels[event.uuid] = label
        return event
