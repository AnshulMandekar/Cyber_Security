"""A small scripting helper that emits the events of one session."""

from __future__ import annotations

import random
from collections.abc import Sequence
from datetime import date, datetime, time, timedelta, timezone

from oktatrace.log_generator import catalog
from oktatrace.log_generator.builder import (
    EventFactory,
    Recorder,
    app_target,
    attachment_target,
    case_target,
)
from oktatrace.log_generator.catalog import App, Place
from oktatrace.log_generator.directory import DirectoryUser, Endpoint
from oktatrace.log_generator.models import EventLabel, Outcome, SystemLogEvent, Target
from oktatrace.scenario import LOG_WINDOW_DAYS, LOG_WINDOW_START, SUPPORT_CASE_COUNT

ATTACHMENT_NAMES = ("screenshot.png", "browser.har", "logs.zip", "config.txt")


def window_dates() -> list[date]:
    """Calendar dates covered by the log window."""
    first = LOG_WINDOW_START.date()
    return [first + timedelta(days=i) for i in range(LOG_WINDOW_DAYS)]


def local_time(day: date, hours: float, place: Place) -> datetime:
    """UTC instant of ``hours`` after local midnight on ``day`` at ``place``."""
    midnight_utc = datetime.combine(day, time(), tzinfo=timezone.utc)
    return midnight_utc + timedelta(hours=hours - place.utc_offset_hours)


def random_case(rng: random.Random) -> str:
    return catalog.case_id(rng.randint(1, SUPPORT_CASE_COUNT))


class SessionScript:
    """Emits the events of one session for one user, all with the same label.

    ``endpoint`` may be reassigned mid-session to model a network or browser
    change on an existing session.
    """

    def __init__(
        self,
        factory: EventFactory,
        recorder: Recorder,
        user: DirectoryUser,
        endpoint: Endpoint,
        label: EventLabel,
        session_id: str | None = None,
    ) -> None:
        self.factory = factory
        self.recorder = recorder
        self.user = user
        self.endpoint = endpoint
        self.label = label
        self.session_id = session_id or factory.new_session_id()

    def emit(
        self,
        when: datetime,
        event_type: str,
        *,
        targets: Sequence[Target] = (),
        outcome: Outcome = "SUCCESS",
        reason: str | None = None,
        credential_type: str | None = None,
        request_uri: str | None = None,
        session_id: str | None = "",
        label: EventLabel | None = None,
    ) -> SystemLogEvent:
        """Record one event; ``session_id=""`` means "this session"."""
        event = self.factory.event(
            when=when,
            event_type=event_type,
            user=self.user,
            endpoint=self.endpoint,
            session_id=self.session_id if session_id == "" else session_id,
            outcome=outcome,
            reason=reason,
            targets=targets,
            credential_type=credential_type,
            request_uri=request_uri,
        )
        return self.recorder.add(event, label or self.label)

    # -- authentication ------------------------------------------------------
    def failed_login(self, when: datetime) -> SystemLogEvent:
        return self.emit(when, catalog.SESSION_START, outcome="FAILURE",
                         reason="INVALID_CREDENTIALS", credential_type="PASSWORD", session_id=None)

    def login(self, when: datetime, *, mfa: bool = True, credential_type: str = "PASSWORD") -> None:
        """Session start, optionally followed by an Okta Verify push a few seconds later."""
        self.emit(when, catalog.SESSION_START, credential_type=credential_type)
        if mfa:
            self.mfa(when + timedelta(seconds=self.factory.rng.uniform(3, 20)))

    def mfa(self, when: datetime, outcome: Outcome = "SUCCESS") -> SystemLogEvent:
        reason = None if outcome == "SUCCESS" else "INVALID_CREDENTIALS"
        return self.emit(when, catalog.MFA_VERIFY, outcome=outcome, reason=reason,
                         credential_type="OKTA_VERIFY_PUSH")

    def logout(self, when: datetime) -> SystemLogEvent:
        return self.emit(when, catalog.SESSION_END)

    # -- activity ------------------------------------------------------------
    def sso(self, when: datetime, app: App) -> SystemLogEvent:
        return self.emit(when, catalog.APP_SSO, targets=[app_target(app)],
                         request_uri=f"/app/{app.slug}/{app.app_id}/sso/saml")

    def case_view(self, when: datetime, case: str) -> SystemLogEvent:
        return self.emit(when, catalog.SUPPORT_CASE_VIEW, targets=[case_target(case)],
                         request_uri=f"/support/cases/{case}")

    def case_create(self, when: datetime, case: str) -> SystemLogEvent:
        return self.emit(when, catalog.SUPPORT_CASE_CREATE, targets=[case_target(case)])

    def attachment(self, when: datetime, case: str, filename: str, *, upload: bool) -> SystemLogEvent:
        event_type = catalog.SUPPORT_ATTACHMENT_UPLOAD if upload else catalog.SUPPORT_ATTACHMENT_DOWNLOAD
        uri = f"/support/cases/{case}/attachments" + ("" if upload else f"/{filename}")
        return self.emit(when, event_type, targets=[case_target(case), attachment_target(case, filename)],
                         request_uri=uri)

    def admin(
        self,
        when: datetime,
        event_type: str,
        targets: Sequence[Target],
        *,
        outcome: Outcome = "SUCCESS",
        reason: str | None = None,
    ) -> SystemLogEvent:
        return self.emit(when, event_type, targets=targets, outcome=outcome, reason=reason)
