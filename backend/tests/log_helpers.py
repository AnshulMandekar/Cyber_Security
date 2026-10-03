"""Builders for small hand-made System Log events used in rule tests."""

from __future__ import annotations

import itertools
from datetime import datetime, timedelta, timezone

from oktatrace.log_generator.models import (
    Actor,
    AuthenticationContext,
    Client,
    DebugContext,
    DirectoryEntry,
    EventOutcome,
    GeographicalContext,
    Geolocation,
    SecurityContext,
    SystemLogEvent,
    Target,
    Transaction,
    UserAgent,
)

T0 = datetime(2023, 10, 3, 17, 0, tzinfo=timezone.utc)  # a Tuesday, 10:00 in San Francisco

SF = ("San Francisco", 37.7749, -122.4194)
OAKLAND = ("Oakland", 37.8044, -122.2712)
NYC = ("New York", 40.7128, -74.0060)
FRANKFURT = ("Frankfurt am Main", 50.1109, 8.6821)

CORP = ("192.0.2.10", 64512, "Acme Synthetic Corp")
CORP_NAT = ("192.0.2.12", 64512, "Acme Synthetic Corp")
HOME = ("198.51.100.20", 64600, "Bayline Broadband")
HOSTING = ("203.0.113.211", 65066, "Nightjar Hosting Ltd")
VENDOR = ("203.0.113.15", 64800, "Vendor Cloud DC")

MAC_CHROME = ("CHROME", "Mac OS X", "Mozilla/5.0 (Macintosh) Chrome/117.0.0.0")
MAC_CHROME_NEW = ("CHROME", "Mac OS X", "Mozilla/5.0 (Macintosh) Chrome/118.0.0.0")
WIN_FIREFOX = ("FIREFOX", "Windows 10", "Mozilla/5.0 (Windows NT 10.0) Firefox/118.0")

_ids = itertools.count(1)


def minutes(n: float) -> timedelta:
    return timedelta(minutes=n)


def log_event(
    when: datetime = T0,
    event_type: str = "user.authentication.sso",
    *,
    actor: str = "alice@acme.example",
    session: str | None = "S-ALICE",
    network: tuple[str, int, str] = CORP,
    place: tuple[str, float, float] = SF,
    agent: tuple[str, str, str] = MAC_CHROME,
    outcome: str = "SUCCESS",
    targets: tuple[Target, ...] = (),
) -> SystemLogEvent:
    """Build a minimal but valid event."""
    ip, asn, isp = network
    city, lat, lon = place
    browser, os_name, raw = agent
    return SystemLogEvent(
        uuid=f"evt-{next(_ids):05d}",
        published=when,
        event_type=event_type,
        severity="INFO" if outcome == "SUCCESS" else "WARN",
        display_message=event_type,
        actor=Actor(id=f"id-{actor}", alternate_id=actor, display_name=actor),
        client=Client(
            user_agent=UserAgent(raw_user_agent=raw, os=os_name, browser=browser),
            device="Computer",
            ip_address=ip,
            geographical_context=GeographicalContext(
                city=city, state="", country="", geolocation=Geolocation(lat=lat, lon=lon)
            ),
        ),
        authentication_context=AuthenticationContext(external_session_id=session),
        security_context=SecurityContext(as_number=asn, as_org=isp, isp=isp, domain="x.example"),
        outcome=EventOutcome(result=outcome),  # type: ignore[arg-type]
        target=list(targets),
        transaction=Transaction(id="t"),
        debug_context=DebugContext(debug_data={}),
    )


def case(case_id: str) -> Target:
    return Target(id=case_id, type="SupportCase", alternate_id=case_id, display_name=case_id)


def directory_entry(login: str, role: str = "employee", utc_offset_hours: int = -7) -> DirectoryEntry:
    return DirectoryEntry(
        user_id=f"id-{login}", login=login, display_name=login, role=role,  # type: ignore[arg-type]
        department="IT", city="San Francisco", utc_offset_hours=utc_offset_hours,
        network="corp-sf", ip_address=CORP[0], user_agent=MAC_CHROME[2],
    )
