"""Shared constants for the synthetic breach scenario.

Every module (sample HAR, log generator, detections, mitigations) draws on the
same fictional organisation, victim and timeline, so the artefacts tell one
consistent story. All names are invented, all domains use the reserved
``.example`` TLD (RFC 2606) and all IPs come from documentation ranges (RFC 5737).

Story: an administrator at "Acme Synthetic Corp" captures a HAR file while
troubleshooting and attaches it to support case CASE-00421. An attacker who has
compromised the identity provider's support system (via a stolen service-account
credential) downloads the HAR, lifts the live session cookie and replays it.
"""

from __future__ import annotations

import random
import string
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Final

DEFAULT_SEED: Final = 20231020

ORG_NAME: Final = "Acme Synthetic Corp"
ORG_DOMAIN: Final = "acme.example"
VENDOR_DOMAIN: Final = "support.vendor.example"
IDP_HOST: Final = "acme.idp.example"
ADMIN_HOST: Final = "acme-admin.idp.example"
REPORTS_HOST: Final = "reports.acme.example"
CDN_HOST: Final = "cdn.acme.example"
WIKI_HOST: Final = "legacy-wiki.acme.example"
APP_HOST: Final = "app.acme.example"

SUPPORT_CASE_ID: Final = "CASE-00421"
SUPPORT_CASE_COUNT: Final = 480
HAR_CAPTURE_START: Final = datetime(2023, 10, 2, 14, 30, 0, tzinfo=timezone.utc)

# System-log window: Thu 28 Sep - Wed 4 Oct 2023 (UTC). The real intrusion window
# disclosed for the 2023 incident began on 28 September.
LOG_WINDOW_START: Final = datetime(2023, 9, 28, tzinfo=timezone.utc)
LOG_WINDOW_DAYS: Final = 7
LOG_WINDOW_END: Final = LOG_WINDOW_START + timedelta(days=LOG_WINDOW_DAYS)

# Acme's head office is in San Francisco. The whole window falls inside US daylight
# saving time, so fixed offsets are exact and no tz database is needed.
ORG_UTC_OFFSET_HOURS: Final = -7
ORG_TIMEZONE_LABEL: Final = "America/Los_Angeles (PDT, UTC-7)"

# Baseline (pre-mitigation) session policy for the fictional tenant.
BASELINE_SESSION_MAX_LIFETIME: Final = timedelta(hours=24)
BASELINE_SESSION_IDLE_TIMEOUT: Final = timedelta(hours=12)

SERVICE_ACCOUNT_LOGIN: Final = f"svc-case-sync@{VENDOR_DOMAIN}"

ALPHANUMERIC: Final = string.ascii_letters + string.digits


@dataclass(frozen=True)
class SyntheticUser:
    """A fabricated directory user."""

    user_id: str
    login: str
    display_name: str


VICTIM: Final = SyntheticUser(
    user_id="00uSYNv1ct1mAdm1n01",
    login="jordan.rivera@acme.example",
    display_name="Jordan Rivera",
)
VICTIM_USER_AGENT: Final = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36"
)


@dataclass(frozen=True)
class ScenarioTokens:
    """Fabricated secret values embedded in the sample HAR.

    The ``session_id`` is the ``sid`` cookie the attacker later replays in the
    synthetic system log. Values contain a ``SYN`` marker so they are obviously
    fake and can never be mistaken for real credentials.
    """

    session_id: str
    idx_session: str
    device_token: str
    session_token: str
    refresh_token: str
    api_token: str
    client_secret: str
    csrf_token: str
    jsession_id: str
    auth_code: str
    password: str
    wiki_password: str


def random_token(rng: random.Random, prefix: str, length: int) -> str:
    """Return ``prefix`` followed by ``length`` seeded alphanumeric characters."""
    return prefix + "".join(rng.choice(ALPHANUMERIC) for _ in range(length))


def make_scenario_tokens(seed: int = DEFAULT_SEED) -> ScenarioTokens:
    """Derive the scenario's fake secrets deterministically from ``seed``."""
    rng = random.Random(seed)
    return ScenarioTokens(
        session_id=random_token(rng, "102SYN", 22),
        idx_session=random_token(rng, "idxSYN", 30),
        device_token=random_token(rng, "dtSYN", 36),
        session_token=random_token(rng, "20111SYN", 40),
        refresh_token=random_token(rng, "rtSYN", 38),
        api_token=random_token(rng, "00SYN", 37),
        client_secret=random_token(rng, "csSYN", 35),
        csrf_token=random_token(rng, "xsrfSYN", 24),
        jsession_id=random_token(rng, "SYN", 29).upper(),
        auth_code=random_token(rng, "acSYN", 28),
        password="Synthetic-Passw0rd-NotReal!",
        wiki_password="Synthetic-Wiki-Pass-01",
    )
