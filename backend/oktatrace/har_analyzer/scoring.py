"""Deterministic, explainable risk scoring for HAR findings.

score = base score for the kind of secret + modifiers, clamped to 0..100.
Every point is recorded as a :class:`RiskFactor` so the UI and report can
explain exactly why a finding received its score.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Final

from oktatrace.har_analyzer.models import FindingKind, RiskFactor, Severity

BASE_SCORES: Final[dict[FindingKind, int]] = {
    FindingKind.PASSWORD: 90,
    FindingKind.API_TOKEN: 80,
    FindingKind.CLIENT_SECRET: 80,
    FindingKind.BASIC_CREDENTIALS: 75,
    FindingKind.REFRESH_TOKEN: 70,
    FindingKind.API_KEY: 70,
    FindingKind.SESSION_COOKIE: 60,
    FindingKind.SAML_ASSERTION: 55,
    FindingKind.ACCESS_TOKEN: 55,
    FindingKind.BEARER_TOKEN: 55,
    FindingKind.SESSION_TOKEN: 50,
    FindingKind.JWT: 45,
    FindingKind.ID_TOKEN: 40,
    FindingKind.DEVICE_TOKEN: 35,
    FindingKind.GENERIC_SECRET: 35,
    FindingKind.OAUTH_CODE: 25,
    FindingKind.CSRF_TOKEN: 15,
}

LONG_LIVED_BY_DESIGN: Final = frozenset(
    {
        FindingKind.API_TOKEN,  # Okta API tokens live until 30 days of inactivity
        FindingKind.REFRESH_TOKEN,
        FindingKind.CLIENT_SECRET,
        FindingKind.API_KEY,
    }
)

SEVERITY_THRESHOLDS: Final = ((80, Severity.CRITICAL), (60, Severity.HIGH), (35, Severity.MEDIUM))

POINTS_VALID_AT_CAPTURE: Final = 10
POINTS_EXPIRED: Final = -35
POINTS_LONG_LIVED: Final = 10
POINTS_IN_URL: Final = 10
POINTS_COOKIE_FLAG: Final = 5
POINTS_PRIVILEGED: Final = 10
POINTS_UNSIGNED: Final = 5


@dataclass(frozen=True)
class RiskContext:
    """Facts about a secret that feed into its score."""

    kind: FindingKind
    in_url: bool = False
    expires_at: datetime | None = None
    captured_at: datetime | None = None
    lifetime_seconds: int | None = None
    cookie_http_only: bool | None = None
    cookie_secure: bool | None = None
    privileged: bool = False
    unsigned_jwt: bool = False


@dataclass(frozen=True)
class RiskAssessment:
    """Score, severity and the factors that produced them."""

    score: int
    severity: Severity
    factors: tuple[RiskFactor, ...]
    long_lived: bool
    valid_at_capture: bool | None


def severity_for(score: int) -> Severity:
    """Map a 0-100 score onto a severity bucket."""
    for threshold, severity in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return severity
    return Severity.LOW


def format_duration(seconds: int) -> str:
    """Render a duration compactly, e.g. ``8h`` or ``30d``."""
    for unit_seconds, suffix in ((86400, "d"), (3600, "h"), (60, "m")):
        if seconds >= unit_seconds:
            return f"{round(seconds / unit_seconds)}{suffix}"
    return f"{seconds}s"


def assess_risk(context: RiskContext, *, long_lived_threshold_seconds: int) -> RiskAssessment:
    """Compute an explainable risk score for one secret."""
    kind_label = context.kind.value.replace("_", " ")
    factors = [RiskFactor(label=f"Base score for {kind_label}", points=BASE_SCORES[context.kind])]

    valid_at_capture: bool | None = None
    if context.expires_at is not None and context.captured_at is not None:
        valid_at_capture = context.expires_at > context.captured_at
        if valid_at_capture:
            factors.append(
                RiskFactor(
                    label="Still valid when the HAR was captured (replayable)",
                    points=POINTS_VALID_AT_CAPTURE,
                )
            )
        else:
            factors.append(
                RiskFactor(label="Already expired when the HAR was captured", points=POINTS_EXPIRED)
            )

    long_lived = False
    if (
        context.lifetime_seconds is not None
        and context.lifetime_seconds > long_lived_threshold_seconds
        and valid_at_capture is not False
    ):
        long_lived = True
        factors.append(
            RiskFactor(
                label=(
                    f"Long-lived: lifetime {format_duration(context.lifetime_seconds)} exceeds "
                    f"{format_duration(long_lived_threshold_seconds)}"
                ),
                points=POINTS_LONG_LIVED,
            )
        )
    elif context.kind in LONG_LIVED_BY_DESIGN:
        long_lived = True
        factors.append(
            RiskFactor(label="Long-lived by design (valid until revoked)", points=POINTS_LONG_LIVED)
        )

    if context.kind is FindingKind.SESSION_COOKIE and context.expires_at is None:
        factors.append(
            RiskFactor(
                label="Browser-session cookie: valid until the server-side session ends",
                points=0,
            )
        )
    if context.in_url:
        factors.append(
            RiskFactor(
                label="Exposed in a URL (leaks via logs, proxies and Referer headers)",
                points=POINTS_IN_URL,
            )
        )
    if context.cookie_http_only is False:
        factors.append(
            RiskFactor(label="Cookie set without HttpOnly (readable by scripts)", points=POINTS_COOKIE_FLAG)
        )
    if context.cookie_secure is False:
        factors.append(
            RiskFactor(
                label="Cookie set without Secure (may be sent over plain HTTP)",
                points=POINTS_COOKIE_FLAG,
            )
        )
    if context.privileged:
        factors.append(
            RiskFactor(label="Carries privileged scopes or admin group claims", points=POINTS_PRIVILEGED)
        )
    if context.unsigned_jwt:
        factors.append(RiskFactor(label="Unsigned JWT (alg=none)", points=POINTS_UNSIGNED))

    score = max(0, min(100, sum(f.points for f in factors)))
    return RiskAssessment(
        score=score,
        severity=severity_for(score),
        factors=tuple(factors),
        long_lived=long_lived,
        valid_at_capture=valid_at_capture,
    )
