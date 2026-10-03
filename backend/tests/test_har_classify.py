"""Tests for classification rules, cookie parsing and risk scoring."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

import pytest

from oktatrace.har_analyzer.classify import (
    classify_cookie,
    classify_header,
    classify_param,
    find_scheme_credentials,
    parse_authorization,
)
from oktatrace.har_analyzer.cookies import parse_cookie_header, parse_set_cookie
from oktatrace.har_analyzer.jwt_utils import encode_jwt
from oktatrace.har_analyzer.models import FindingKind, Severity
from oktatrace.har_analyzer.scoring import RiskContext, assess_risk, severity_for

JWT = encode_jwt({"alg": "HS256"}, {"sub": "someone"}, b"signature")
NOW = datetime(2023, 10, 2, 14, 30, tzinfo=timezone.utc)
EIGHT_HOURS = 8 * 3600


@pytest.mark.parametrize(
    ("name", "value", "expected"),
    [
        ("sid", "102SYNabcdefghijklmn", FindingKind.SESSION_COOKIE),
        ("IDX", "idxSYNabcdefghijklmn", FindingKind.SESSION_COOKIE),
        ("DT", "dtSYNabcdefghijklmnop", FindingKind.DEVICE_TOKEN),
        ("XSRF-TOKEN", "xsrfSYNabcdefgh", FindingKind.CSRF_TOKEN),
        ("my_auth_cookie", "Abc123456789", FindingKind.SESSION_COOKIE),
        ("prefs", JWT, FindingKind.JWT),
        ("okta-oauth-state", "Abc123456789", None),
        ("lang", "en-US-variant", None),
        ("sid", "short", None),
        ("sid", "[REDACTED:sha256=abc123]", None),
    ],
)
def test_classify_cookie(name: str, value: str, expected: FindingKind | None) -> None:
    assert classify_cookie(name, value) is expected


@pytest.mark.parametrize(
    ("name", "value", "context", "expected"),
    [
        ("password", "x", "json", FindingKind.PASSWORD),
        ("refresh_token", "rtSYN12345678", "form", FindingKind.REFRESH_TOKEN),
        ("sessionToken", "20111SYNabcdef", "json", FindingKind.SESSION_TOKEN),
        ("client_secret", "csSYN12345678", "form", FindingKind.CLIENT_SECRET),
        ("code", "acSYN12345678", "url", FindingKind.OAUTH_CODE),
        ("code", "E0000011", "json", None),  # error codes in JSON are not OAuth codes
        ("token_type", "Bearer", "json", None),
        ("token_endpoint", "https://idp.example/oauth2/v1/token", "json", None),
        ("token_endpoint_auth_method", "client_secret_basic", "json", None),
        ("legacyReportToken", JWT, "json", FindingKind.JWT),
        ("anything", JWT, "url", FindingKind.JWT),
        ("myApiSecret", "Zx9Kq2LmP0", "json", FindingKind.GENERIC_SECRET),
        ("access_token", "short", "url", None),
        ("access_token", 12345, "json", None),
        ("access_token", "[REDACTED:sha256=abc]", "url", None),
    ],
)
def test_classify_param(name: str, value: object, context: str, expected: FindingKind | None) -> None:
    assert classify_param(name, value, context=context) is expected  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("X-API-Key", FindingKind.API_KEY),
        ("X-Okta-XsrfToken", FindingKind.CSRF_TOKEN),
        ("X-Okta-Session-Id", FindingKind.SESSION_TOKEN),
        ("Accept", None),
    ],
)
def test_classify_header(name: str, expected: FindingKind | None) -> None:
    assert classify_header(name) is expected


def test_parse_authorization_schemes() -> None:
    bearer = parse_authorization(f"Bearer {JWT}")
    assert bearer is not None and bearer.kind is FindingKind.BEARER_TOKEN and bearer.secret == JWT

    ssws = parse_authorization("SSWS 00SYNabcdefghijklmnopqrstuvwxyz")
    assert ssws is not None and ssws.kind is FindingKind.API_TOKEN

    blob = base64.b64encode(b"svc-user:hunter2").decode()
    basic = parse_authorization(f"Basic {blob}")
    assert basic is not None and basic.kind is FindingKind.BASIC_CREDENTIALS
    assert basic.username == "svc-user"

    raw = parse_authorization(JWT)
    assert raw is not None and raw.kind is FindingKind.JWT

    custom = parse_authorization("Token abcdefghijklmnop")
    assert custom is not None and custom.kind is FindingKind.GENERIC_SECRET

    assert parse_authorization("Bearer [REDACTED:sha256=abc]") is None
    assert parse_authorization("Bearer ") is None


def test_find_scheme_credentials_ignores_prose() -> None:
    blob = base64.b64encode(b"svc:pw").decode()
    text = (
        "Bearer authentication is described in RFC 6750. Basic information follows. "
        f"curl -H 'Authorization: SSWS 00SYNabcdefghijklmnopqrstu1' -H 'Authorization: Basic {blob}'"
    )
    kinds = [c.kind for c in find_scheme_credentials(text)]
    assert kinds == [FindingKind.API_TOKEN, FindingKind.BASIC_CREDENTIALS]


def test_parse_cookie_header() -> None:
    assert parse_cookie_header('sid=abc; lang=en; quoted="v"; junk') == [
        ("sid", "abc"),
        ("lang", "en"),
        ("quoted", "v"),
    ]


def test_parse_set_cookie_attributes() -> None:
    parsed = parse_set_cookie(
        "sid=abc123; Path=/; Expires=Wed, 04 Oct 2023 14:30:00 GMT; Max-Age=3600; Secure; SameSite=Lax"
    )
    assert parsed is not None
    name, value, attrs = parsed
    assert (name, value) == ("sid", "abc123")
    assert attrs.secure is True and attrs.http_only is False and attrs.same_site == "Lax"
    assert attrs.max_age == 3600
    assert attrs.expiry_from(NOW) == NOW + timedelta(hours=1)  # Max-Age wins over Expires
    assert parse_set_cookie("garbage-without-equals") is None


@pytest.mark.parametrize(
    ("score", "expected"),
    [(100, Severity.CRITICAL), (80, Severity.CRITICAL), (79, Severity.HIGH), (60, Severity.HIGH),
     (59, Severity.MEDIUM), (35, Severity.MEDIUM), (34, Severity.LOW), (0, Severity.LOW)],
)
def test_severity_thresholds(score: int, expected: Severity) -> None:
    assert severity_for(score) is expected


def test_expired_token_is_discounted_and_not_long_lived() -> None:
    result = assess_risk(
        RiskContext(kind=FindingKind.JWT, expires_at=NOW - timedelta(days=1), captured_at=NOW,
                    lifetime_seconds=30 * 86400),
        long_lived_threshold_seconds=EIGHT_HOURS,
    )
    assert result.valid_at_capture is False
    assert result.long_lived is False
    assert result.score == 10
    assert any("expired" in f.label for f in result.factors)


def test_score_is_clamped_and_factors_add_up() -> None:
    result = assess_risk(
        RiskContext(kind=FindingKind.PASSWORD, in_url=True, privileged=True, unsigned_jwt=True),
        long_lived_threshold_seconds=EIGHT_HOURS,
    )
    assert result.score == 100
    assert sum(f.points for f in result.factors) > 100


def test_long_lived_by_design_without_expiry() -> None:
    result = assess_risk(RiskContext(kind=FindingKind.API_TOKEN), long_lived_threshold_seconds=EIGHT_HOURS)
    assert result.long_lived is True
    assert result.valid_at_capture is None
    assert result.score == 90
