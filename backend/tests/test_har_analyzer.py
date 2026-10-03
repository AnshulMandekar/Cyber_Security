"""Tests for the HAR analyzer, mostly against the synthetic sample HAR."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest

from oktatrace.common.masking import fingerprint
from oktatrace.har_analyzer import (
    Finding,
    FindingKind,
    HarAnalysisResult,
    HarParseError,
    Severity,
    analyze_har,
    load_har,
)
from oktatrace.har_analyzer.jwt_utils import encode_jwt
from oktatrace.har_analyzer.sample_har import make_sample_jwts
from oktatrace.scenario import make_scenario_tokens
from tests.conftest import EIGHT_HOURS
from tests.helpers import make_entry, make_har

TOKENS = make_scenario_tokens()
JWTS = make_sample_jwts()


def by_fingerprint(result: HarAnalysisResult, value: str) -> Finding:
    matches = [f for f in result.findings if f.fingerprint == fingerprint(value)]
    assert len(matches) == 1, f"expected exactly one finding for value, got {len(matches)}"
    return matches[0]


def factor_labels(finding: Finding) -> str:
    return " | ".join(f.label for f in finding.factors)


def test_sample_produces_every_expected_kind(sample_analysis: HarAnalysisResult) -> None:
    kinds = {f.kind for f in sample_analysis.findings}
    assert kinds == {
        FindingKind.PASSWORD,
        FindingKind.SESSION_TOKEN,
        FindingKind.DEVICE_TOKEN,
        FindingKind.SESSION_COOKIE,
        FindingKind.JWT,
        FindingKind.REFRESH_TOKEN,
        FindingKind.CLIENT_SECRET,
        FindingKind.ACCESS_TOKEN,
        FindingKind.ID_TOKEN,
        FindingKind.CSRF_TOKEN,
        FindingKind.API_TOKEN,
        FindingKind.BASIC_CREDENTIALS,
        FindingKind.OAUTH_CODE,
    }
    assert sample_analysis.stats.total_findings == 16


def test_password_is_critical_and_never_fingerprinted(sample_analysis: HarAnalysisResult) -> None:
    [password] = [f for f in sample_analysis.findings if f.kind is FindingKind.PASSWORD]
    assert password.severity is Severity.CRITICAL
    assert password.fingerprint is None
    assert password.value_preview == "********"
    assert password.occurrences[0].location == "request.body:password"


def test_replayable_sid_cookie_is_tracked_across_requests(sample_analysis: HarAnalysisResult) -> None:
    sid = by_fingerprint(sample_analysis, TOKENS.session_id)
    assert sid.kind is FindingKind.SESSION_COOKIE
    assert sid.severity is Severity.HIGH
    assert [o.entry_index for o in sid.occurrences] == [1, 2, 11]
    assert sid.occurrences[0].location == "response.set-cookie:sid"
    assert "Browser-session cookie" in factor_labels(sid)
    assert sid.expires_at is None


def test_bearer_header_merges_with_token_response(sample_analysis: HarAnalysisResult) -> None:
    access = by_fingerprint(sample_analysis, JWTS.access_token)
    assert access.kind is FindingKind.ACCESS_TOKEN
    assert {o.location for o in access.occurrences} == {
        "response.body:access_token",
        "request.header:Authorization",
    }
    assert access.jwt is not None
    assert access.jwt.algorithm == "RS256"
    assert "okta.users.manage" in access.jwt.scopes
    assert access.valid_at_capture is True
    assert access.lifetime_seconds == 3600
    assert "privileged" in factor_labels(access)
    assert access.risk_score == 75


def test_long_lived_jwt_in_url_and_referer_is_critical(sample_analysis: HarAnalysisResult) -> None:
    report = by_fingerprint(sample_analysis, JWTS.long_lived_report)
    assert report.severity is Severity.CRITICAL
    assert report.long_lived is True
    assert report.lifetime_seconds == 30 * 86400
    assert {o.location for o in report.occurrences} == {
        "request.query:access_token",
        "request.referer:access_token",
    }
    labels = factor_labels(report)
    assert "Exposed in a URL" in labels and "Long-lived" in labels


def test_expired_embedded_jwt_scores_low(sample_analysis: HarAnalysisResult) -> None:
    legacy = by_fingerprint(sample_analysis, JWTS.expired_legacy)
    assert legacy.kind is FindingKind.JWT
    assert legacy.severity is Severity.LOW
    assert legacy.valid_at_capture is False
    assert legacy.long_lived is False
    assert legacy.occurrences[0].location == "response.body:embedded JWT"


def test_cookie_without_httponly_and_secure_is_penalised(sample_analysis: HarAnalysisResult) -> None:
    jsession = by_fingerprint(sample_analysis, TOKENS.jsession_id)
    labels = factor_labels(jsession)
    assert "without HttpOnly" in labels and "without Secure" in labels
    assert jsession.long_lived is True
    assert jsession.severity is Severity.CRITICAL


def test_device_token_expiry_comes_from_set_cookie(sample_analysis: HarAnalysisResult) -> None:
    device = by_fingerprint(sample_analysis, TOKENS.device_token)
    assert device.kind is FindingKind.DEVICE_TOKEN
    assert device.lifetime_seconds == 5 * 365 * 86400
    assert device.long_lived is True


def test_api_token_is_long_lived_by_design(sample_analysis: HarAnalysisResult) -> None:
    api = by_fingerprint(sample_analysis, TOKENS.api_token)
    assert api.kind is FindingKind.API_TOKEN
    assert api.long_lived is True
    assert "Long-lived by design" in factor_labels(api)


def test_basic_credentials_reveal_username_only(sample_analysis: HarAnalysisResult) -> None:
    [basic] = [f for f in sample_analysis.findings if f.kind is FindingKind.BASIC_CREDENTIALS]
    assert basic.value_preview == "username=svc-wiki, password=********"
    assert basic.fingerprint is None


def test_session_token_in_url_and_oauth_code_in_redirect(sample_analysis: HarAnalysisResult) -> None:
    session_token = by_fingerprint(sample_analysis, TOKENS.session_token)
    assert "request.query:token" in {o.location for o in session_token.occurrences}
    assert "Exposed in a URL" in factor_labels(session_token)
    code = by_fingerprint(sample_analysis, TOKENS.auth_code)
    assert code.kind is FindingKind.OAUTH_CODE
    assert code.occurrences[0].location == "response.redirect:code"
    assert code.occurrence_count == 1  # Location header and redirectURL are the same sighting


def test_clean_entry_produces_no_findings(sample_analysis: HarAnalysisResult) -> None:
    seen_entries = {o.entry_index for f in sample_analysis.findings for o in f.occurrences}
    assert 9 not in seen_entries  # CDN font request: no secrets


def test_report_never_contains_raw_secrets(
    sample_analysis: HarAnalysisResult, sample_secrets: list[str]
) -> None:
    dumped = sample_analysis.model_dump_json()
    leaked = [s for s in sample_secrets if s in dumped]
    assert leaked == []


def test_findings_sorted_by_risk_with_sequential_ids(sample_analysis: HarAnalysisResult) -> None:
    scores = [f.risk_score for f in sample_analysis.findings]
    assert scores == sorted(scores, reverse=True)
    assert [f.id for f in sample_analysis.findings] == [
        f"HAR-{i:03d}" for i in range(1, len(scores) + 1)
    ]


def test_stats_and_summary(sample_analysis: HarAnalysisResult) -> None:
    stats, summary = sample_analysis.stats, sample_analysis.summary
    assert sum(stats.by_severity.values()) == stats.total_findings
    assert stats.overall_severity is Severity.CRITICAL
    assert stats.long_lived_count == sum(f.long_lived for f in sample_analysis.findings)
    assert summary.entry_count == 12
    assert "acme.idp.example" in summary.hosts
    assert summary.first_request_at is not None and summary.last_request_at is not None
    assert summary.first_request_at < summary.last_request_at


def test_analysis_is_deterministic(sample_har: dict[str, Any]) -> None:
    first = analyze_har(sample_har, long_lived_threshold_seconds=EIGHT_HOURS)
    second = analyze_har(sample_har, long_lived_threshold_seconds=EIGHT_HOURS)
    assert first.model_dump() == second.model_dump()


def test_threshold_controls_long_lived_flag(sample_har: dict[str, Any]) -> None:
    lenient = analyze_har(sample_har, long_lived_threshold_seconds=60 * 86400)
    report = by_fingerprint(lenient, JWTS.long_lived_report)
    assert report.long_lived is False


@pytest.mark.parametrize(
    "raw",
    [b"not json", b"[]", b'{"nolog": {}}', b'{"log": {"entries": {}}}', b"\xff\xfe\x00"],
)
def test_invalid_input_raises(raw: bytes) -> None:
    with pytest.raises(HarParseError):
        load_har(raw)


def test_load_har_accepts_path_and_bytes(tmp_path: Path, sample_har: dict[str, Any]) -> None:
    path = tmp_path / "x.har"
    path.write_text(json.dumps(sample_har), encoding="utf-8")
    assert load_har(path) == sample_har
    assert load_har(path.read_bytes()) == sample_har


def test_base64_encoded_body_is_scanned() -> None:
    body = base64.b64encode(json.dumps({"refresh_token": "rtSYNbase64Body123"}).encode()).decode()
    result = analyze_har(make_har(make_entry(response_text=body, response_encoding="base64")))
    assert [f.kind for f in result.findings] == [FindingKind.REFRESH_TOKEN]


def test_unsigned_jwt_is_flagged() -> None:
    token = encode_jwt({"alg": "none"}, {"sub": "x", "exp": 1700000000}, b"")
    result = analyze_har(make_har(make_entry(request_headers=[("Authorization", f"Bearer {token}")])))
    [finding] = result.findings
    assert finding.kind is FindingKind.BEARER_TOKEN
    assert "alg=none" in factor_labels(finding)
    assert finding.jwt is not None and finding.jwt.signature_present is False


def test_scheme_credential_pasted_in_text_body() -> None:
    body = "Steps to reproduce: curl -H 'Authorization: SSWS 00SYNpastedIntoTicket12345' https://x"
    result = analyze_har(make_har(make_entry(method="POST", post_text=body, post_mime="text/plain")))
    [finding] = result.findings
    assert finding.kind is FindingKind.API_TOKEN
    assert finding.occurrences[0].location == "request.body:SSWS"


def test_custom_api_key_header() -> None:
    result = analyze_har(make_har(make_entry(request_headers=[("X-API-Key", "Key123SYNabcdefg")])))
    [finding] = result.findings
    assert finding.kind is FindingKind.API_KEY
    assert finding.long_lived is True


def test_empty_har_has_no_findings() -> None:
    result = analyze_har(make_har())
    assert result.findings == []
    assert result.stats.overall_severity is None
    assert result.stats.max_risk_score == 0
