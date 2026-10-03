"""Tests for HAR redaction."""

from __future__ import annotations

import base64
import copy
import json
from typing import Any
from urllib.parse import urlsplit

from oktatrace.har_analyzer import HarAnalysisResult, analyze_har, redact_har, redact_url
from oktatrace.har_analyzer.redactor import REDACTION_COMMENT
from tests.helpers import make_entry, make_har


def headers_of(entry: dict[str, Any], side: str) -> dict[str, str]:
    return {h["name"]: h["value"] for h in entry[side]["headers"]}


def test_redacted_har_contains_no_raw_secrets(
    sample_har: dict[str, Any], sample_secrets: list[str]
) -> None:
    dumped = json.dumps(redact_har(sample_har).har)
    assert [s for s in sample_secrets if s in dumped] == []


def test_reanalysing_redacted_har_finds_nothing(sample_har: dict[str, Any]) -> None:
    result = analyze_har(redact_har(sample_har).har)
    assert result.findings == []


def test_input_is_not_mutated(sample_har: dict[str, Any]) -> None:
    original = copy.deepcopy(sample_har)
    redact_har(sample_har)
    assert sample_har == original


def test_structure_and_benign_values_are_preserved(sample_har: dict[str, Any]) -> None:
    redacted = redact_har(sample_har).har
    before, after = sample_har["log"]["entries"], redacted["log"]["entries"]
    assert len(before) == len(after)
    for old, new in zip(before, after):
        assert old["request"]["method"] == new["request"]["method"]
        old_url, new_url = urlsplit(old["request"]["url"]), urlsplit(new["request"]["url"])
        assert (old_url.hostname, old_url.path) == (new_url.hostname, new_url.path)
        assert old["response"]["status"] == new["response"]["status"]
    token_params = {p["name"]: p["value"] for p in after[3]["request"]["postData"]["params"]}
    assert token_params["grant_type"] == "refresh_token"
    assert token_params["refresh_token"].startswith("[REDACTED:sha256=")
    assert headers_of(after[4], "request")["Accept"] == "application/json"


def test_markers_carry_fingerprints_matching_findings(
    sample_har: dict[str, Any], sample_analysis: HarAnalysisResult
) -> None:
    dumped = json.dumps(redact_har(sample_har).har)
    for finding in sample_analysis.findings:
        if finding.fingerprint is not None:
            assert f"[REDACTED:sha256={finding.fingerprint}]" in dumped, finding.id


def test_passwords_and_basic_credentials_get_bare_markers(sample_har: dict[str, Any]) -> None:
    entries = redact_har(sample_har).har["log"]["entries"]
    body = json.loads(entries[0]["request"]["postData"]["text"])
    assert body["password"] == "[REDACTED]"
    assert body["username"] == "jordan.rivera@acme.example"
    assert headers_of(entries[10], "request")["Authorization"] == "Basic [REDACTED]"


def test_cookie_names_kept_and_set_cookie_attributes_preserved(sample_har: dict[str, Any]) -> None:
    entries = redact_har(sample_har).har["log"]["entries"]
    cookie_header = headers_of(entries[2], "request")["Cookie"]
    assert [part.split("=", 1)[0] for part in cookie_header.split("; ")] == [
        "sid", "idx", "DT", "lang", "_ga",
    ]
    assert "102SYN" not in cookie_header
    set_cookie = next(h["value"] for h in entries[5]["response"]["headers"] if h["name"] == "Set-Cookie")
    assert set_cookie.startswith("JSESSIONID=[REDACTED:sha256=")
    assert "Max-Age=2592000" in set_cookie


def test_redaction_comment_and_counts(sample_har: dict[str, Any]) -> None:
    result = redact_har(sample_har)
    assert REDACTION_COMMENT in result.har["log"]["comment"]
    assert result.redaction_count == sum(result.by_area.values()) > 0
    assert result.by_area["request.cookie"] > 0


def test_base64_body_is_redacted_and_reencoded() -> None:
    body = base64.b64encode(json.dumps({"refresh_token": "rtSYNbase64Body123"}).encode()).decode()
    har = make_har(make_entry(response_text=body, response_encoding="base64"))
    content = redact_har(har).har["log"]["entries"][0]["response"]["content"]
    decoded = json.loads(base64.b64decode(content["text"]))
    assert decoded["refresh_token"].startswith("[REDACTED:sha256=")


def test_custom_fields_are_swept() -> None:
    entry = make_entry()
    entry["_initiator"] = {"note": "Authorization: SSWS 00SYNhiddenInCustomField99"}
    redacted = redact_har(make_har(entry)).har
    assert "00SYNhiddenInCustomField99" not in json.dumps(redacted)


def test_redact_url_masks_only_sensitive_params() -> None:
    url = "https://x.example/cb?code=acSYNabcdefgh123&state=xyz&redirectUrl=https://y.example/home"
    masked = redact_url(url)
    assert "acSYNabcdefgh123" not in masked
    assert "state=xyz" in masked
    assert "redirectUrl=https://y.example/home" in masked
    assert redact_url("https://x.example/plain?page=2") == "https://x.example/plain?page=2"
