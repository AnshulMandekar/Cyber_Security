"""Tests for decode-only JWT helpers."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from oktatrace.har_analyzer.jwt_utils import (
    b64url_encode,
    decode_jwt_unverified,
    encode_jwt,
    find_jwts,
    looks_like_jwt,
)

TOKEN = encode_jwt({"alg": "RS256", "kid": "k1"}, {"sub": "user", "exp": 1696258800}, b"sig-bytes")


def test_decode_roundtrip_reads_header_and_claims() -> None:
    decoded = decode_jwt_unverified(TOKEN)
    assert decoded is not None
    assert decoded.algorithm == "RS256"
    assert decoded.payload["sub"] == "user"
    assert decoded.signature_present is True
    assert decoded.claim_time("exp") == datetime(2023, 10, 2, 15, 0, tzinfo=timezone.utc)
    assert decoded.claim_time("iat") is None


def test_unsigned_token_has_no_signature() -> None:
    token = encode_jwt({"alg": "none"}, {"sub": "x"}, b"")
    decoded = decode_jwt_unverified(token)
    assert decoded is not None
    assert decoded.signature_present is False
    assert token.endswith(".")


@pytest.mark.parametrize(
    "value",
    [
        "not-a-jwt",
        "a.b.c",
        "eyJhbGciOiJIUzI1NiJ9.notbase64json.sig",
        b64url_encode(b"[1,2]") + "." + b64url_encode(b'{"a":1}') + ".sig",  # header not an object
    ],
)
def test_invalid_values_are_not_decoded(value: str) -> None:
    assert decode_jwt_unverified(value) is None
    assert looks_like_jwt(value) is False


def test_find_jwts_returns_distinct_tokens_in_order() -> None:
    other = encode_jwt({"alg": "HS256"}, {"sub": "other"}, b"s")
    text = f'var a="{TOKEN}"; var b="{other}"; var c="{TOKEN}";'
    assert find_jwts(text) == [TOKEN, other]


def test_find_jwts_ignores_undecodable_lookalikes() -> None:
    assert find_jwts("eyJxxxxx.eyJyyyyy.zzz") == []
