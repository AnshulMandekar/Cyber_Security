"""Decode-only JWT helpers.

Signatures are deliberately NOT verified. A forensic analyst reviewing leaked
artefacts needs to read claims (issuer, subject, scopes, expiry) but has no key
and no business validating or re-using the token. Never use these helpers to
make authentication decisions.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final

from oktatrace.common.timeutil import from_epoch

JWT_PATTERN: Final = re.compile(
    r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*"
)
"""Compact-serialised JWS: base64url(JSON header).base64url(JSON payload).signature."""


@dataclass(frozen=True)
class DecodedJwt:
    """Header and payload of a JWT whose signature has not been checked."""

    header: dict[str, Any]
    payload: dict[str, Any]
    signature_present: bool

    @property
    def algorithm(self) -> str | None:
        """The ``alg`` header value, if it is a string."""
        alg = self.header.get("alg")
        return alg if isinstance(alg, str) else None

    def claim_time(self, claim: str) -> datetime | None:
        """Return a NumericDate claim such as ``exp`` as a UTC datetime."""
        return from_epoch(self.payload.get(claim))


def b64url_decode(segment: str) -> bytes:
    """Decode unpadded base64url."""
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def b64url_encode(data: bytes) -> str:
    """Encode bytes as unpadded base64url."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def decode_jwt_unverified(token: str) -> DecodedJwt | None:
    """Decode a JWT's header and payload WITHOUT verifying it; ``None`` if not a JWT."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
    except ValueError:  # covers binascii.Error, JSONDecodeError and UnicodeDecodeError
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return DecodedJwt(header=header, payload=payload, signature_present=bool(parts[2]))


def looks_like_jwt(value: str) -> bool:
    """True if ``value`` is exactly one decodable JWT."""
    return bool(JWT_PATTERN.fullmatch(value.strip())) and decode_jwt_unverified(value) is not None


def find_jwts(text: str) -> list[str]:
    """Return each distinct decodable JWT embedded anywhere in ``text``, in order."""
    found: list[str] = []
    for match in JWT_PATTERN.finditer(text):
        token = match.group(0)
        if token not in found and decode_jwt_unverified(token) is not None:
            found.append(token)
    return found


def encode_jwt(header: dict[str, Any], payload: dict[str, Any], signature: bytes) -> str:
    """Assemble a compact JWT from parts. Used only to fabricate synthetic samples."""
    return ".".join(
        (
            b64url_encode(json.dumps(header, separators=(",", ":")).encode()),
            b64url_encode(json.dumps(payload, separators=(",", ":")).encode()),
            b64url_encode(signature),
        )
    )
