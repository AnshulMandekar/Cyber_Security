"""Masking, fingerprinting and redaction-marker helpers.

Fingerprints are truncated SHA-256 digests. They let an analyst say "the token
in this HAR is the same one replayed in the logs" without ever displaying the
token. They are only published for high-entropy machine-generated secrets;
human-chosen passwords are never fingerprinted because an unsalted digest of a
short password can be brute-forced.
"""

from __future__ import annotations

import hashlib
import re
from typing import Final

FINGERPRINT_HEX_CHARS: Final = 12
_REDACTED_RE: Final = re.compile(r"\[REDACTED(?::[^\]\s]*)?\]")


def fingerprint(value: str) -> str:
    """Return a short, stable SHA-256 fingerprint of ``value``."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:FINGERPRINT_HEX_CHARS]


def redaction_marker(value: str, *, with_fingerprint: bool = True) -> str:
    """Return the placeholder that replaces ``value`` in a redacted artefact."""
    if not with_fingerprint:
        return "[REDACTED]"
    return f"[REDACTED:sha256={fingerprint(value)}]"


def is_redacted(value: str) -> bool:
    """True if ``value`` is already a redaction marker (so it must not be re-flagged)."""
    return bool(_REDACTED_RE.fullmatch(value.strip()))


def mask_preview(value: str, visible: int = 6) -> str:
    """Show just enough of a secret to recognise its type, never enough to reuse it."""
    if len(value) <= visible * 3:
        return "*" * 8
    return f"{value[:visible]}...({len(value)} chars)"
