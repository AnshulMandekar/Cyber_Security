"""Timestamp parsing helpers that always return timezone-aware UTC datetimes."""

from __future__ import annotations

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime


def ensure_utc(value: datetime) -> datetime:
    """Return ``value`` as an aware UTC datetime (naive values are assumed UTC)."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def parse_iso8601(value: object) -> datetime | None:
    """Parse an ISO-8601 string such as HAR's ``startedDateTime``; ``None`` if invalid."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        return ensure_utc(datetime.fromisoformat(text))
    except ValueError:
        return None


def parse_http_date(value: object) -> datetime | None:
    """Parse an RFC 1123 date as used in ``Set-Cookie: Expires=``; ``None`` if invalid."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = parsedate_to_datetime(value.strip())
    except (TypeError, ValueError, IndexError):
        return None
    return ensure_utc(parsed) if parsed is not None else None


def from_epoch(value: object) -> datetime | None:
    """Convert a numeric epoch-seconds claim (``exp``, ``iat``) to UTC; ``None`` if invalid."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def isoformat_z(value: datetime) -> str:
    """Format a datetime as ISO-8601 UTC with a trailing ``Z``."""
    return ensure_utc(value).isoformat().replace("+00:00", "Z")
