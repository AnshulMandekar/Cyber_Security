"""Cookie header parsing (``Cookie`` and ``Set-Cookie``)."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from oktatrace.common.timeutil import parse_http_date, parse_iso8601


def _merge_flag(first: bool | None, second: bool | None) -> bool | None:
    if first is None:
        return second
    if second is None:
        return first
    return first or second


@dataclass(frozen=True)
class CookieAttributes:
    """Security-relevant ``Set-Cookie`` attributes. ``None`` means "not observed"."""

    expires: datetime | None = None
    max_age: int | None = None
    http_only: bool | None = None
    secure: bool | None = None
    same_site: str | None = None

    def expiry_from(self, issued_at: datetime | None) -> datetime | None:
        """Absolute expiry; ``Max-Age`` wins over ``Expires`` (RFC 6265 section 5.3)."""
        if self.max_age is not None and issued_at is not None:
            return issued_at + timedelta(seconds=self.max_age)
        return self.expires

    def merged_with(self, other: CookieAttributes) -> CookieAttributes:
        """Combine attributes seen for the same cookie in the header and in ``response.cookies``."""
        return CookieAttributes(
            expires=self.expires or other.expires,
            max_age=self.max_age if self.max_age is not None else other.max_age,
            http_only=_merge_flag(self.http_only, other.http_only),
            secure=_merge_flag(self.secure, other.secure),
            same_site=self.same_site or other.same_site,
        )


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return value[1:-1]
    return value


def parse_cookie_header(value: str) -> list[tuple[str, str]]:
    """Parse a request ``Cookie: a=1; b=2`` header into ``(name, value)`` pairs."""
    pairs: list[tuple[str, str]] = []
    for part in value.split(";"):
        name, sep, cookie_value = part.strip().partition("=")
        if sep and name.strip():
            pairs.append((name.strip(), _unquote(cookie_value)))
    return pairs


def parse_set_cookie(line: str) -> tuple[str, str, CookieAttributes] | None:
    """Parse one ``Set-Cookie`` line. Flags absent from the header are recorded as ``False``."""
    segments = line.split(";")
    name, sep, value = segments[0].strip().partition("=")
    if not sep or not name.strip():
        return None
    expires: datetime | None = None
    max_age: int | None = None
    same_site: str | None = None
    http_only = secure = False
    for segment in segments[1:]:
        key, _, attr_value = segment.strip().partition("=")
        key, attr_value = key.strip().lower(), attr_value.strip()
        if key == "expires":
            expires = parse_http_date(attr_value)
        elif key == "max-age":
            try:
                max_age = int(attr_value)
            except ValueError:
                pass
        elif key == "httponly":
            http_only = True
        elif key == "secure":
            secure = True
        elif key == "samesite":
            same_site = attr_value or None
    attributes = CookieAttributes(
        expires=expires, max_age=max_age, http_only=http_only, secure=secure, same_site=same_site
    )
    return name.strip(), _unquote(value), attributes


def attributes_from_har_cookie(cookie: Mapping[str, Any]) -> CookieAttributes:
    """Read attributes from a HAR ``response.cookies[]`` object."""

    def optional_bool(raw: object) -> bool | None:
        return raw if isinstance(raw, bool) else None

    same_site = cookie.get("sameSite")
    return CookieAttributes(
        expires=parse_iso8601(cookie.get("expires")),
        http_only=optional_bool(cookie.get("httpOnly")),
        secure=optional_bool(cookie.get("secure")),
        same_site=same_site if isinstance(same_site, str) else None,
    )
