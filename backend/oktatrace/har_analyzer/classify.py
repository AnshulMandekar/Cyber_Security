"""Name- and value-based rules that decide whether a HAR field holds a secret.

The analyzer and the redactor both call these functions, so anything the
analyzer reports is guaranteed to be masked by the redactor.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from typing import Final, Literal

from oktatrace.common.masking import is_redacted
from oktatrace.har_analyzer.jwt_utils import looks_like_jwt
from oktatrace.har_analyzer.models import FindingKind

ParamContext = Literal["url", "form", "json"]
"""Where a name/value pair came from; some rules only apply in some places."""

MIN_SECRET_LENGTH: Final = 8

LOW_ENTROPY_KINDS: Final = frozenset({FindingKind.PASSWORD, FindingKind.BASIC_CREDENTIALS})
"""Human-chosen secrets: shown fully masked and never fingerprinted."""

SESSION_COOKIE_NAMES: Final = frozenset(
    {
        "sid",  # Okta Classic session
        "idx",  # Okta Identity Engine session
        "jsessionid",
        "session",
        "sessionid",
        "session_id",
        "connect.sid",
        "phpsessid",
        "asp.net_sessionid",
        "_session_id",
    }
)
DEVICE_COOKIE_NAMES: Final = frozenset({"dt", "device_token", "devicetoken"})
CSRF_NAMES: Final = frozenset(
    {
        "xsrf-token",
        "x-xsrf-token",
        "xsrf_token",
        "csrftoken",
        "csrf_token",
        "csrf",
        "_csrf",
        "x-csrf-token",
        "x-csrftoken",
        "x-okta-xsrftoken",
        "authenticity_token",
    }
)
_SESSIONISH_COOKIE_RE: Final = re.compile(r"sess|sid|auth|token|jwt|bearer", re.IGNORECASE)
_BENIGN_COOKIE_RE: Final = re.compile(r"nonce|state|redirect|lang|locale|consent", re.IGNORECASE)

AUTH_HEADERS: Final = frozenset({"authorization", "proxy-authorization"})
API_KEY_HEADERS: Final = frozenset({"x-api-key", "api-key", "apikey", "x-auth-token", "x-access-token"})
SESSION_HEADERS: Final = frozenset({"x-okta-session-id", "x-session-token", "x-session-id"})
URL_HEADERS: Final = frozenset({"referer", "location", "content-location"})

_PARAM_KINDS: Final[dict[str, FindingKind]] = {
    "password": FindingKind.PASSWORD,
    "passwd": FindingKind.PASSWORD,
    "pwd": FindingKind.PASSWORD,
    "passcode": FindingKind.PASSWORD,
    "newpassword": FindingKind.PASSWORD,
    "otp": FindingKind.PASSWORD,
    "refresh_token": FindingKind.REFRESH_TOKEN,
    "refreshtoken": FindingKind.REFRESH_TOKEN,
    "access_token": FindingKind.ACCESS_TOKEN,
    "accesstoken": FindingKind.ACCESS_TOKEN,
    "id_token": FindingKind.ID_TOKEN,
    "idtoken": FindingKind.ID_TOKEN,
    "sessiontoken": FindingKind.SESSION_TOKEN,
    "session_token": FindingKind.SESSION_TOKEN,
    "statetoken": FindingKind.SESSION_TOKEN,
    "state_token": FindingKind.SESSION_TOKEN,
    "token": FindingKind.SESSION_TOKEN,  # Okta: /login/sessionCookieRedirect?token=<sessionToken>
    "sid": FindingKind.SESSION_TOKEN,
    "sessionid": FindingKind.SESSION_TOKEN,
    "client_secret": FindingKind.CLIENT_SECRET,
    "clientsecret": FindingKind.CLIENT_SECRET,
    "api_key": FindingKind.API_KEY,
    "apikey": FindingKind.API_KEY,
    "x-api-key": FindingKind.API_KEY,
    "code": FindingKind.OAUTH_CODE,
    "assertion": FindingKind.SAML_ASSERTION,
    "samlresponse": FindingKind.SAML_ASSERTION,
    **{name: FindingKind.CSRF_TOKEN for name in CSRF_NAMES},
}
_NON_SECRET_PARAMS: Final = frozenset(
    {
        "token_type",
        "tokentype",
        "token_type_hint",
        "expires_in",
        "expiresat",
        "expires_at",
        "grant_type",
        "response_type",
        "code_challenge",
        "code_challenge_method",
        "state",
        "nonce",
        "scope",
    }
)
_GENERIC_SECRET_NAME_RE: Final = re.compile(
    r"secret|passw|token|api[_-]?key|credential|private[_-]?key", re.IGNORECASE
)

SCHEME_CREDENTIAL_RE: Final = re.compile(r"\b(Bearer|SSWS|Basic)\s+([A-Za-z0-9._~+/=-]{8,})")
"""An HTTP auth scheme followed by a credential, e.g. inside a pasted curl command."""


@dataclass(frozen=True)
class AuthorizationSecret:
    """The secret part of an ``Authorization`` header value."""

    kind: FindingKind
    secret: str
    scheme: str
    username: str | None = None


def _normalise(name: str) -> str:
    return name.strip().lower()


def _looks_secret_like(value: str) -> bool:
    """Cheap entropy check: no whitespace, not a URL, mixes character classes."""
    if len(value) < MIN_SECRET_LENGTH or any(c.isspace() for c in value):
        return False
    if value.lower().startswith(("http://", "https://")):
        return False
    classes = sum(
        (
            any(c.islower() for c in value),
            any(c.isupper() for c in value),
            any(c.isdigit() for c in value),
        )
    )
    return classes >= 2


def classify_cookie(name: str, value: str) -> FindingKind | None:
    """Classify a cookie by name (and JWT-shaped value); ``None`` if not sensitive."""
    value = value.strip()
    if len(value) < MIN_SECRET_LENGTH or is_redacted(value):
        return None
    key = _normalise(name)
    if key in SESSION_COOKIE_NAMES:
        return FindingKind.SESSION_COOKIE
    if key in DEVICE_COOKIE_NAMES:
        return FindingKind.DEVICE_TOKEN
    if key in CSRF_NAMES:
        return FindingKind.CSRF_TOKEN
    if _BENIGN_COOKIE_RE.search(key):
        return None
    if _SESSIONISH_COOKIE_RE.search(key):
        return FindingKind.SESSION_COOKIE
    if looks_like_jwt(value):
        return FindingKind.JWT
    return None


def classify_header(name: str) -> FindingKind | None:
    """Classify a non-``Authorization`` header whose whole value is a secret."""
    key = _normalise(name)
    if key in API_KEY_HEADERS:
        return FindingKind.API_KEY
    if key in CSRF_NAMES:
        return FindingKind.CSRF_TOKEN
    if key in SESSION_HEADERS:
        return FindingKind.SESSION_TOKEN
    return None


def classify_param(name: str, value: object, *, context: ParamContext) -> FindingKind | None:
    """Classify a query/form/JSON name-value pair; ``None`` if not sensitive.

    Args:
        name: Parameter or JSON key name.
        value: Its value (non-strings are never secrets here).
        context: ``"url"``, ``"form"`` or ``"json"``. OAuth ``code`` is only
            considered in URLs and form bodies, because ``"code"`` in JSON is
            usually an error code.
    """
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or is_redacted(value):
        return None
    key = _normalise(name)
    if key in _NON_SECRET_PARAMS:
        return None
    kind = _PARAM_KINDS.get(key)
    if kind is FindingKind.OAUTH_CODE and context == "json":
        kind = None
    if kind is None and _GENERIC_SECRET_NAME_RE.search(key):
        kind = FindingKind.GENERIC_SECRET
    if kind in (None, FindingKind.GENERIC_SECRET) and looks_like_jwt(value):
        return FindingKind.JWT
    if kind is None:
        return None
    if kind is FindingKind.GENERIC_SECRET and not _looks_secret_like(value):
        return None
    if kind is not FindingKind.PASSWORD and len(value) < MIN_SECRET_LENGTH:
        return None
    return kind


def _basic_username(blob: str) -> str | None:
    """Extract the username from a Basic credential blob (the password is discarded)."""
    try:
        decoded = base64.b64decode(blob, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return None
    user, sep, _ = decoded.partition(":")
    return user if sep else None


def parse_authorization(value: str) -> AuthorizationSecret | None:
    """Split an ``Authorization`` header into scheme and secret and classify it."""
    text = value.strip()
    scheme, sep, credential = text.partition(" ")
    credential = credential.strip()
    if not sep:
        if len(text) < MIN_SECRET_LENGTH or is_redacted(text):
            return None
        kind = FindingKind.JWT if looks_like_jwt(text) else FindingKind.GENERIC_SECRET
        return AuthorizationSecret(kind=kind, secret=text, scheme="")
    if not credential or is_redacted(credential):
        return None
    lowered = scheme.lower()
    if lowered == "basic":
        return AuthorizationSecret(
            kind=FindingKind.BASIC_CREDENTIALS,
            secret=credential,
            scheme=scheme,
            username=_basic_username(credential),
        )
    kind = {
        "bearer": FindingKind.BEARER_TOKEN,
        "ssws": FindingKind.API_TOKEN,  # Okta API token scheme
    }.get(lowered, FindingKind.GENERIC_SECRET)
    return AuthorizationSecret(kind=kind, secret=credential, scheme=scheme)


def is_plausible_scheme_credential(scheme: str, credential: str) -> bool:
    """Filter prose like "Bearer authentication" out of free-text scheme matches."""
    if scheme.lower() == "basic":
        return _basic_username(credential) is not None
    return len(credential) >= 16 and (_looks_secret_like(credential) or looks_like_jwt(credential))


def find_scheme_credentials(text: str) -> list[AuthorizationSecret]:
    """Find ``Bearer``/``SSWS``/``Basic`` credentials embedded in free text."""
    found: list[AuthorizationSecret] = []
    for match in SCHEME_CREDENTIAL_RE.finditer(text):
        scheme, credential = match.group(1), match.group(2)
        if is_plausible_scheme_credential(scheme, credential):
            parsed = parse_authorization(f"{scheme} {credential}")
            if parsed is not None:
                found.append(parsed)
    return found
