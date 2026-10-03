"""Find session material and credentials in HAR files and score their risk.

Pipeline:

1. Each entry is scanned field by field (cookies, headers, query string, request
   body, Set-Cookie, redirects, response body) to produce *candidates*.
2. Candidates with the same value are grouped into one :class:`Finding`, so a
   session cookie sent in 14 requests is one finding with 14 occurrences.
3. Each finding gets a deterministic, explainable risk score.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final
from urllib.parse import parse_qsl, urlsplit

from oktatrace import DISCLAIMER
from oktatrace.common.masking import fingerprint, is_redacted, mask_preview
from oktatrace.common.timeutil import parse_iso8601
from oktatrace.config import get_settings
from oktatrace.har_analyzer.classify import (
    AUTH_HEADERS,
    LOW_ENTROPY_KINDS,
    ParamContext,
    classify_cookie,
    classify_header,
    classify_param,
    find_scheme_credentials,
    parse_authorization,
)
from oktatrace.har_analyzer.cookies import (
    CookieAttributes,
    attributes_from_har_cookie,
    parse_cookie_header,
    parse_set_cookie,
)
from oktatrace.har_analyzer.har_io import (
    decode_body,
    iter_json_strings,
    iter_name_values,
    load_har,
    try_parse_json,
)
from oktatrace.har_analyzer.jwt_utils import DecodedJwt, decode_jwt_unverified, find_jwts, looks_like_jwt
from oktatrace.har_analyzer.models import (
    Finding,
    FindingKind,
    HarAnalysisResult,
    HarStats,
    HarSummary,
    JwtSummary,
    Occurrence,
    Severity,
)
from oktatrace.har_analyzer.redactor import redact_url
from oktatrace.har_analyzer.scoring import BASE_SCORES, RiskContext, assess_risk, severity_for

EMBEDDED_JWT_NAME: Final = "embedded JWT"
_PRIVILEGE_CLAIMS: Final = ("scp", "scope", "groups", "roles", "role", "permissions")
_PRIVILEGE_HINTS: Final = ("admin", ".manage", "superuser")

RECOMMENDATIONS: Final[dict[FindingKind, str]] = {
    FindingKind.SESSION_COOKIE: (
        "Terminate the session server-side and treat all activity after the capture time as "
        "suspect. Strip cookies from HAR files before sharing them."
    ),
    FindingKind.DEVICE_TOKEN: (
        "Reset device trust for the user: a copied device token can make an attacker's browser "
        "look like a known device and weaken risk-based checks."
    ),
    FindingKind.BEARER_TOKEN: (
        "Revoke the token and shorten access-token lifetimes; prefer sender-constrained tokens "
        "(DPoP or mTLS) so a copied token cannot be replayed."
    ),
    FindingKind.ACCESS_TOKEN: (
        "Revoke the token and shorten access-token lifetimes; never pass tokens in URLs and "
        "prefer sender-constrained tokens (DPoP or mTLS)."
    ),
    FindingKind.ID_TOKEN: (
        "ID tokens describe a login and should not be used as API credentials; review the client "
        "and revoke the related session."
    ),
    FindingKind.REFRESH_TOKEN: (
        "Revoke the refresh token (and its grant) immediately and enable refresh-token rotation."
    ),
    FindingKind.SESSION_TOKEN: (
        "One-time session tokens must be exchanged immediately and never placed in URLs that can "
        "be logged; revoke the resulting session."
    ),
    FindingKind.API_TOKEN: (
        "Revoke the API token now. API tokens inherit the creating admin's privileges; replace it "
        "with a narrowly scoped OAuth service app."
    ),
    FindingKind.API_KEY: "Rotate the key and restrict it by scope and source network.",
    FindingKind.BASIC_CREDENTIALS: (
        "Rotate the account password and replace Basic authentication with token-based auth."
    ),
    FindingKind.PASSWORD: (
        "Force a password reset and check for reuse. HAR captures of login flows record "
        "passwords in clear text."
    ),
    FindingKind.CLIENT_SECRET: (
        "Rotate the client secret and move the client to private_key_jwt authentication."
    ),
    FindingKind.OAUTH_CODE: (
        "Authorization codes are single-use and short-lived; make sure PKCE is enforced so an "
        "intercepted code is useless."
    ),
    FindingKind.SAML_ASSERTION: (
        "Assertions can be replayed until NotOnOrAfter; confirm the service provider enforces "
        "one-time use."
    ),
    FindingKind.CSRF_TOKEN: (
        "Low risk on its own: it is bound to the session, so revoking the session invalidates it."
    ),
    FindingKind.JWT: "Identify the issuing system from the claims and revoke the token if still valid.",
    FindingKind.GENERIC_SECRET: "Confirm whether this value is a credential and rotate it if so.",
}


@dataclass(frozen=True)
class _EntryContext:
    index: int
    timestamp: datetime | None
    method: str
    url: str


@dataclass
class _Candidate:
    """One sighting of a possible secret in one place of one entry."""

    kind: FindingKind
    name: str
    value: str
    carrier: str
    entry: _EntryContext
    in_url: bool = False
    cookie: CookieAttributes | None = None
    username: str | None = None

    @property
    def location(self) -> str:
        return f"{self.carrier}:{self.name}"


class _EntryScanner:
    """Collects candidate secrets from one HAR entry, de-duplicating repeats.

    The same cookie often appears in both ``request.cookies`` and the ``Cookie``
    header; both map to the carrier ``request.cookie`` and collapse into one
    candidate.
    """

    def __init__(self, context: _EntryContext) -> None:
        self.context = context
        self._found: dict[tuple[str, str, str], _Candidate] = {}

    @property
    def candidates(self) -> list[_Candidate]:
        return list(self._found.values())

    def add(
        self,
        kind: FindingKind,
        name: str,
        value: str,
        carrier: str,
        *,
        in_url: bool = False,
        cookie: CookieAttributes | None = None,
        username: str | None = None,
    ) -> bool:
        value = value.strip()
        if not value or is_redacted(value):
            return False
        key = (carrier, name.lower(), value)
        existing = self._found.get(key)
        if existing is None:
            self._found[key] = _Candidate(
                kind, name, value, carrier, self.context, in_url, cookie, username
            )
        else:
            existing.in_url = existing.in_url or in_url
            if cookie is not None:
                existing.cookie = cookie if existing.cookie is None else existing.cookie.merged_with(cookie)
        return True

    # -- field helpers -----------------------------------------------------
    def _add_param(
        self, name: str, value: str, carrier: str, *, context: ParamContext, in_url: bool = False
    ) -> bool:
        kind = classify_param(name, value, context=context)
        return kind is not None and self.add(kind, name, value, carrier, in_url=in_url)

    def _add_cookie(
        self, name: str, value: str, carrier: str, attributes: CookieAttributes | None = None
    ) -> None:
        kind = classify_cookie(name, value)
        if kind is not None:
            self.add(kind, name, value, carrier, cookie=attributes)

    def _add_authorization(self, header_name: str, value: str, carrier: str) -> None:
        parsed = parse_authorization(value)
        if parsed is not None:
            self.add(parsed.kind, header_name, parsed.secret, carrier, username=parsed.username)

    def _scan_url(self, url: str, carrier: str) -> None:
        try:
            parts = urlsplit(url)
        except ValueError:
            return
        for source in (parts.query, parts.fragment):
            for name, value in parse_qsl(source, keep_blank_values=True):
                self._add_param(name, value, carrier, context="url", in_url=True)

    def _scan_header(self, name: str, value: str, carrier: str) -> None:
        kind = classify_header(name)
        if kind is not None:
            self.add(kind, name, value, carrier)
            return
        for token in find_jwts(value):
            self.add(FindingKind.JWT, name, token, carrier)

    def _scan_body(self, text: str | None, mime: object, carrier: str) -> set[str]:
        """Scan body text structurally, then by pattern; returns the values found."""
        found: set[str] = set()
        if not text:
            return found
        parsed = try_parse_json(text)
        if parsed is not None:
            for key, value in iter_json_strings(parsed):
                if self._add_param(key, value, carrier, context="json"):
                    found.add(value.strip())
        elif isinstance(mime, str) and "x-www-form-urlencoded" in mime.lower():
            for name, value in parse_qsl(text, keep_blank_values=True):
                if self._add_param(name, value, carrier, context="form"):
                    found.add(value.strip())
        for credential in find_scheme_credentials(text):
            if credential.secret not in found:
                self.add(credential.kind, credential.scheme, credential.secret, carrier,
                         username=credential.username)
                found.add(credential.secret)
        for token in find_jwts(text):
            if token not in found:
                self.add(FindingKind.JWT, EMBEDDED_JWT_NAME, token, carrier)
                found.add(token)
        return found

    # -- entry sides -------------------------------------------------------
    def scan_request(self, request: Mapping[str, Any]) -> None:
        for name, value in iter_name_values(request.get("cookies")):
            self._add_cookie(name, value, "request.cookie")
        for name, value in iter_name_values(request.get("headers")):
            key = name.lower()
            if key == "cookie":
                for cookie_name, cookie_value in parse_cookie_header(value):
                    self._add_cookie(cookie_name, cookie_value, "request.cookie")
            elif key in AUTH_HEADERS:
                self._add_authorization(name, value, "request.header")
            elif key == "referer":
                self._scan_url(value, "request.referer")
            else:
                self._scan_header(name, value, "request.header")

        query = list(iter_name_values(request.get("queryString")))
        if not query and isinstance(request.get("url"), str):
            query = parse_qsl(urlsplit(request["url"]).query, keep_blank_values=True)
        for name, value in query:
            self._add_param(name, value, "request.query", context="url", in_url=True)

        post = request.get("postData")
        if isinstance(post, Mapping):
            for name, value in iter_name_values(post.get("params")):
                self._add_param(name, value, "request.body", context="form")
            body = decode_body(post.get("text"), post.get("encoding"))
            self._scan_body(body, post.get("mimeType"), "request.body")

    def scan_response(self, response: Mapping[str, Any]) -> None:
        cookies = response.get("cookies")
        if isinstance(cookies, list):
            for cookie in cookies:
                if isinstance(cookie, Mapping):
                    name, value = cookie.get("name"), cookie.get("value")
                    if isinstance(name, str) and isinstance(value, str):
                        self._add_cookie(
                            name, value, "response.set-cookie", attributes_from_har_cookie(cookie)
                        )
        for name, value in iter_name_values(response.get("headers")):
            key = name.lower()
            if key == "set-cookie":
                for line in value.split("\n"):
                    parsed = parse_set_cookie(line)
                    if parsed is not None:
                        self._add_cookie(parsed[0], parsed[1], "response.set-cookie", parsed[2])
            elif key in ("location", "content-location"):
                self._scan_url(value, "response.redirect")
            elif key in AUTH_HEADERS:
                self._add_authorization(name, value, "response.header")
            else:
                self._scan_header(name, value, "response.header")
        if isinstance(response.get("redirectURL"), str):
            self._scan_url(response["redirectURL"], "response.redirect")
        content = response.get("content")
        if isinstance(content, Mapping):
            body = decode_body(content.get("text"), content.get("encoding"))
            self._scan_body(body, content.get("mimeType"), "response.body")


# -- aggregation -------------------------------------------------------------
def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _claim_strings(payload: Mapping[str, Any], claims: tuple[str, ...]) -> list[str]:
    values: list[str] = []
    for claim in claims:
        raw = payload.get(claim)
        if isinstance(raw, str):
            values.extend(raw.split())
        elif isinstance(raw, list):
            values.extend(item for item in raw if isinstance(item, str))
    return values


def _is_privileged(jwt: DecodedJwt) -> bool:
    return any(
        hint in value.lower()
        for value in _claim_strings(jwt.payload, _PRIVILEGE_CLAIMS)
        for hint in _PRIVILEGE_HINTS
    )


def _jwt_summary(jwt: DecodedJwt) -> JwtSummary:
    payload = jwt.payload
    audience = payload.get("aud")
    if not isinstance(audience, (str, list)):
        audience = None
    return JwtSummary(
        algorithm=jwt.algorithm,
        signature_present=jwt.signature_present,
        issuer=payload.get("iss") if isinstance(payload.get("iss"), str) else None,
        subject=payload.get("sub") if isinstance(payload.get("sub"), str) else None,
        audience=audience,
        scopes=_claim_strings(payload, ("scp", "scope")),
        issued_at=jwt.claim_time("iat"),
        expires_at=jwt.claim_time("exp"),
        header=jwt.header,
        payload=payload,
    )


def _expiry(
    jwt: DecodedJwt | None, group: list[_Candidate], captured_at: datetime | None
) -> tuple[datetime | None, int | None]:
    """Work out absolute expiry and total lifetime from JWT claims or cookie attributes."""
    if jwt is not None:
        expires_at = jwt.claim_time("exp")
        if expires_at is None:
            return None, None
        start = jwt.claim_time("iat") or jwt.claim_time("nbf") or captured_at
        lifetime = int((expires_at - start).total_seconds()) if start is not None else None
        return expires_at, lifetime
    for candidate in group:
        issued_at = candidate.entry.timestamp
        if candidate.cookie is not None and issued_at is not None:
            expires_at = candidate.cookie.expiry_from(issued_at)
            if expires_at is not None:
                return expires_at, int((expires_at - issued_at).total_seconds())
    return None, None


def _preview(primary: _Candidate, low_entropy: bool) -> str:
    if primary.kind is FindingKind.BASIC_CREDENTIALS:
        return f"username={primary.username}, password=********" if primary.username else "********"
    if low_entropy:
        return "********"
    return mask_preview(primary.value)


def _draft_finding(group: list[_Candidate], threshold: int) -> Finding:
    group = sorted(group, key=lambda c: c.entry.index)
    # Highest-risk interpretation wins; ``max`` keeps the earliest on ties.
    primary = max(group, key=lambda c: BASE_SCORES[c.kind])
    captured_at = group[0].entry.timestamp
    jwt = decode_jwt_unverified(primary.value) if looks_like_jwt(primary.value) else None
    expires_at, lifetime = _expiry(jwt, group, captured_at)
    cookie = next((c.cookie for c in group if c.cookie is not None), None)
    assessment = assess_risk(
        RiskContext(
            kind=primary.kind,
            in_url=any(c.in_url for c in group),
            expires_at=expires_at,
            captured_at=captured_at,
            lifetime_seconds=lifetime,
            cookie_http_only=cookie.http_only if cookie else None,
            cookie_secure=cookie.secure if cookie else None,
            privileged=jwt is not None and _is_privileged(jwt),
            unsigned_jwt=jwt is not None and (jwt.algorithm or "").lower() == "none",
        ),
        long_lived_threshold_seconds=threshold,
    )
    low_entropy = any(c.kind in LOW_ENTROPY_KINDS for c in group)
    return Finding(
        id="",
        kind=primary.kind,
        name=primary.name,
        value_preview=_preview(primary, low_entropy),
        fingerprint=None if low_entropy else fingerprint(primary.value),
        risk_score=assessment.score,
        severity=assessment.severity,
        long_lived=assessment.long_lived,
        valid_at_capture=assessment.valid_at_capture,
        expires_at=expires_at,
        lifetime_seconds=lifetime,
        factors=list(assessment.factors),
        jwt=_jwt_summary(jwt) if jwt is not None else None,
        occurrence_count=len(group),
        occurrences=[
            Occurrence(
                entry_index=c.entry.index,
                location=c.location,
                method=c.entry.method,
                url=c.entry.url,
                timestamp=c.entry.timestamp,
            )
            for c in group
        ],
        recommendation=RECOMMENDATIONS[primary.kind],
    )


def _build_findings(candidates: list[_Candidate], threshold: int) -> list[Finding]:
    groups: dict[str, list[_Candidate]] = {}
    for candidate in candidates:
        groups.setdefault(_digest(candidate.value), []).append(candidate)
    drafts = [_draft_finding(group, threshold) for group in groups.values()]
    drafts.sort(key=lambda f: (-f.risk_score, f.occurrences[0].entry_index, f.kind.value, f.name))
    return [f.model_copy(update={"id": f"HAR-{i:03d}"}) for i, f in enumerate(drafts, start=1)]


def _summarise(document: Mapping[str, Any]) -> HarSummary:
    log = document["log"]
    creator = log.get("creator")
    creator_text = None
    if isinstance(creator, Mapping) and isinstance(creator.get("name"), str):
        creator_text = f"{creator['name']} {creator.get('version', '')}".strip()
    hosts: set[str] = set()
    timestamps: list[datetime] = []
    for entry in log["entries"]:
        if not isinstance(entry, Mapping):
            continue
        request = entry.get("request")
        if isinstance(request, Mapping) and isinstance(request.get("url"), str):
            host = urlsplit(request["url"]).hostname
            if host:
                hosts.add(host)
        started = parse_iso8601(entry.get("startedDateTime"))
        if started is not None:
            timestamps.append(started)
    pages = log.get("pages")
    return HarSummary(
        creator=creator_text,
        entry_count=len(log["entries"]),
        page_count=len(pages) if isinstance(pages, list) else 0,
        hosts=sorted(hosts),
        first_request_at=min(timestamps) if timestamps else None,
        last_request_at=max(timestamps) if timestamps else None,
    )


def _stats(findings: list[Finding]) -> HarStats:
    by_severity = Counter(f.severity for f in findings)
    max_score = max((f.risk_score for f in findings), default=0)
    return HarStats(
        total_findings=len(findings),
        by_severity={severity: by_severity.get(severity, 0) for severity in Severity},
        by_kind=dict(sorted(Counter(f.kind for f in findings).items())),
        long_lived_count=sum(f.long_lived for f in findings),
        max_risk_score=max_score,
        overall_severity=severity_for(max_score) if findings else None,
    )


def _entry_context(index: int, entry: Mapping[str, Any]) -> _EntryContext:
    request = entry.get("request")
    method, url = "", ""
    if isinstance(request, Mapping):
        method = str(request.get("method") or "").upper()
        url = request.get("url") if isinstance(request.get("url"), str) else ""
    return _EntryContext(
        index=index,
        timestamp=parse_iso8601(entry.get("startedDateTime")),
        method=method,
        url=redact_url(url) if url else "",
    )


def analyze_har(
    har: Mapping[str, Any], *, long_lived_threshold_seconds: int | None = None
) -> HarAnalysisResult:
    """Analyse a parsed HAR document.

    Args:
        har: Parsed HAR (see :func:`oktatrace.har_analyzer.load_har`).
        long_lived_threshold_seconds: Lifetime above which a token counts as
            long-lived. Defaults to ``OKTATRACE_LONG_LIVED_HOURS`` (8h).

    Returns:
        Summary, statistics and findings sorted by descending risk. No raw
        secret value appears anywhere in the result.

    Raises:
        HarParseError: If ``har`` is not structurally valid.
    """
    document = load_har(har)
    threshold = (
        long_lived_threshold_seconds
        if long_lived_threshold_seconds is not None
        else get_settings().long_lived_threshold_seconds
    )
    candidates: list[_Candidate] = []
    for index, entry in enumerate(document["log"]["entries"]):
        if not isinstance(entry, Mapping):
            continue
        scanner = _EntryScanner(_entry_context(index, entry))
        if isinstance(entry.get("request"), Mapping):
            scanner.scan_request(entry["request"])
        if isinstance(entry.get("response"), Mapping):
            scanner.scan_response(entry["response"])
        candidates.extend(scanner.candidates)

    findings = _build_findings(candidates, threshold)
    return HarAnalysisResult(
        disclaimer=DISCLAIMER,
        summary=_summarise(document),
        stats=_stats(findings),
        findings=findings,
    )
