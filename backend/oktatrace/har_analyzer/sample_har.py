"""Build the bundled synthetic HAR file used throughout the demo.

Story: Acme's identity administrator captured this HAR while troubleshooting
and attached it to support case CASE-00421. Like the HAR files in the 2023
incident, it contains live session cookies and other credentials. Every value
is fabricated and seeded, so the file is byte-for-byte reproducible.

Entry map (index: what it demonstrates):

0. POST /api/v1/authn - clear-text password in the body; long-lived ``DT`` cookie set
1. GET sessionCookieRedirect - one-time session token in the URL; ``sid``/``idx`` set
2. GET /app/UserHome - session cookies replayed; expired JWT embedded in the HTML
3. POST /oauth2/v1/token - refresh token and client secret in the form body; tokens in response
4. GET /api/v1/users - Bearer access token with admin scopes; CSRF header
5. GET admin dashboard - 30-day ``JSESSIONID`` without HttpOnly/Secure
6. GET /api/v1/logs - Okta-style ``SSWS`` API token
7. GET reports export - long-lived JWT in the query string
8. GET CDN stylesheet - the same JWT leaking through the Referer header
9. GET CDN font - clean negative control (binary body)
10. GET legacy wiki - HTTP Basic credentials
11. GET /oauth2/v1/authorize - authorization code in the redirect Location
"""

from __future__ import annotations

import base64
import json
import random
from dataclasses import astuple, dataclass
from datetime import datetime, timedelta
from email.utils import format_datetime
from typing import Any, Final
from urllib.parse import parse_qsl, urlencode, urlsplit

from oktatrace import DISCLAIMER, __version__
from oktatrace.har_analyzer.jwt_utils import encode_jwt
from oktatrace.scenario import (
    ADMIN_HOST,
    APP_HOST,
    CDN_HOST,
    DEFAULT_SEED,
    HAR_CAPTURE_START,
    IDP_HOST,
    ORG_NAME,
    REPORTS_HOST,
    SUPPORT_CASE_ID,
    VICTIM,
    VICTIM_USER_AGENT,
    WIKI_HOST,
    make_scenario_tokens,
    random_token,
)

SAMPLE_HAR_FILENAME: Final = "support_case_00421.har"
ADMIN_CLIENT_ID: Final = "0oaSYNadminConsole01"
REPORTS_CLIENT_ID: Final = "0oaSYNreportsApp0001"
_SERVER_IPS: Final = {  # RFC 5737 documentation addresses
    IDP_HOST: "192.0.2.10",
    ADMIN_HOST: "192.0.2.11",
    REPORTS_HOST: "198.51.100.20",
    CDN_HOST: "198.51.100.30",
    WIKI_HOST: "203.0.113.40",
}

Header = tuple[str, str]


@dataclass(frozen=True)
class SampleJwts:
    """The fabricated JWTs embedded in the sample HAR."""

    access_token: str
    id_token: str
    expired_legacy: str
    long_lived_report: str


def _epoch(value: datetime) -> int:
    return int(value.timestamp())


def make_sample_jwts(seed: int = DEFAULT_SEED) -> SampleJwts:
    """Fabricate the sample JWTs. Signatures are random bytes, not real signatures."""
    rng = random.Random(f"oktatrace-jwt-{seed}")
    t0 = HAR_CAPTURE_START
    issued = t0 + timedelta(seconds=4)
    rs256 = {"kid": "SYN-kid-01", "alg": "RS256"}
    hs256 = {"typ": "JWT", "alg": "HS256"}
    access_token = encode_jwt(
        rs256,
        {
            "ver": 1,
            "jti": random_token(rng, "AT.SYN", 24),
            "iss": f"https://{IDP_HOST}",
            "aud": f"https://{IDP_HOST}",
            "iat": _epoch(issued),
            "exp": _epoch(issued + timedelta(hours=1)),
            "cid": ADMIN_CLIENT_ID,
            "uid": VICTIM.user_id,
            "scp": ["openid", "profile", "okta.users.manage", "okta.groups.manage"],
            "sub": VICTIM.login,
            "synthetic": True,
        },
        rng.randbytes(256),
    )
    id_token = encode_jwt(
        rs256,
        {
            "sub": VICTIM.user_id,
            "name": VICTIM.display_name,
            "email": VICTIM.login,
            "ver": 1,
            "iss": f"https://{IDP_HOST}",
            "aud": ADMIN_CLIENT_ID,
            "iat": _epoch(issued),
            "exp": _epoch(issued + timedelta(hours=1)),
            "jti": random_token(rng, "ID.SYN", 24),
            "amr": ["pwd"],
            "auth_time": _epoch(t0),
            "groups": ["Everyone", "Acme-Super-Admins"],
            "synthetic": True,
        },
        rng.randbytes(256),
    )
    expired_legacy = encode_jwt(
        hs256,
        {
            "iss": f"https://{REPORTS_HOST}",
            "sub": VICTIM.login,
            "iat": _epoch(t0 - timedelta(days=10)),
            "exp": _epoch(t0 - timedelta(days=9)),
            "scope": "reports.read",
            "synthetic": True,
        },
        rng.randbytes(32),
    )
    long_lived_report = encode_jwt(
        hs256,
        {
            "iss": f"https://{REPORTS_HOST}",
            "sub": VICTIM.login,
            "iat": _epoch(t0 - timedelta(days=2)),
            "exp": _epoch(t0 + timedelta(days=28)),
            "scope": "reports.read reports.export",
            "synthetic": True,
        },
        rng.randbytes(32),
    )
    return SampleJwts(access_token, id_token, expired_legacy, long_lived_report)


def _basic_blob(username: str, password: str) -> str:
    return base64.b64encode(f"{username}:{password}".encode()).decode("ascii")


def sample_secret_values(seed: int = DEFAULT_SEED) -> list[str]:
    """Every raw secret embedded in the sample HAR (used by tests to prove nothing leaks)."""
    tokens = make_scenario_tokens(seed)
    return [
        *astuple(tokens),
        *astuple(make_sample_jwts(seed)),
        _basic_blob("svc-wiki", tokens.wiki_password),
    ]


def har_timestamp(value: datetime) -> str:
    """Format like Chrome's HAR export: ``2023-10-02T14:30:00.000Z``."""
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}Z"


def _set_cookie(
    name: str,
    value: str,
    *,
    domain: str,
    issued: datetime,
    max_age: int | None = None,
    http_only: bool = True,
    secure: bool = True,
    same_site: str | None = "Lax",
) -> tuple[Header, dict[str, Any]]:
    """Build a matching ``Set-Cookie`` header and HAR ``response.cookies`` object."""
    parts = [f"{name}={value}", "Path=/"]
    expires = issued + timedelta(seconds=max_age) if max_age is not None else None
    if expires is not None:
        parts += [f"Expires={format_datetime(expires, usegmt=True)}", f"Max-Age={max_age}"]
    if secure:
        parts.append("Secure")
    if http_only:
        parts.append("HttpOnly")
    if same_site:
        parts.append(f"SameSite={same_site}")
    cookie = {
        "name": name,
        "value": value,
        "path": "/",
        "domain": domain,
        "expires": har_timestamp(expires) if expires else None,
        "httpOnly": http_only,
        "secure": secure,
        "sameSite": same_site,
    }
    return ("Set-Cookie", "; ".join(parts)), cookie


def _entry(
    rng: random.Random,
    started: datetime,
    method: str,
    url: str,
    *,
    request_headers: tuple[Header, ...] = (),
    request_cookies: tuple[Header, ...] = (),
    post: dict[str, Any] | None = None,
    status: int = 200,
    status_text: str = "OK",
    response_headers: tuple[Header, ...] = (),
    response_cookies: tuple[dict[str, Any], ...] = (),
    mime: str = "application/json",
    body: str = "",
    body_encoding: str | None = None,
    redirect_url: str = "",
) -> dict[str, Any]:
    """Assemble one HAR 1.2 entry."""
    host = urlsplit(url).hostname or ""
    headers = [{"name": "User-Agent", "value": VICTIM_USER_AGENT}]
    headers += [{"name": n, "value": v} for n, v in request_headers]
    if request_cookies:
        headers.append({"name": "Cookie", "value": "; ".join(f"{n}={v}" for n, v in request_cookies)})
    request: dict[str, Any] = {
        "method": method,
        "url": url,
        "httpVersion": "HTTP/2.0",
        "headers": headers,
        "cookies": [{"name": n, "value": v} for n, v in request_cookies],
        "queryString": [
            {"name": n, "value": v} for n, v in parse_qsl(urlsplit(url).query, keep_blank_values=True)
        ],
        "headersSize": -1,
        "bodySize": len(post["text"].encode()) if post else 0,
    }
    if post is not None:
        request["postData"] = post

    content: dict[str, Any] = {"size": len(body.encode()), "mimeType": mime, "text": body}
    if body_encoding:
        content["encoding"] = body_encoding
    wait = round(rng.uniform(40, 260), 3)
    response = {
        "status": status,
        "statusText": status_text,
        "httpVersion": "HTTP/2.0",
        "headers": [
            {"name": "Date", "value": format_datetime(started, usegmt=True)},
            {"name": "Content-Type", "value": mime},
            {"name": "X-Request-Id", "value": random_token(rng, "req-SYN", 16)},
            *({"name": n, "value": v} for n, v in response_headers),
        ],
        "cookies": list(response_cookies),
        "content": content,
        "redirectURL": redirect_url,
        "headersSize": -1,
        "bodySize": len(body.encode()),
    }
    return {
        "pageref": "page_1",
        "startedDateTime": har_timestamp(started),
        "time": round(wait + 4.1, 3),
        "request": request,
        "response": response,
        "cache": {},
        "timings": {"blocked": 1.2, "dns": -1, "ssl": -1, "connect": -1, "send": 0.4,
                    "wait": wait, "receive": 2.5},
        "serverIPAddress": _SERVER_IPS.get(host, "192.0.2.99"),
        "connection": "443",
    }


def build_sample_har(seed: int = DEFAULT_SEED) -> dict[str, Any]:
    """Return the synthetic support-case HAR as a parsed document."""
    tok = make_scenario_tokens(seed)
    jwts = make_sample_jwts(seed)
    rng = random.Random(f"oktatrace-har-{seed}")
    t0 = HAR_CAPTURE_START

    def at(seconds: float) -> datetime:
        return t0 + timedelta(seconds=seconds)

    idp = f"https://{IDP_HOST}"
    json_headers: tuple[Header, ...] = (("Accept", "application/json"),)
    session_cookies = (("sid", tok.session_id), ("idx", tok.idx_session), ("DT", tok.device_token))

    dt_header, dt_cookie = _set_cookie(
        "DT", tok.device_token, domain=IDP_HOST, issued=at(0), max_age=5 * 365 * 86400,
        same_site="None",
    )
    sid_header, sid_cookie = _set_cookie(
        "sid", tok.session_id, domain=IDP_HOST, issued=at(1), same_site="None"
    )
    idx_header, idx_cookie = _set_cookie("idx", tok.idx_session, domain=IDP_HOST, issued=at(1))
    jsid_header, jsid_cookie = _set_cookie(
        "JSESSIONID", tok.jsession_id, domain=ADMIN_HOST, issued=at(9), max_age=30 * 86400,
        http_only=False, secure=False, same_site=None,
    )

    token_form = {
        "grant_type": "refresh_token",
        "refresh_token": tok.refresh_token,
        "client_id": ADMIN_CLIENT_ID,
        "client_secret": tok.client_secret,
        "scope": "openid profile okta.users.manage okta.groups.manage",
    }
    report_url = (
        f"https://{REPORTS_HOST}/export.csv?"
        + urlencode({"report": "quarterly-access-review", "access_token": jwts.long_lived_report})
    )
    oauth_state = random_token(rng, "st", 18)  # anti-CSRF value, deliberately not a secret
    callback = f"https://{APP_HOST}/callback?" + urlencode({"code": tok.auth_code, "state": oauth_state})
    authorize_url = f"{idp}/oauth2/v1/authorize?" + urlencode(
        {
            "client_id": REPORTS_CLIENT_ID,
            "response_type": "code",
            "scope": "openid",
            "redirect_uri": f"https://{APP_HOST}/callback",
            "state": oauth_state,
            "code_challenge": random_token(rng, "", 43),
            "code_challenge_method": "S256",
        }
    )
    redirect_to_home = f"{idp}/login/sessionCookieRedirect?" + urlencode(
        {"token": tok.session_token, "redirectUrl": f"{idp}/app/UserHome"}
    )
    home_html = (
        "<!doctype html><html><head><title>Acme Dashboard</title><script>"
        f'window.__ACME_STATE__ = {{"user":"{VICTIM.login}",'
        f'"legacyReportToken":"{jwts.expired_legacy}"}};'
        "</script></head><body><h1>Welcome back</h1></body></html>"
    )

    entries = [
        _entry(
            rng, at(0), "POST", f"{idp}/api/v1/authn",
            request_headers=json_headers + (("Content-Type", "application/json"), ("Origin", idp)),
            post={
                "mimeType": "application/json",
                "text": json.dumps(
                    {
                        "username": VICTIM.login,
                        "password": tok.password,
                        "options": {"warnBeforePasswordExpired": True},
                    }
                ),
            },
            response_headers=(dt_header,),
            response_cookies=(dt_cookie,),
            body=json.dumps(
                {
                    "status": "SUCCESS",
                    "expiresAt": har_timestamp(at(300)),
                    "sessionToken": tok.session_token,
                    "_embedded": {"user": {"id": VICTIM.user_id, "profile": {"login": VICTIM.login}}},
                }
            ),
        ),
        _entry(
            rng, at(1), "GET", redirect_to_home,
            request_cookies=(("DT", tok.device_token),),
            status=302, status_text="Found",
            response_headers=(("Location", f"{idp}/app/UserHome"), sid_header, idx_header),
            response_cookies=(sid_cookie, idx_cookie),
            mime="text/html", redirect_url=f"{idp}/app/UserHome",
        ),
        _entry(
            rng, at(2), "GET", f"{idp}/app/UserHome",
            request_headers=(("Accept", "text/html"),),
            request_cookies=session_cookies + (("lang", "en"), ("_ga", "GA1.2.1577384417.1696256400")),
            mime="text/html", body=home_html,
        ),
        _entry(
            rng, at(5), "POST", f"{idp}/oauth2/v1/token",
            request_headers=json_headers
            + (("Content-Type", "application/x-www-form-urlencoded"), ("Origin", idp)),
            post={
                "mimeType": "application/x-www-form-urlencoded",
                "text": urlencode(token_form),
                "params": [{"name": k, "value": v} for k, v in token_form.items()],
            },
            body=json.dumps(
                {
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "access_token": jwts.access_token,
                    "scope": token_form["scope"],
                    "refresh_token": tok.refresh_token,
                    "id_token": jwts.id_token,
                }
            ),
        ),
        _entry(
            rng, at(6), "GET", f"{idp}/api/v1/users?" + urlencode({"limit": 25, "filter": 'status eq "ACTIVE"'}),
            request_headers=json_headers
            + (
                ("Authorization", f"Bearer {jwts.access_token}"),
                ("X-Okta-XsrfToken", tok.csrf_token),
                ("Referer", f"{idp}/admin/users"),
            ),
            body=json.dumps(
                [
                    {"id": "00uSYNalexchen0001", "status": "ACTIVE",
                     "profile": {"login": "alex.chen@acme.example"}},
                    {"id": "00uSYNpriyanair001", "status": "ACTIVE",
                     "profile": {"login": "priya.nair@acme.example"}},
                ]
            ),
        ),
        _entry(
            rng, at(9), "GET", f"https://{ADMIN_HOST}/admin/dashboard",
            request_headers=(("Accept", "text/html"),),
            response_headers=(jsid_header,), response_cookies=(jsid_cookie,),
            mime="text/html", body="<html><body><h1>Admin dashboard</h1></body></html>",
        ),
        _entry(
            rng, at(14), "GET",
            f"{idp}/api/v1/logs?" + urlencode({"since": "2023-10-02T00:00:00Z", "limit": 20}),
            request_headers=json_headers + (("Authorization", f"SSWS {tok.api_token}"),),
            body=json.dumps([{"eventType": "user.session.start", "outcome": {"result": "SUCCESS"}}]),
        ),
        _entry(
            rng, at(20), "GET", report_url,
            request_headers=(("Accept", "text/csv"),),
            mime="text/csv", body=f"user,last_access\n{VICTIM.login},2023-10-01\n",
        ),
        _entry(
            rng, at(20.4), "GET", f"https://{CDN_HOST}/assets/css/report.css",
            request_headers=(("Accept", "text/css"), ("Referer", report_url)),
            mime="text/css", body="body{font-family:sans-serif}",
        ),
        _entry(
            rng, at(21), "GET", f"https://{CDN_HOST}/assets/fonts/inter.woff2",
            request_headers=(("Accept", "*/*"), ("Referer", f"{idp}/app/UserHome")),
            mime="font/woff2",
            body=base64.b64encode(b"wOF2\x00\x01\xff\xfe" + rng.randbytes(56)).decode("ascii"),
            body_encoding="base64",
        ),
        _entry(
            rng, at(25), "GET", f"https://{WIKI_HOST}/rest/api/space?limit=10",
            request_headers=json_headers
            + (("Authorization", f"Basic {_basic_blob('svc-wiki', tok.wiki_password)}"),),
            body=json.dumps({"results": [{"key": "OPS", "name": "Operations"}], "size": 1}),
        ),
        _entry(
            rng, at(30), "GET", authorize_url,
            request_cookies=session_cookies,
            status=302, status_text="Found",
            response_headers=(("Location", callback),),
            mime="text/html", redirect_url=callback,
        ),
    ]

    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "OktaTrace synthetic HAR generator", "version": __version__},
            "browser": {"name": "Chrome", "version": "117.0.5938.149"},
            "pages": [
                {
                    "startedDateTime": har_timestamp(t0),
                    "id": "page_1",
                    "title": f"{ORG_NAME} admin troubleshooting ({SUPPORT_CASE_ID})",
                    "pageTimings": {"onContentLoad": 812.4, "onLoad": 1430.9},
                }
            ],
            "entries": entries,
            "comment": f"{DISCLAIMER} Fictional capture attached to support case {SUPPORT_CASE_ID}.",
        }
    }
