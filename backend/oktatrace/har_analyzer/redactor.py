"""Produce a sanitised copy of a HAR file with every secret masked.

Rules, applied to a deep copy (the input is never mutated):

* every cookie value (request and response) is masked, names are kept;
* ``Authorization`` credentials, API-key, CSRF and session headers are masked;
* sensitive query, form and JSON parameters are masked (same rules as the analyzer);
* any JWT or ``Bearer``/``SSWS``/``Basic`` credential anywhere else in the
  document (bodies, custom ``_`` fields, comments) is masked by a final sweep.

Markers keep a truncated SHA-256 fingerprint (``[REDACTED:sha256=...]``) so a
redacted HAR can still be correlated with logs. Passwords and Basic credentials
become a bare ``[REDACTED]``.
"""

from __future__ import annotations

import base64
import binascii
import copy
import json
import re
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from oktatrace.common.masking import is_redacted, redaction_marker
from oktatrace.har_analyzer.classify import (
    AUTH_HEADERS,
    LOW_ENTROPY_KINDS,
    SCHEME_CREDENTIAL_RE,
    URL_HEADERS,
    ParamContext,
    classify_header,
    classify_param,
    is_plausible_scheme_credential,
)
from oktatrace.har_analyzer.har_io import try_parse_json
from oktatrace.har_analyzer.jwt_utils import JWT_PATTERN

REDACTION_COMMENT: Final = (
    "Secrets masked by OktaTrace. Markers keep a truncated SHA-256 fingerprint so "
    "redacted values can still be correlated."
)
_URL_SAFE_CHARS: Final = "[]:=/"


@dataclass(frozen=True)
class RedactionResult:
    """A redacted HAR plus counts of what was masked, per area."""

    har: dict[str, Any]
    redaction_count: int
    by_area: dict[str, int]


class _Redactor:
    """Stateful helper that masks values and counts how many it masked."""

    def __init__(self) -> None:
        self.counts: Counter[str] = Counter()

    def mask(self, value: str, area: str, *, with_fingerprint: bool = True) -> str:
        if not value.strip() or is_redacted(value):
            return value
        self.counts[area] += 1
        return redaction_marker(value, with_fingerprint=with_fingerprint)

    def mask_param(self, name: str, value: str, area: str, context: ParamContext) -> str:
        kind = classify_param(name, value, context=context)
        if kind is None:
            return value
        return self.mask(value, area, with_fingerprint=kind not in LOW_ENTROPY_KINDS)

    # -- free text ---------------------------------------------------------
    def scrub_text(self, text: str, area: str) -> str:
        """Mask JWTs and scheme credentials embedded anywhere in ``text``."""
        if not text:
            return text
        text = JWT_PATTERN.sub(lambda m: self.mask(m.group(0), area), text)

        def replace_scheme(match: re.Match[str]) -> str:
            scheme, credential = match.group(1), match.group(2)
            if not is_plausible_scheme_credential(scheme, credential):
                return match.group(0)
            masked = self.mask(credential, area, with_fingerprint=scheme.lower() != "basic")
            return f"{scheme} {masked}"

        return SCHEME_CREDENTIAL_RE.sub(replace_scheme, text)

    def deep_scrub(self, node: Any) -> Any:
        """Apply :meth:`scrub_text` to every string anywhere in the document."""
        if isinstance(node, dict):
            return {key: self.deep_scrub(value) for key, value in node.items()}
        if isinstance(node, list):
            return [self.deep_scrub(value) for value in node]
        if isinstance(node, str):
            return self.scrub_text(node, "other")
        return node

    # -- URLs --------------------------------------------------------------
    def redact_pairs(self, encoded: str, area: str, context: ParamContext) -> str:
        """Mask sensitive values in an ``a=1&b=2`` string; unchanged text if nothing matched."""
        if "=" not in encoded:
            return encoded
        before = sum(self.counts.values())
        pairs = [
            (name, self.mask_param(name, value, area, context))
            for name, value in parse_qsl(encoded, keep_blank_values=True)
        ]
        if sum(self.counts.values()) == before:
            return encoded
        return urlencode(pairs, safe=_URL_SAFE_CHARS)

    def redact_url(self, url: str, area: str) -> str:
        """Mask sensitive query-string and fragment parameters in ``url``."""
        try:
            parts = urlsplit(url)
        except ValueError:
            return self.scrub_text(url, area)
        query = self.redact_pairs(parts.query, area, "url")
        fragment = self.redact_pairs(parts.fragment, area, "url")
        if query == parts.query and fragment == parts.fragment:
            return self.scrub_text(url, area)
        return self.scrub_text(urlunsplit(parts._replace(query=query, fragment=fragment)), area)

    # -- headers and cookies ----------------------------------------------
    def _redact_cookie_pair(self, pair: str, area: str) -> str:
        name, sep, value = pair.strip().partition("=")
        if not sep:
            return pair.strip()
        return f"{name.strip()}={self.mask(value.strip(), area)}"

    def _redact_set_cookie(self, line: str, area: str) -> str:
        first, sep, attributes = line.partition(";")
        return self._redact_cookie_pair(first, area) + (sep + attributes if sep else "")

    def _redact_authorization(self, value: str, area: str) -> str:
        scheme, sep, credential = value.strip().partition(" ")
        if not sep:
            return self.mask(value, area)
        if not credential.strip():
            return value
        with_fingerprint = scheme.lower() != "basic"
        return f"{scheme} {self.mask(credential.strip(), area, with_fingerprint=with_fingerprint)}"

    def redact_header_value(self, name: str, value: str, area: str) -> str:
        key = name.strip().lower()
        if key == "cookie":
            return "; ".join(self._redact_cookie_pair(p, area) for p in value.split(";") if p.strip())
        if key == "set-cookie":
            return "\n".join(self._redact_set_cookie(line, area) for line in value.split("\n"))
        if key in AUTH_HEADERS:
            return self._redact_authorization(value, area)
        if classify_header(key) is not None:
            return self.mask(value, area)
        if key in URL_HEADERS:
            return self.redact_url(value, area)
        return self.scrub_text(value, area)

    def redact_headers(self, headers: object, area: str) -> None:
        if not isinstance(headers, list):
            return
        for header in headers:
            if isinstance(header, dict):
                name, value = header.get("name"), header.get("value")
                if isinstance(name, str) and isinstance(value, str):
                    header["value"] = self.redact_header_value(name, value, area)

    def redact_cookie_list(self, cookies: object, area: str) -> None:
        if not isinstance(cookies, list):
            return
        for cookie in cookies:
            if isinstance(cookie, dict) and isinstance(cookie.get("value"), str):
                cookie["value"] = self.mask(cookie["value"], area)

    def redact_param_list(self, params: object, area: str, context: ParamContext) -> None:
        if not isinstance(params, list):
            return
        for param in params:
            if isinstance(param, dict):
                name, value = param.get("name"), param.get("value")
                if isinstance(name, str) and isinstance(value, str):
                    param["value"] = self.mask_param(name, value, area, context)

    # -- bodies ------------------------------------------------------------
    def _redact_json(self, node: Any, key: str | None, area: str) -> Any:
        if isinstance(node, dict):
            return {k: self._redact_json(v, str(k), area) for k, v in node.items()}
        if isinstance(node, list):
            return [self._redact_json(v, key, area) for v in node]
        if isinstance(node, str) and key is not None:
            return self.mask_param(key, node, area, "json")
        return node

    def redact_body_text(self, text: str, mime: object, area: str) -> str:
        parsed = try_parse_json(text)
        if parsed is not None:
            before = sum(self.counts.values())
            try:
                redacted = self._redact_json(parsed, None, area)
            except RecursionError:
                redacted = parsed
            if sum(self.counts.values()) != before:
                text = json.dumps(redacted, ensure_ascii=False)
        elif isinstance(mime, str) and "x-www-form-urlencoded" in mime.lower():
            text = self.redact_pairs(text, area, "form")
        return self.scrub_text(text, area)

    def redact_content(self, content: dict[str, Any], area: str) -> None:
        text = content.get("text")
        if not isinstance(text, str) or not text:
            return
        encoding = content.get("encoding")
        if isinstance(encoding, str) and encoding.lower() == "base64":
            try:
                decoded = base64.b64decode(text).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError):
                return  # binary payload (image, font): nothing textual to redact
            redacted = self.redact_body_text(decoded, content.get("mimeType"), area)
            if redacted != decoded:
                content["text"] = base64.b64encode(redacted.encode("utf-8")).decode("ascii")
            return
        content["text"] = self.redact_body_text(text, content.get("mimeType"), area)

    # -- entries -----------------------------------------------------------
    def redact_entry(self, entry: dict[str, Any]) -> None:
        request = entry.get("request")
        if isinstance(request, dict):
            if isinstance(request.get("url"), str):
                request["url"] = self.redact_url(request["url"], "request.url")
            self.redact_headers(request.get("headers"), "request.header")
            self.redact_cookie_list(request.get("cookies"), "request.cookie")
            self.redact_param_list(request.get("queryString"), "request.query", "url")
            post = request.get("postData")
            if isinstance(post, dict):
                self.redact_param_list(post.get("params"), "request.body", "form")
                self.redact_content(post, "request.body")
        response = entry.get("response")
        if isinstance(response, dict):
            self.redact_headers(response.get("headers"), "response.header")
            self.redact_cookie_list(response.get("cookies"), "response.cookie")
            if isinstance(response.get("redirectURL"), str):
                response["redirectURL"] = self.redact_url(response["redirectURL"], "response.redirect")
            content = response.get("content")
            if isinstance(content, dict):
                self.redact_content(content, "response.body")


def redact_har(har: Mapping[str, Any]) -> RedactionResult:
    """Return a redacted deep copy of ``har``; the input is left untouched."""
    redactor = _Redactor()
    document = copy.deepcopy(dict(har))
    log = document.get("log")
    if isinstance(log, dict) and isinstance(log.get("entries"), list):
        for entry in log["entries"]:
            if isinstance(entry, dict):
                redactor.redact_entry(entry)
    document = redactor.deep_scrub(document)
    log = document.get("log")
    if isinstance(log, dict):
        existing = log.get("comment")
        log["comment"] = f"{existing} | {REDACTION_COMMENT}" if existing else REDACTION_COMMENT
    return RedactionResult(
        har=document, redaction_count=sum(redactor.counts.values()), by_area=dict(redactor.counts)
    )


def redact_url(url: str) -> str:
    """Mask sensitive parameters in a single URL (used for report output)."""
    return _Redactor().redact_url(url, "url")
