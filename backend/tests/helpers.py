"""Builders for small hand-made HAR documents used in focused tests."""

from __future__ import annotations

from typing import Any


def make_har(*entries: dict[str, Any]) -> dict[str, Any]:
    """Wrap entries in a minimal HAR document."""
    return {"log": {"version": "1.2", "creator": {"name": "test", "version": "1"}, "entries": list(entries)}}


def make_entry(
    *,
    url: str = "https://app.test.example/",
    method: str = "GET",
    request_headers: list[tuple[str, str]] | None = None,
    response_headers: list[tuple[str, str]] | None = None,
    post_text: str | None = None,
    post_mime: str = "application/json",
    response_text: str | None = None,
    response_mime: str = "application/json",
    response_encoding: str | None = None,
    started: str = "2023-10-02T14:30:00.000Z",
) -> dict[str, Any]:
    """Build a minimal HAR entry for focused tests."""
    request: dict[str, Any] = {
        "method": method,
        "url": url,
        "headers": [{"name": n, "value": v} for n, v in request_headers or []],
        "cookies": [],
        "queryString": [],
    }
    if post_text is not None:
        request["postData"] = {"mimeType": post_mime, "text": post_text}
    content: dict[str, Any] = {"mimeType": response_mime, "text": response_text or ""}
    if response_encoding:
        content["encoding"] = response_encoding
    return {
        "startedDateTime": started,
        "request": request,
        "response": {
            "status": 200,
            "headers": [{"name": n, "value": v} for n, v in response_headers or []],
            "cookies": [],
            "content": content,
            "redirectURL": "",
        },
    }
