"""Loading, validating and walking HAR documents."""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any


class HarParseError(ValueError):
    """Raised when the input is not a structurally valid HAR document."""


def load_har(source: Mapping[str, Any] | bytes | bytearray | str | Path) -> dict[str, Any]:
    """Load and validate a HAR document.

    Args:
        source: An already-parsed mapping, raw JSON bytes, a JSON string, or a
            :class:`~pathlib.Path` to a ``.har`` file. Plain strings are treated
            as JSON text, never as file paths.

    Raises:
        HarParseError: If the input is not JSON or lacks ``log.entries``.
    """
    if isinstance(source, Mapping):
        document: Any = dict(source)
    else:
        if isinstance(source, Path):
            raw = source.read_bytes()
        elif isinstance(source, str):
            raw = source.encode("utf-8")
        else:
            raw = bytes(source)
        try:
            document = json.loads(raw.decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HarParseError(f"Input is not valid UTF-8 JSON: {exc}") from exc
        except RecursionError as exc:
            raise HarParseError("Input JSON is nested too deeply") from exc

    if not isinstance(document, dict):
        raise HarParseError("HAR root must be a JSON object")
    log = document.get("log")
    if not isinstance(log, dict):
        raise HarParseError("HAR is missing the 'log' object")
    if not isinstance(log.get("entries"), list):
        raise HarParseError("HAR 'log.entries' must be a list")
    return document


def iter_name_values(items: object) -> Iterator[tuple[str, str]]:
    """Yield ``(name, value)`` string pairs from a HAR ``[{name, value}, ...]`` list."""
    if not isinstance(items, list):
        return
    for item in items:
        if isinstance(item, Mapping):
            name, value = item.get("name"), item.get("value")
            if isinstance(name, str) and isinstance(value, str):
                yield name, value


def decode_body(text: object, encoding: object) -> str | None:
    """Return body text, decoding base64 content; ``None`` for empty or binary bodies."""
    if not isinstance(text, str) or not text:
        return None
    if isinstance(encoding, str) and encoding.lower() == "base64":
        try:
            return base64.b64decode(text).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            return None
    return text


def try_parse_json(text: str) -> Any | None:
    """Parse ``text`` as a JSON object or array, or return ``None``."""
    stripped = text.lstrip()
    if not stripped or stripped[0] not in "{[":
        return None
    try:
        return json.loads(stripped)
    except (ValueError, RecursionError):
        return None


def iter_json_strings(node: Any) -> Iterator[tuple[str, str]]:
    """Yield ``(key, value)`` for every string leaf in a parsed JSON tree.

    List items inherit their parent's key, so ``{"tokens": ["a"]}`` yields
    ``("tokens", "a")``. Iterative, so deeply nested input cannot blow the stack.
    """
    stack: list[tuple[str | None, Any]] = [(None, node)]
    while stack:
        key, current = stack.pop()
        if isinstance(current, dict):
            stack.extend((str(k), v) for k, v in reversed(list(current.items())))
        elif isinstance(current, list):
            stack.extend((key, v) for v in reversed(current))
        elif isinstance(current, str) and key is not None:
            yield key, current
