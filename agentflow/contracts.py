"""JSON contracts used by structured workflow handoffs."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError


# A Markdown fence marker on a line of its own (optionally tagged, e.g. ```json).
_FENCE_LINE_PATTERN = re.compile(r"^[ \t]*```[A-Za-z0-9_+-]*[ \t]*\r?$", re.MULTILINE)
SCHEMA_ERROR_CAP = 20


def check_json_schema(schema: dict[str, Any], *, label: str) -> None:
    """Raise a concise ``ValueError`` when a declared contract is invalid."""

    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        raise ValueError(f"{label} is not a valid JSON Schema: {exc.message}") from exc


def _loads(text: str) -> tuple[bool, Any | None]:
    try:
        return True, json.loads(text)
    except json.JSONDecodeError:
        return False, None


def _whole_fence(text: str) -> tuple[bool, Any | None]:
    """The whole text is one fenced block: drop its first and last lines."""

    lines = text.splitlines()
    if len(lines) < 3 or not _FENCE_LINE_PATTERN.fullmatch(lines[0]) or not _FENCE_LINE_PATTERN.fullmatch(lines[-1]):
        return False, None
    return _loads("\n".join(lines[1:-1]).strip())


def _last_fenced_block(text: str) -> tuple[bool, Any | None]:
    """The last fenced block whose body parses.

    Fence markers are matched on lines of their own, so a marker inside a JSON
    string never closes a block. Openers are tried from the last one backwards
    and, for each opener, closers from the last one backwards.
    """

    fences = list(_FENCE_LINE_PATTERN.finditer(text))
    for opener_index in range(len(fences) - 1, -1, -1):
        for closer_index in range(len(fences) - 1, opener_index, -1):
            body = text[fences[opener_index].end() : fences[closer_index].start()].strip()
            if not body:
                continue
            found, value = _loads(body)
            if found:
                return True, value
    return False, None


def _starts_a_value(prefix: str) -> bool:
    """A raw JSON value may start the text, start a line, or follow a colon."""

    stripped = prefix.rstrip(" \t")
    return not stripped or stripped.endswith(("\n", ":"))


def _last_embedded_json(text: str) -> tuple[bool, Any | None]:
    """Find the last ``{``/``[`` whose value parses through to the end of ``text``."""

    if not text or text[-1] not in "}]":
        return False, None
    decoder = json.JSONDecoder()
    for start in range(len(text) - 1, -1, -1):
        if text[start] not in "{[" or not _starts_a_value(text[:start]):
            continue
        try:
            value, end = decoder.raw_decode(text, start)
        except json.JSONDecodeError:
            continue
        if end == len(text):
            return True, value
    return False, None


def parse_json_output(text: str | None) -> tuple[Any | None, str | None]:
    """Parse an agent's JSON response.

    Tries the whole text first, then the text as one fenced block, then the
    last fenced block whose body parses, then the last object or array that
    starts a line (or follows a colon) and runs to the end of the text.
    """

    normalized = str(text or "").strip()
    if not normalized:
        return None, "output is empty"
    try:
        return json.loads(normalized), None
    except json.JSONDecodeError as exc:
        error = f"output is not valid JSON: {exc.msg} at line {exc.lineno} column {exc.colno}"
    for fallback in (_whole_fence, _last_fenced_block, _last_embedded_json):
        found, value = fallback(normalized)
        if found:
            return value, None
    return None, error


def _json_pointer(path: Iterable[Any]) -> str:
    parts = [str(part).replace("~", "~0").replace("/", "~1") for part in path]
    return "/" + "/".join(parts) if parts else "/"


def validate_json_instance(instance: Any, schema: dict[str, Any]) -> list[str]:
    """List Draft 2020-12 violations as ``"<json pointer>: <message>"``.

    Errors are sorted by pointer then message and capped at ``SCHEMA_ERROR_CAP``
    so they can be quoted back to an agent on retry.
    """

    errors = sorted(
        (_json_pointer(error.absolute_path), error.message)
        for error in Draft202012Validator(schema).iter_errors(instance)
    )
    return [f"{pointer}: {message}" for pointer, message in errors[:SCHEMA_ERROR_CAP]]


def select_json_path(value: Any, path: str) -> Any:
    """Resolve a small dotted/JSON-pointer path used by runtime fan-out."""

    normalized = path.strip()
    if normalized in {"", "$", "/"}:
        return value
    if normalized.startswith("/"):
        parts = [part.replace("~1", "/").replace("~0", "~") for part in normalized[1:].split("/")]
    else:
        if normalized.startswith("$."):
            normalized = normalized[2:]
        parts = normalized.split(".")

    current = value
    for part in parts:
        if isinstance(current, dict) and part in current:
            current = current[part]
            continue
        if isinstance(current, list):
            try:
                current = current[int(part)]
                continue
            except (ValueError, IndexError):
                pass
        raise KeyError(path)
    return current
