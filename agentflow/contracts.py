"""JSON contracts used by structured workflow handoffs."""

from __future__ import annotations

import json
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError


def check_json_schema(schema: dict[str, Any], *, label: str) -> None:
    """Raise a concise ``ValueError`` when a declared contract is invalid."""

    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        raise ValueError(f"{label} is not a valid JSON Schema: {exc.message}") from exc


def validate_json_contract(value: Any, schema: dict[str, Any], *, label: str) -> list[str]:
    """Return stable, human-readable validation failures for ``value``."""

    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(value), key=lambda error: list(error.absolute_path))
    messages: list[str] = []
    for error in errors:
        path = ".".join(str(part) for part in error.absolute_path) or "$"
        messages.append(f"{label} at {path}: {error.message}")
    return messages


def parse_json_output(text: str | None) -> tuple[Any | None, str | None]:
    """Parse an agent's JSON response, accepting a single fenced JSON block."""

    normalized = str(text or "").strip()
    if normalized.startswith("```"):
        lines = normalized.splitlines()
        if len(lines) >= 3 and lines[-1].strip() == "```":
            opening = lines[0].strip().lower()
            if opening in {"```", "```json"}:
                normalized = "\n".join(lines[1:-1]).strip()
    if not normalized:
        return None, "output is empty"
    try:
        return json.loads(normalized), None
    except json.JSONDecodeError as exc:
        return None, f"output is not valid JSON: {exc.msg} at line {exc.lineno} column {exc.colno}"


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
