from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from agentflow.contracts import parse_json_output, validate_json_instance
from agentflow.specs import (
    FileContainsCriterion,
    FileExistsCriterion,
    FileJsonSchemaCriterion,
    FileNonEmptyCriterion,
    ConnectorToolCalledCriterion,
    NodeResult,
    NodeSpec,
    OutputContainsCriterion,
    OutputJsonSchemaCriterion,
    OutputRegexCriterion,
)

# Filesystem mtimes come from the kernel's coarse clock and can lag the wall
# clock that stamps ``attempt_started_at`` by one scheduler tick, so a file
# written immediately after launch is still accepted as modified in the attempt.
MTIME_TOLERANCE_SECONDS = 0.05


def _connector_tool_completed(result: NodeResult, connector: str, tool: str) -> bool:
    aliases = {
        f"{connector}.{tool}",
        f"{connector}_{tool}",
        f"mcp__{connector}__{tool}",
    }
    attempt = result.current_attempt or max(
        (event.attempt for event in result.trace_events),
        default=1,
    )
    return any(
        event.attempt == attempt
        and event.kind == "connector_tool_completed"
        and getattr(event, "is_error", True) is False
        and (
            (
                getattr(event, "connector", None) == connector
                and getattr(event, "tool", None) == tool
            )
            or getattr(event, "tool_name", None) in aliases
        )
        for event in result.trace_events
    )


def _read_success_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _has_nonempty_contents(path: Path) -> bool:
    text = _read_success_text(path)
    if text is not None:
        return text.strip() != ""
    try:
        return path.read_bytes().strip() != b""
    except OSError:
        return False


def _timestamp_seconds(value: str) -> float:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _schema_verdict(label: str, errors: list[str]) -> tuple[bool, str]:
    if not errors:
        return True, f"{label}=True"
    return False, f"{label}=False: {len(errors)} error(s): " + "; ".join(errors)


def _check_output_json_schema(criterion: OutputJsonSchemaCriterion, result: NodeResult) -> tuple[bool, str]:
    label = "output_json_schema"
    instance = result.structured_output
    if instance is None:
        instance, error = parse_json_output(result.output or result.final_response)
        if error is not None:
            return False, f"{label}=False: {error}"
    return _schema_verdict(label, validate_json_instance(instance, criterion.json_schema))


def _check_file_json_schema(
    criterion: FileJsonSchemaCriterion,
    *,
    working_dir: Path,
    runtime_dir: Path | None,
    attempt_started_at: str | None,
) -> tuple[bool, str]:
    label = f"file_json_schema({criterion.path})"
    root = runtime_dir if criterion.root == "runtime" else working_dir
    if root is None:
        return False, f"{label}=False: runtime directory is unknown"
    path = root / criterion.path
    text = _read_success_text(path) if path.is_file() else None
    if text is None:
        return False, f"{label}=False: file not found"
    if criterion.modified_in_attempt and attempt_started_at is not None:
        if path.stat().st_mtime + MTIME_TOLERANCE_SECONDS < _timestamp_seconds(attempt_started_at):
            return False, f"{label}=False: file was not modified during this attempt"
    if not text.strip():
        return False, f"{label}=False: file is empty"
    try:
        instance = json.loads(text)
    except json.JSONDecodeError as exc:
        return False, f"{label}=False: file is not valid JSON: {exc.msg} at line {exc.lineno} column {exc.colno}"
    return _schema_verdict(label, validate_json_instance(instance, criterion.json_schema))


def evaluate_success(
    node: NodeSpec,
    result: NodeResult,
    working_dir: Path,
    *,
    runtime_dir: Path | None = None,
    attempt_started_at: str | None = None,
) -> tuple[bool, list[str]]:
    if not node.success_criteria:
        return True, ["no success criteria configured"]

    messages: list[str] = []
    output = result.output or result.final_response or ""
    passed = True

    for criterion in node.success_criteria:
        if isinstance(criterion, OutputContainsCriterion):
            haystack = output if criterion.case_sensitive else output.lower()
            needle = criterion.value if criterion.case_sensitive else criterion.value.lower()
            ok = needle in haystack
            messages.append(f"output_contains({criterion.value!r})={ok}")
        elif isinstance(criterion, OutputRegexCriterion):
            flags = 0
            if not criterion.case_sensitive:
                flags |= re.IGNORECASE
            if criterion.multiline:
                flags |= re.MULTILINE
            try:
                ok = re.search(criterion.value, output, flags) is not None
            except re.error as exc:
                ok = False
                messages.append(f"output_regex({criterion.value!r}): invalid pattern ({exc})")
                passed = passed and ok
                continue
            messages.append(f"output_regex({criterion.value!r})={ok}")
        elif isinstance(criterion, FileExistsCriterion):
            ok = (working_dir / criterion.path).exists()
            messages.append(f"file_exists({criterion.path})={ok}")
        elif isinstance(criterion, FileContainsCriterion):
            path = working_dir / criterion.path
            contents = _read_success_text(path) if path.exists() else None
            haystack = contents if criterion.case_sensitive or contents is None else contents.lower()
            needle = criterion.value if criterion.case_sensitive else criterion.value.lower()
            ok = contents is not None and needle in haystack
            messages.append(f"file_contains({criterion.path}, {criterion.value!r})={ok}")
        elif isinstance(criterion, FileNonEmptyCriterion):
            path = working_dir / criterion.path
            ok = path.exists() and _has_nonempty_contents(path)
            messages.append(f"file_nonempty({criterion.path})={ok}")
        elif isinstance(criterion, ConnectorToolCalledCriterion):
            ok = _connector_tool_completed(result, criterion.connector, criterion.tool)
            messages.append(
                f"connector_tool_called({criterion.connector}.{criterion.tool})={ok}"
            )
        elif isinstance(criterion, OutputJsonSchemaCriterion):
            ok, message = _check_output_json_schema(criterion, result)
            messages.append(message)
        elif isinstance(criterion, FileJsonSchemaCriterion):
            ok, message = _check_file_json_schema(
                criterion,
                working_dir=working_dir,
                runtime_dir=runtime_dir,
                attempt_started_at=attempt_started_at,
            )
            messages.append(message)
        else:
            ok = False
            messages.append(f"unsupported success criterion: {criterion}")
        passed = passed and ok
    return passed, messages
