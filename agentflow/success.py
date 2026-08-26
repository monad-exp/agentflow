from __future__ import annotations

import json
import re
from pathlib import Path

from agentflow.specs import (
    FileContainsCriterion,
    FileExistsCriterion,
    FileNonEmptyCriterion,
    ConnectorToolCalledCriterion,
    NodeResult,
    NodeSpec,
    OutputContainsCriterion,
    OutputRegexCriterion,
)


def _connector_tool_completed(result: NodeResult, connector: str, tool: str) -> bool:
    aliases = {
        tool,
        f"{connector}.{tool}",
        f"{connector}_{tool}",
        f"mcp__{connector}__{tool}",
    }
    for event in result.trace_events:
        raw = event.raw
        text = " ".join(
            part
            for part in (
                event.title,
                event.content or "",
                json.dumps(raw, ensure_ascii=False, sort_keys=True) if raw is not None else "",
            )
            if part
        )
        if not any(alias in text for alias in aliases) or connector not in text:
            continue
        if isinstance(raw, dict):
            item = raw.get("item")
            if isinstance(item, dict) and item.get("type") == "mcp_tool_call":
                if item.get("server") != connector or item.get("tool") != tool:
                    continue
                if event.kind != "item_completed":
                    continue
                error = item.get("error")
                return (
                    item.get("status") == "completed"
                    and (error is None or error == "")
                )
        lowered = text.lower()
        if event.kind in {"tool_result", "toolresult"} and "error" not in lowered:
            return True
        if event.kind in {"assistant_message", "message_end", "agent_end", "turn_end", "event"} and any(
            marker in lowered for marker in ("tool_use", "tooluse", "tool_call", "toolcall")
        ):
            return True
    return False


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


def evaluate_success(node: NodeSpec, result: NodeResult, working_dir: Path) -> tuple[bool, list[str]]:
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
        else:
            ok = False
            messages.append(f"unsupported success criterion: {criterion}")
        passed = passed and ok
    return passed, messages
