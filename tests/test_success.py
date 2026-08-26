from pathlib import Path

import json

import pytest

from agentflow.specs import AgentKind, NodeResult, NodeSpec
from agentflow.success import evaluate_success
from agentflow.traces import create_trace_parser


def test_success_criteria_cover_output_and_files(tmp_path: Path):
    target = tmp_path / "artifact.txt"
    target.write_text("hello success world", encoding="utf-8")
    node = NodeSpec.model_validate(
        {
            "id": "writer",
            "agent": "codex",
            "prompt": "x",
            "success_criteria": [
                {"kind": "output_contains", "value": "success"},
                {"kind": "file_exists", "path": "artifact.txt"},
                {"kind": "file_contains", "path": "artifact.txt", "value": "hello"},
                {"kind": "file_nonempty", "path": "artifact.txt"},
            ],
        }
    )
    result = NodeResult(node_id="writer", output="success")
    passed, messages = evaluate_success(node, result, tmp_path)
    assert passed is True
    assert any("file_exists" in message for message in messages)


def test_success_criteria_handle_non_utf8_artifacts(tmp_path: Path):
    target = tmp_path / "artifact.bin"
    target.write_bytes(b"\xff\xfehello\n")
    node = NodeSpec.model_validate(
        {
            "id": "writer",
            "agent": "codex",
            "prompt": "x",
            "success_criteria": [
                {"kind": "file_contains", "path": "artifact.bin", "value": "hello"},
                {"kind": "file_nonempty", "path": "artifact.bin"},
            ],
        }
    )

    passed, messages = evaluate_success(node, NodeResult(node_id="writer"), tmp_path)

    assert passed is True
    assert "file_contains(artifact.bin, 'hello')=True" in messages
    assert "file_nonempty(artifact.bin)=True" in messages


def _connector_success_node(agent: AgentKind) -> NodeSpec:
    return NodeSpec.model_validate(
        {
            "id": "hunt",
            "agent": agent.value,
            "prompt": "finish",
            "success_criteria": [
                {
                    "kind": "connector_tool_called",
                    "connector": "bugdb",
                    "tool": "finish_hunt",
                }
            ],
        }
    )


def _connector_events(agent: AgentKind, *, is_error: bool, attempt: int = 1):
    parser = create_trace_parser(agent, "hunt")
    parser.start_attempt(attempt)
    if agent == AgentKind.CODEX:
        return parser.feed(
            json.dumps(
                {
                    "type": "item.completed",
                    "item": {
                        "id": f"codex-{attempt}-{is_error}",
                        "type": "mcp_tool_call",
                        "server": "bugdb",
                        "tool": "finish_hunt",
                        "status": "failed" if is_error else "completed",
                        "error": "database rejected write" if is_error else None,
                    },
                }
            )
        )
    if agent == AgentKind.CLAUDE:
        call_id = f"claude-{attempt}-{is_error}"
        parser.feed(
            json.dumps(
                {
                    "type": "assistant",
                    "message": {
                        "content": [
                            {
                                "type": "tool_use",
                                "id": call_id,
                                "name": "mcp__bugdb__finish_hunt",
                                "input": {},
                            }
                        ]
                    },
                }
            )
        )
        return parser.feed(
            json.dumps(
                {
                    "type": "user",
                    "message": {
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": call_id,
                                "is_error": is_error,
                                "content": "failed" if is_error else "ok",
                            }
                        ]
                    },
                }
            )
        )
    return parser.feed(
        json.dumps(
            {
                "type": "tool_execution_end",
                "toolCallId": f"pi-{attempt}-{is_error}",
                "toolName": "bugdb_finish_hunt",
                "result": {},
                "isError": is_error,
            }
        )
    )


@pytest.mark.parametrize("agent", [AgentKind.CODEX, AgentKind.CLAUDE, AgentKind.PI])
def test_success_criteria_require_completed_non_error_connector_call(
    tmp_path: Path,
    agent: AgentKind,
):
    node = _connector_success_node(agent)
    result = NodeResult(
        node_id="hunt",
        current_attempt=1,
        trace_events=_connector_events(agent, is_error=True),
    )

    assert evaluate_success(node, result, tmp_path)[0] is False

    result.trace_events.extend(_connector_events(agent, is_error=False))
    passed, messages = evaluate_success(node, result, tmp_path)

    assert passed is True
    assert messages == ["connector_tool_called(bugdb.finish_hunt)=True"]


@pytest.mark.parametrize("agent", [AgentKind.CODEX, AgentKind.CLAUDE, AgentKind.PI])
def test_connector_success_ignores_calls_from_previous_attempt(
    tmp_path: Path,
    agent: AgentKind,
):
    node = _connector_success_node(agent)
    result = NodeResult(
        node_id="hunt",
        current_attempt=2,
        trace_events=[
            *_connector_events(agent, is_error=False, attempt=1),
            *_connector_events(agent, is_error=True, attempt=2),
        ],
    )

    assert evaluate_success(node, result, tmp_path)[0] is False


def test_connector_success_does_not_scan_assistant_text(tmp_path: Path):
    node = _connector_success_node(AgentKind.CLAUDE)
    parser = create_trace_parser(AgentKind.CLAUDE, "hunt")
    events = parser.feed(
        '{"type":"assistant","message":{"content":[{"type":"text",'
        '"text":"I called mcp__bugdb__finish_hunt successfully"}]}}'
    )
    result = NodeResult(node_id="hunt", current_attempt=1, trace_events=events)

    assert evaluate_success(node, result, tmp_path)[0] is False


def test_connector_success_requires_the_declared_connector(tmp_path: Path):
    node = _connector_success_node(AgentKind.PI)
    parser = create_trace_parser(AgentKind.PI, "hunt")
    events = parser.feed(
        '{"type":"tool_execution_end","toolCallId":"other-1",'
        '"toolName":"otherdb_finish_hunt","result":{},"isError":false}'
    )
    result = NodeResult(node_id="hunt", current_attempt=1, trace_events=events)

    assert evaluate_success(node, result, tmp_path)[0] is False
