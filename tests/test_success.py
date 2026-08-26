from pathlib import Path

from agentflow.specs import AgentKind, NodeResult, NodeSpec, NormalizedTraceEvent
from agentflow.success import evaluate_success


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


def test_success_criteria_require_completed_connector_tool_call(tmp_path: Path):
    node = NodeSpec.model_validate(
        {
            "id": "hunt",
            "agent": "codex",
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
    result = NodeResult(
        node_id="hunt",
        trace_events=[
            NormalizedTraceEvent(
                node_id="hunt",
                agent=AgentKind.CODEX,
                kind="item_started",
                title="Item started: mcp_tool_call",
                raw={
                    "type": "item.started",
                    "item": {
                        "type": "mcp_tool_call",
                        "server": "bugdb",
                        "tool": "finish_hunt",
                        "status": "in_progress",
                        "error": None,
                    },
                },
            ),
            NormalizedTraceEvent(
                node_id="hunt",
                agent=AgentKind.CODEX,
                kind="item_completed",
                title="Item completed: mcp_tool_call",
                raw={
                    "type": "item.completed",
                    "item": {
                        "type": "mcp_tool_call",
                        "server": "bugdb",
                        "tool": "finish_hunt",
                        "status": "completed",
                        "error": None,
                    },
                },
            )
        ],
    )

    passed, messages = evaluate_success(node, result, tmp_path)

    assert passed is True
    assert messages == ["connector_tool_called(bugdb.finish_hunt)=True"]
