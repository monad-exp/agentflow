from datetime import datetime, timedelta, timezone
from pathlib import Path

import json
import os
import time

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


RANK_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["rankedFiles"],
    "properties": {
        "rankedFiles": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["path", "score"],
                "properties": {
                    "path": {"type": "string"},
                    "score": {"type": "integer", "minimum": 1, "maximum": 5},
                },
            },
        }
    },
}


def _schema_node(criteria: list[dict]) -> NodeSpec:
    return NodeSpec.model_validate(
        {"id": "rank", "agent": "codex", "prompt": "rank", "success_criteria": criteria}
    )


def _attempt_started_seconds_ago(seconds: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat()


def test_output_json_schema_validates_structured_output(tmp_path: Path):
    node = _schema_node([{"kind": "output_json_schema", "schema": RANK_SCHEMA}])
    result = NodeResult(
        node_id="rank",
        output="ignored when structured output is present",
        structured_output={"rankedFiles": [{"path": "api.py", "score": 5}]},
    )

    assert evaluate_success(node, result, tmp_path) == (True, ["output_json_schema=True"])


def test_output_json_schema_reparses_output_when_structured_output_is_missing(tmp_path: Path):
    node = _schema_node([{"kind": "output_json_schema", "schema": RANK_SCHEMA}])
    result = NodeResult(node_id="rank", output='Ranking complete.\n{"rankedFiles": []}')

    assert evaluate_success(node, result, tmp_path) == (True, ["output_json_schema=True"])


def test_output_json_schema_lists_every_schema_error(tmp_path: Path):
    node = _schema_node([{"kind": "output_json_schema", "schema": RANK_SCHEMA}])
    result = NodeResult(
        node_id="rank",
        structured_output={"rankedFiles": [{"path": 1, "score": 9}], "extra": True},
    )

    passed, messages = evaluate_success(node, result, tmp_path)

    assert passed is False
    assert messages == [
        "output_json_schema=False: 3 error(s): "
        "/: Additional properties are not allowed ('extra' was unexpected); "
        "/rankedFiles/0/path: 1 is not of type 'string'; "
        "/rankedFiles/0/score: 9 is greater than the maximum of 5"
    ]


def test_output_json_schema_reports_unparseable_output(tmp_path: Path):
    node = _schema_node([{"kind": "output_json_schema", "schema": RANK_SCHEMA}])
    result = NodeResult(node_id="rank", final_response="I could not finish the ranking.")

    passed, messages = evaluate_success(node, result, tmp_path)

    assert passed is False
    assert messages == [
        "output_json_schema=False: output is not valid JSON: Expecting value at line 1 column 1"
    ]


def test_file_json_schema_reads_runtime_and_workdir_roots(tmp_path: Path):
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    (runtime / "plan.json").write_text('{"rankedFiles": []}', encoding="utf-8")
    (tmp_path / "work.json").write_text('{"rankedFiles": [{"path": "a", "score": 1}]}', encoding="utf-8")
    node = _schema_node(
        [
            {"kind": "file_json_schema", "path": "plan.json", "schema": RANK_SCHEMA},
            {"kind": "file_json_schema", "path": "work.json", "schema": RANK_SCHEMA, "root": "workdir"},
        ]
    )

    passed, messages = evaluate_success(
        node,
        NodeResult(node_id="rank"),
        tmp_path,
        runtime_dir=runtime,
        attempt_started_at=_attempt_started_seconds_ago(5),
    )

    assert passed is True
    assert messages == ["file_json_schema(plan.json)=True", "file_json_schema(work.json)=True"]


def test_file_json_schema_rejects_stale_missing_and_invalid_files(tmp_path: Path):
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    stale = runtime / "stale.json"
    stale.write_text('{"rankedFiles": []}', encoding="utf-8")
    an_hour_ago = time.time() - 3600
    os.utime(stale, (an_hour_ago, an_hour_ago))
    (runtime / "broken.json").write_text("{not json", encoding="utf-8")
    (runtime / "empty.json").write_text("\n", encoding="utf-8")
    (runtime / "wrong.json").write_text('{"rankedFiles": "no"}', encoding="utf-8")
    node = _schema_node(
        [
            {"kind": "file_json_schema", "path": "stale.json", "schema": RANK_SCHEMA},
            {"kind": "file_json_schema", "path": "missing.json", "schema": RANK_SCHEMA},
            {"kind": "file_json_schema", "path": "broken.json", "schema": RANK_SCHEMA},
            {"kind": "file_json_schema", "path": "empty.json", "schema": RANK_SCHEMA},
            {"kind": "file_json_schema", "path": "wrong.json", "schema": RANK_SCHEMA},
        ]
    )

    passed, messages = evaluate_success(
        node,
        NodeResult(node_id="rank"),
        tmp_path,
        runtime_dir=runtime,
        attempt_started_at=_attempt_started_seconds_ago(5),
    )

    assert passed is False
    assert messages == [
        "file_json_schema(stale.json)=False: file was not modified during this attempt",
        "file_json_schema(missing.json)=False: file not found",
        "file_json_schema(broken.json)=False: file is not valid JSON: "
        "Expecting property name enclosed in double quotes at line 1 column 2",
        "file_json_schema(empty.json)=False: file is empty",
        "file_json_schema(wrong.json)=False: 1 error(s): /rankedFiles: 'no' is not of type 'array'",
    ]


def test_file_json_schema_can_accept_files_written_before_the_attempt(tmp_path: Path):
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    stale = runtime / "plan.json"
    stale.write_text('{"rankedFiles": []}', encoding="utf-8")
    an_hour_ago = time.time() - 3600
    os.utime(stale, (an_hour_ago, an_hour_ago))
    relaxed = _schema_node(
        [{"kind": "file_json_schema", "path": "plan.json", "schema": RANK_SCHEMA, "modified_in_attempt": False}]
    )
    strict = _schema_node([{"kind": "file_json_schema", "path": "plan.json", "schema": RANK_SCHEMA}])

    assert evaluate_success(
        relaxed,
        NodeResult(node_id="rank"),
        tmp_path,
        runtime_dir=runtime,
        attempt_started_at=_attempt_started_seconds_ago(5),
    ) == (True, ["file_json_schema(plan.json)=True"])
    # Without an attempt timestamp there is nothing to compare against.
    assert evaluate_success(strict, NodeResult(node_id="rank"), tmp_path, runtime_dir=runtime) == (
        True,
        ["file_json_schema(plan.json)=True"],
    )


def test_file_json_schema_needs_a_runtime_dir_for_the_runtime_root(tmp_path: Path):
    node = _schema_node([{"kind": "file_json_schema", "path": "plan.json", "schema": RANK_SCHEMA}])

    passed, messages = evaluate_success(node, NodeResult(node_id="rank"), tmp_path)

    assert passed is False
    assert messages == ["file_json_schema(plan.json)=False: runtime directory is unknown"]


def test_json_schema_criteria_reject_invalid_schemas():
    with pytest.raises(ValueError, match="output_json_schema schema is not a valid JSON Schema"):
        _schema_node([{"kind": "output_json_schema", "schema": {"type": "nope"}}])
    with pytest.raises(ValueError, match="file_json_schema schema is not a valid JSON Schema"):
        _schema_node([{"kind": "file_json_schema", "path": "x.json", "schema": {"required": "id"}}])


def test_json_schema_criteria_round_trip_through_persisted_node_specs():
    node = _schema_node([{"kind": "output_json_schema", "schema": RANK_SCHEMA}])

    assert node.success_criteria[0].json_schema == RANK_SCHEMA
    assert node.model_dump(mode="json", by_alias=True)["success_criteria"][0]["schema"] == RANK_SCHEMA
    reloaded = NodeSpec.model_validate(node.model_dump(mode="json"))
    assert reloaded.success_criteria[0].json_schema == RANK_SCHEMA
