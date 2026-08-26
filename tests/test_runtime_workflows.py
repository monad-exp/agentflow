from __future__ import annotations

import asyncio
import json
import socket
from pathlib import Path

import pytest

from agentflow.agents.registry import AdapterRegistry
from agentflow.agents.base import AgentAdapter
from agentflow.orchestrator import Orchestrator
from agentflow.prepared import ExecutionPaths, PreparedExecution
from agentflow.runners.registry import RunnerRegistry
from agentflow.specs import AgentKind, NodeStatus, PipelineSpec
from agentflow.store import RunStore

from tests.test_orchestrator import MockAdapter


class DurableRetryAdapter(AgentAdapter):
    def prepare(self, node, prompt: str, paths: ExecutionPaths) -> PreparedExecution:
        script = r'''
import json
import sys
from pathlib import Path

marker = Path(sys.argv[1])
prompt = sys.argv[2]
if not marker.exists():
    marker.write_text("failed", encoding="utf-8")
    raise SystemExit(1)
print(json.dumps({
    "type": "response.output_item.done",
    "item": {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": prompt}]},
}))
'''
        return PreparedExecution(
            command=["python3", "-c", script, str(Path(paths.host_workdir) / ".durable-retry"), prompt],
            env={},
            cwd=paths.target_workdir,
            trace_kind="codex",
        )


def _orchestrator(tmp_path: Path) -> Orchestrator:
    adapters = AdapterRegistry()
    adapters.register(AgentKind.CODEX, MockAdapter())
    adapters.register(AgentKind.CLAUDE, MockAdapter())
    adapters.register(AgentKind.PI, MockAdapter())
    return Orchestrator(
        store=RunStore(tmp_path / "runs"),
        adapters=adapters,
        runners=RunnerRegistry(),
    )


@pytest.mark.asyncio
async def test_runtime_fanout_expands_json_collection_and_waits_for_every_member(tmp_path: Path):
    orchestrator = _orchestrator(tmp_path)
    pipeline = PipelineSpec.model_validate(
        {
            "name": "runtime-fanout",
            "working_dir": str(tmp_path),
            "concurrency": 4,
            "nodes": [
                {
                    "id": "rank",
                    "agent": "codex",
                    "prompt": '{"targets":[{"path":"api.py"},{"path":"auth.py"}]}',
                    "output_schema": {
                        "type": "object",
                        "required": ["targets"],
                        "properties": {"targets": {"type": "array"}},
                    },
                },
                {
                    "id": "hunt",
                    "agent": "codex",
                    "prompt": "hunt {{ item.path }}",
                    "fanout_from": {"from": "rank", "path": "targets", "as": "target"},
                    "input_schema": {
                        "type": "object",
                        "required": ["path"],
                        "properties": {"path": {"type": "string"}},
                    },
                },
                {
                    "id": "deduplicate",
                    "agent": "codex",
                    "depends_on": ["hunt"],
                    "prompt": (
                        "{% for lead in fanouts.hunt.nodes %}"
                        "{{ lead.path }}={{ lead.output }};"
                        "{% endfor %}"
                    ),
                },
            ],
        }
    )

    submitted = await orchestrator.submit(pipeline)
    completed = await orchestrator.wait(submitted.id, timeout=5)

    assert completed.status.value == "completed"
    assert completed.pipeline.fanouts["hunt"] == ["hunt_0", "hunt_1"]
    assert completed.nodes["hunt"].status == NodeStatus.COMPLETED
    assert completed.nodes["hunt_0"].output.startswith("hunt api.py")
    assert completed.nodes["hunt_1"].output.startswith("hunt auth.py")
    assert "api.py=hunt api.py" in completed.nodes["deduplicate"].output
    assert "auth.py=hunt auth.py" in completed.nodes["deduplicate"].output


@pytest.mark.asyncio
async def test_runtime_fanin_completes_after_failed_member_so_mandatory_review_runs(tmp_path: Path):
    orchestrator = _orchestrator(tmp_path)
    pipeline = PipelineSpec.model_validate(
        {
            "name": "all-terminal-fanin",
            "working_dir": str(tmp_path),
            "nodes": [
                {
                    "id": "rank",
                    "agent": "codex",
                    "prompt": '{"targets":[{"path":"api.py"}]}',
                },
                {
                    "id": "hunt",
                    "agent": "codex",
                    "prompt": "not-json",
                    "fanout_from": {"from": "rank", "path": "targets"},
                    "output_schema": {"type": "object"},
                },
                {
                    "id": "mandatory_review",
                    "agent": "codex",
                    "depends_on": ["hunt"],
                    "prompt": "reviewed despite failed hunt",
                },
            ],
        }
    )

    submitted = await orchestrator.submit(pipeline)
    completed = await orchestrator.wait(submitted.id, timeout=5)

    assert completed.status.value == "failed"
    assert completed.nodes["hunt_0"].status == NodeStatus.FAILED
    assert completed.nodes["hunt"].status == NodeStatus.COMPLETED
    assert completed.nodes["mandatory_review"].status == NodeStatus.COMPLETED


@pytest.mark.asyncio
async def test_runtime_fanin_preserves_timed_out_member_and_runs_downstream(tmp_path: Path):
    orchestrator = _orchestrator(tmp_path)
    pipeline = PipelineSpec.model_validate(
        {
            "name": "timed-out-fanin",
            "working_dir": str(tmp_path),
            "nodes": [
                {"id": "rank", "agent": "codex", "prompt": "[null]"},
                {
                    "id": "hunt",
                    "agent": "python",
                    "prompt": "import time; time.sleep(2)",
                    "timeout_seconds": 1,
                    "fanout_from": {"from": "rank"},
                },
                {
                    "id": "deduplicate",
                    "agent": "codex",
                    "depends_on": ["hunt"],
                    "prompt": "dedup after timeout",
                },
            ],
        }
    )

    submitted = await orchestrator.submit(pipeline)
    completed = await orchestrator.wait(submitted.id, timeout=6)

    assert completed.status.value == "failed"
    assert completed.nodes["hunt_0"].status == NodeStatus.TIMED_OUT
    assert completed.nodes["hunt"].status == NodeStatus.COMPLETED
    assert completed.nodes["deduplicate"].status == NodeStatus.COMPLETED
    assert any(
        event.type == "node_timed_out" and event.node_id == "hunt_0"
        for event in orchestrator.store.get_events(completed.id)
    )


@pytest.mark.asyncio
async def test_runtime_fanout_rejects_member_id_collisions(tmp_path: Path):
    orchestrator = _orchestrator(tmp_path)
    pipeline = PipelineSpec.model_validate(
        {
            "name": "runtime-id-collision",
            "working_dir": str(tmp_path),
            "nodes": [
                {"id": "rank", "agent": "codex", "prompt": '[{"path":"api.py"}]'},
                {
                    "id": "hunt",
                    "agent": "codex",
                    "prompt": "hunt",
                    "fanout_from": {"from": "rank"},
                },
                {"id": "hunt_0", "agent": "codex", "prompt": "preexisting"},
            ],
        }
    )

    submitted = await orchestrator.submit(pipeline)
    completed = await orchestrator.wait(submitted.id, timeout=5)

    assert completed.status.value == "failed"
    assert completed.nodes["hunt"].status == NodeStatus.FAILED
    assert "already exist" in completed.nodes["hunt"].success_details[0]


@pytest.mark.asyncio
async def test_output_contract_failure_is_a_node_failure(tmp_path: Path):
    orchestrator = _orchestrator(tmp_path)
    pipeline = PipelineSpec.model_validate(
        {
            "name": "contract-failure",
            "working_dir": str(tmp_path),
            "nodes": [
                {
                    "id": "rank",
                    "agent": "codex",
                    "prompt": '{"targets":"not-an-array"}',
                    "output_schema": {
                        "type": "object",
                        "required": ["targets"],
                        "properties": {"targets": {"type": "array"}},
                    },
                }
            ],
        }
    )

    submitted = await orchestrator.submit(pipeline)
    completed = await orchestrator.wait(submitted.id, timeout=5)

    assert completed.status.value == "failed"
    assert completed.nodes["rank"].status == NodeStatus.FAILED
    assert any("is not of type 'array'" in detail for detail in completed.nodes["rank"].success_details)


@pytest.mark.asyncio
async def test_named_concurrency_pool_limits_provider_parallelism(tmp_path: Path):
    orchestrator = _orchestrator(tmp_path)
    pipeline = PipelineSpec.model_validate(
        {
            "name": "provider-pool",
            "working_dir": str(tmp_path),
            "concurrency": 2,
            "concurrency_pools": {"codex-provider": 1},
            "nodes": [
                {
                    "id": "alpha",
                    "agent": "codex",
                    "prompt": "alpha",
                    "concurrency_pool": "codex-provider",
                },
                {
                    "id": "beta",
                    "agent": "codex",
                    "prompt": "beta",
                    "concurrency_pool": "codex-provider",
                },
            ],
        }
    )

    started = asyncio.get_running_loop().time()
    submitted = await orchestrator.submit(pipeline)
    completed = await orchestrator.wait(submitted.id, timeout=5)
    elapsed = asyncio.get_running_loop().time() - started

    assert completed.status.value == "completed"
    assert elapsed >= 0.45


def _available_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@pytest.mark.asyncio
async def test_connector_command_is_run_scoped_and_injected_without_database_env(
    tmp_path: Path,
    monkeypatch,
):
    port = _available_port()
    monkeypatch.setenv("BUGDB_SOURCE_URL", "postgresql://application-role")
    orchestrator = _orchestrator(tmp_path)
    pipeline = PipelineSpec.model_validate(
        {
            "name": "connector-lifecycle",
            "working_dir": str(tmp_path),
            "connectors": [
                {
                    "name": "bugdb",
                    "url": f"http://127.0.0.1:{port}/mcp",
                    "command": "python3",
                    "args": ["-m", "http.server", str(port), "--bind", "127.0.0.1"],
                    "env_from": {"DATABASE_URL": "BUGDB_SOURCE_URL"},
                    "tools": [
                        {
                            "name": "list_hunts_and_leads",
                            "description": "List durable Hunts and Leads",
                            "input_schema": {"type": "object"},
                        }
                    ],
                }
            ],
            "nodes": [
                {
                    "id": "deduplicate",
                    "agent": "python",
                    "prompt": (
                        "import os; print('DATABASE_URL=%s BUGDB_SOURCE_URL=%s' % "
                        "(os.getenv('DATABASE_URL'), os.getenv('BUGDB_SOURCE_URL')))"
                    ),
                    "connectors": ["bugdb"],
                }
            ],
        }
    )

    submitted = await orchestrator.submit(pipeline)
    completed = await orchestrator.wait(submitted.id, timeout=5)

    assert completed.status.value == "completed"
    node = completed.pipeline.node_map["deduplicate"]
    assert node.mcps[0].name == "bugdb"
    assert "DATABASE_URL" not in node.env
    assert completed.nodes["deduplicate"].output == "DATABASE_URL=None BUGDB_SOURCE_URL=None"
    event_types = [event.type for event in orchestrator.store.get_events(completed.id)]
    assert "connectors_ready" in event_types
    assert "connectors_stopped" in event_types
    with pytest.raises(OSError):
        await asyncio.open_connection("127.0.0.1", port)


@pytest.mark.asyncio
async def test_connector_stops_when_node_process_cannot_launch(tmp_path: Path):
    port = _available_port()
    orchestrator = Orchestrator(
        store=RunStore(tmp_path / "runs"),
        adapters=AdapterRegistry(),
        runners=RunnerRegistry(),
    )
    pipeline = PipelineSpec.model_validate(
        {
            "name": "connector-crash-cleanup",
            "working_dir": str(tmp_path),
            "connectors": [
                {
                    "name": "bugdb",
                    "url": f"http://127.0.0.1:{port}/mcp",
                    "command": "python3",
                    "args": ["-m", "http.server", str(port), "--bind", "127.0.0.1"],
                }
            ],
            "nodes": [
                {
                    "id": "cannot_launch",
                    "agent": "codex",
                    "executable": "/definitely/missing/codex",
                    "prompt": "fail before launch",
                    "connectors": ["bugdb"],
                }
            ],
        }
    )

    submitted = await orchestrator.submit(pipeline)
    completed = await orchestrator.wait(submitted.id, timeout=5)

    assert completed.status.value == "failed"
    assert "node execution crashed" in completed.nodes["cannot_launch"].success_details[0]
    with pytest.raises(OSError):
        await asyncio.open_connection("127.0.0.1", port)


@pytest.mark.asyncio
async def test_connector_backed_fanout_uses_durable_ids_and_writes_report_artifacts(tmp_path: Path):
    port = _available_port()
    server_script = r'''
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        payload = ["hunt-file", "hunt-threat", "hunt-exhausted"] if self.path.endswith("/hunts") else ["finding-cross-file"]
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *_args):
        pass

HTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
'''
    orchestrator = _orchestrator(tmp_path)
    pipeline = PipelineSpec.model_validate(
        {
            "name": "durable-bugfinder-fixture",
            "working_dir": str(tmp_path),
            "fail_fast": False,
            "source_snapshot": {
                "repositoryUrl": "https://example.test/owner/repository.git",
                "inputRef": "main",
                "commitSha": "0123456789abcdef0123456789abcdef01234567",
            },
            "connectors": [
                {
                    "name": "bugdb",
                    "url": f"http://127.0.0.1:{port}/mcp",
                    "control_url": f"http://127.0.0.1:{port}/orchestration",
                    "command": "python3",
                    "args": ["-c", server_script, str(port)],
                    "tools": [
                        {
                            "name": "get_hunt",
                            "description": "Read injected Hunt",
                            "input_schema": {"type": "object"},
                        },
                        {
                            "name": "get_finding",
                            "description": "Read injected Finding",
                            "input_schema": {"type": "object"},
                        },
                    ],
                }
            ],
            "nodes": [
                {"id": "rank", "agent": "codex", "prompt": "planner stdout is not durable JSON"},
                {"id": "threat", "agent": "codex", "prompt": "threat planning complete"},
                {"id": "roam", "agent": "codex", "prompt": "roam planning complete"},
                {
                    "id": "hunt",
                    "agent": "codex",
                    "depends_on": ["rank", "threat", "roam"],
                    "prompt": "hunt through injected connector scope",
                    "connectors": ["bugdb"],
                    "fanout_from": {
                        "from": "rank",
                        "connector": "bugdb",
                        "resource": "hunts",
                        "as": "hunt",
                    },
                },
                {
                    "id": "deduplicate",
                    "agent": "codex",
                    "depends_on": ["hunt"],
                    "prompt": "deduplicate from bugdb only",
                    "connectors": ["bugdb"],
                },
                {
                    "id": "triage",
                    "agent": "codex",
                    "prompt": "triage injected finding",
                    "connectors": ["bugdb"],
                    "fanout_from": {
                        "from": "deduplicate",
                        "connector": "bugdb",
                        "resource": "findings",
                    },
                },
                {
                    "id": "rereview",
                    "agent": "codex",
                    "prompt": "mandatory independent rereview",
                    "connectors": ["bugdb"],
                    "fanout_from": {
                        "from": "triage",
                        "connector": "bugdb",
                        "resource": "findings",
                    },
                },
                {
                    "id": "report",
                    "agent": "codex",
                    "prompt": "# Finding report\n\nDerived disposition: CONFIRMED",
                    "connectors": ["bugdb"],
                    "output_artifact": "report.md",
                    "fanout_from": {
                        "from": "rereview",
                        "connector": "bugdb",
                        "resource": "findings",
                    },
                },
            ],
        }
    )

    submitted = await orchestrator.submit(pipeline)
    completed = await orchestrator.wait(submitted.id, timeout=8)

    assert completed.status.value == "completed"
    assert completed.pipeline.fanouts["hunt"] == ["hunt_0", "hunt_1", "hunt_2"]
    assert completed.nodes["hunt"].status == NodeStatus.COMPLETED
    assert completed.nodes["deduplicate"].status == NodeStatus.COMPLETED
    assert completed.nodes["rereview_0"].status == NodeStatus.COMPLETED
    assert completed.nodes["report_0"].status == NodeStatus.COMPLETED
    assert completed.pipeline.node_map["hunt_0"].input is None
    assert "hunt-file" not in (completed.nodes["hunt_0"].output or "")

    report = orchestrator.store.read_artifact_text(completed.id, "report_0", "report.md")
    assert report.startswith("# Finding report")
    snapshot_path = orchestrator.store.run_artifact_dir(completed.id) / "source-snapshot.json"
    assert json.loads(snapshot_path.read_text(encoding="utf-8"))["commitSha"].startswith("01234567")

    member = completed.pipeline.node_map["hunt_0"]
    headers = member.connector_bindings[0].headers
    assert headers["x-agentflow-item-id"] == "hunt-file"
    assert len(headers["x-agentflow-item-signature"]) == 64
    assert member.mcps[0].headers == {}
    persisted_run = (orchestrator.store.run_dir(completed.id) / "run.json").read_text(encoding="utf-8")
    assert headers["x-agentflow-item-signature"] not in persisted_run


@pytest.mark.asyncio
async def test_supervised_durable_goal_retries_from_connector_checkpoint(tmp_path: Path):
    adapters = AdapterRegistry()
    adapters.register(AgentKind.CODEX, DurableRetryAdapter())
    orchestrator = Orchestrator(
        store=RunStore(tmp_path / "runs"),
        adapters=adapters,
        runners=RunnerRegistry(),
    )
    pipeline = PipelineSpec.model_validate(
        {
            "name": "durable-resume",
            "working_dir": str(tmp_path),
            "nodes": [
                {
                    "id": "hunt",
                    "agent": "codex",
                    "prompt": "continue the hunt",
                    "retries": 1,
                    "retry_backoff_seconds": 0,
                    "durable_goal": {"mode": "supervised"},
                }
            ],
        }
    )

    submitted = await orchestrator.submit(pipeline)
    completed = await orchestrator.wait(submitted.id, timeout=5)

    assert completed.status.value == "completed"
    assert len(completed.nodes["hunt"].attempts) == 2
    assert "AgentFlow supervised durable-goal resume" in (completed.nodes["hunt"].output or "")
    checkpoint = orchestrator.store.read_artifact_text(
        completed.id,
        "hunt",
        "durable-goal-checkpoint-attempt-1.json",
    )
    assert json.loads(checkpoint)["resumeMode"] == "supervised"
