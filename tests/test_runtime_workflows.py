from __future__ import annotations

import asyncio
import json
import subprocess
from pathlib import Path
from urllib.parse import urlparse

import pytest

from agentflow.agents.registry import AdapterRegistry
from agentflow.agents.base import AgentAdapter
from agentflow.orchestrator import Orchestrator
from agentflow.prepared import ExecutionPaths, PreparedExecution
from agentflow.runners.registry import RunnerRegistry
from agentflow.specs import (
    AgentKind,
    NodeAttempt,
    NodeResult,
    NodeStatus,
    PipelineSpec,
    RunRecord,
    RunStatus,
    SourceSnapshotSpec,
    expand_runtime_fanout_node,
)
from agentflow.store import RunStore

from tests.test_orchestrator import MockAdapter
from tests.test_connectors import SERVER as CONNECTOR_SERVER


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


class FanoutRetryAdapter(AgentAdapter):
    def prepare(self, node, prompt: str, paths: ExecutionPaths) -> PreparedExecution:
        script = r'''
import json
import sys
from pathlib import Path

node_id = sys.argv[1]
prompt = sys.argv[2]
marker = Path(sys.argv[3])
if node_id == "hunt_0":
    if not marker.exists():
        marker.write_text("started", encoding="utf-8")
        raise SystemExit(1)
    marker.write_text("completed", encoding="utf-8")
if node_id in {"deduplicate", "report"} and (
    not marker.exists() or marker.read_text(encoding="utf-8") != "completed"
):
    raise SystemExit(2)
print(json.dumps({
    "type": "response.output_item.done",
    "item": {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": prompt}]},
}))
'''
        return PreparedExecution(
            command=[
                "python3",
                "-c",
                script,
                node.id,
                prompt,
                str(Path(paths.host_workdir) / ".fanout-retry"),
            ],
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
                },
                {
                    "id": "hunt",
                    "agent": "codex",
                    "prompt": "hunt {{ item.path }}",
                    "fanout_from": {"from": "rank", "path": "targets", "as": "target"},
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
    assert pipeline.fanouts == {}
    assert [node.id for node in pipeline.nodes] == ["rank", "hunt", "deduplicate"]
    assert completed.declared_pipeline is not None
    assert completed.declared_pipeline.fanouts == {}


@pytest.mark.asyncio
async def test_runtime_fanout_does_not_settle_during_member_retry_backoff(tmp_path: Path):
    adapters = AdapterRegistry()
    adapters.register(AgentKind.CODEX, FanoutRetryAdapter())
    orchestrator = Orchestrator(
        store=RunStore(tmp_path / "runs"),
        adapters=adapters,
        runners=RunnerRegistry(),
    )
    pipeline = PipelineSpec.model_validate(
        {
            "name": "runtime-fanout-retry",
            "working_dir": str(tmp_path),
            "concurrency": 3,
            "nodes": [
                {"id": "rank", "agent": "codex", "prompt": '[{"path":"api.py"}]'},
                {
                    "id": "hunt",
                    "agent": "codex",
                    "prompt": "hunt {{ item.path }}",
                    "retries": 1,
                    "retry_backoff_seconds": 0.5,
                    "fanout_from": {"from": "rank"},
                },
                {
                    "id": "deduplicate",
                    "agent": "codex",
                    "prompt": "deduplicated",
                    "depends_on": ["hunt"],
                },
            ],
        }
    )

    submitted = await orchestrator.submit(pipeline)
    completed = await orchestrator.wait(submitted.id, timeout=5)

    assert completed.status == RunStatus.COMPLETED
    assert [attempt.status for attempt in completed.nodes["hunt_0"].attempts] == [
        NodeStatus.FAILED,
        NodeStatus.COMPLETED,
    ]
    assert completed.nodes["hunt"].status == NodeStatus.COMPLETED
    assert completed.nodes["deduplicate"].status == NodeStatus.COMPLETED
    events = orchestrator.store.get_events(completed.id)
    member_completed = next(
        index
        for index, event in enumerate(events)
        if event.type == "node_completed" and event.node_id == "hunt_0"
    )
    downstream_started = next(
        index
        for index, event in enumerate(events)
        if event.type == "node_started" and event.node_id == "deduplicate"
    )
    assert member_completed < downstream_started


@pytest.mark.asyncio
async def test_runtime_fanout_is_independent_across_submissions_reruns_and_reload(tmp_path: Path):
    orchestrator = _orchestrator(tmp_path)
    pipeline = PipelineSpec.model_validate(
        {
            "name": "run-local-fanout",
            "working_dir": str(tmp_path),
            "nodes": [
                {"id": "rank", "agent": "codex", "prompt": '[{"path":"api.py"}]'},
                {
                    "id": "hunt",
                    "agent": "codex",
                    "prompt": "hunt {{ item.path }}",
                    "fanout_from": {"from": "rank"},
                },
            ],
        }
    )

    first, second = await asyncio.gather(orchestrator.submit(pipeline), orchestrator.submit(pipeline))
    first_done, second_done = await asyncio.gather(
        orchestrator.wait(first.id, timeout=5),
        orchestrator.wait(second.id, timeout=5),
    )
    rerun = await orchestrator.rerun(first_done.id)
    rerun_done = await orchestrator.wait(rerun.id, timeout=5)

    assert pipeline.fanouts == {}
    assert [node.id for node in pipeline.nodes] == ["rank", "hunt"]
    for record in (first_done, second_done, rerun_done):
        assert record.status == RunStatus.COMPLETED
        assert record.pipeline.fanouts["hunt"] == ["hunt_0"]
        assert record.nodes["hunt"].structured_output == [{"path": "api.py"}]
        assert record.declared_pipeline is not None
        assert record.declared_pipeline.fanouts == {}
        assert [node.id for node in record.declared_pipeline.nodes] == ["rank", "hunt"]

    reloaded = RunStore(orchestrator.store.base_dir).get_run(first_done.id)
    assert reloaded.pipeline.fanouts["hunt"] == ["hunt_0"]
    assert reloaded.pipeline.node_map["hunt_0"].fanout_member is not None
    assert reloaded.pipeline.node_map["hunt_0"].fanout_member["path"] == "api.py"


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
                    "success_criteria": [{"kind": "output_contains", "value": "expected-marker"}],
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


def test_node_stdout_contracts_are_not_part_of_the_pipeline_api(tmp_path: Path):
    with pytest.raises(ValueError, match="output_schema"):
        PipelineSpec.model_validate(
            {
                "name": "no-stdout-contract",
                "working_dir": str(tmp_path),
                "nodes": [
                    {
                        "id": "rank",
                        "agent": "codex",
                        "prompt": "rank",
                        "output_schema": {"type": "object"},
                    }
                ],
            }
        )


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


@pytest.mark.asyncio
async def test_named_pool_is_acquired_before_global_capacity(tmp_path: Path, monkeypatch):
    acquisition_order: list[str] = []

    class RecordingSemaphore:
        def __init__(self, value: int):
            self.name = "global" if value == 2 else "pool"

        async def __aenter__(self):
            acquisition_order.append(self.name)
            return self

        async def __aexit__(self, *_args):
            return None

        async def acquire(self):
            acquisition_order.append(self.name)

        def release(self):
            return None

    monkeypatch.setattr("agentflow.orchestrator.asyncio.Semaphore", RecordingSemaphore)
    orchestrator = _orchestrator(tmp_path)
    pipeline = PipelineSpec.model_validate(
        {
            "name": "pool-order",
            "working_dir": str(tmp_path),
            "concurrency": 2,
            "concurrency_pools": {"provider": 1},
            "nodes": [
                {
                    "id": "only",
                    "agent": "codex",
                    "prompt": "done",
                    "concurrency_pool": "provider",
                }
            ],
        }
    )

    submitted = await orchestrator.submit(pipeline)
    completed = await orchestrator.wait(submitted.id, timeout=5)

    assert completed.status == RunStatus.COMPLETED
    assert acquisition_order[:2] == ["pool", "global"]


def _git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


@pytest.mark.asyncio
async def test_source_input_resolves_to_one_shared_detached_worktree(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    _git(repo, "config", "user.email", "tests@example.test")
    _git(repo, "config", "user.name", "AgentFlow Tests")
    (repo / "source.txt").write_text("pinned\n", encoding="utf-8")
    _git(repo, "add", "source.txt")
    _git(repo, "commit", "-q", "-m", "source")
    commit_sha = _git(repo, "rev-parse", "HEAD")

    orchestrator = _orchestrator(tmp_path)
    pipeline = PipelineSpec.model_validate(
        {
            "name": "pinned-source",
            "working_dir": str(repo),
            "source_snapshot": {
                "repositoryUrl": "https://example.test/owner/repository.git",
                "inputRef": "HEAD",
            },
            "nodes": [
                {
                    "id": node_id,
                    "agent": "python",
                    "prompt": (
                        "import os, subprocess; "
                        "print(os.getcwd()); "
                        "print(subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip())"
                    ),
                }
                for node_id in ("first", "second")
            ],
        }
    )

    submitted = await orchestrator.submit(pipeline)
    completed = await orchestrator.wait(submitted.id, timeout=5)

    assert completed.status == RunStatus.COMPLETED
    assert completed.source_snapshot is not None
    assert completed.source_snapshot.commit_sha == commit_sha
    assert completed.source_snapshot.input_ref == "HEAD"
    workdirs = {
        (completed.nodes[node_id].output or "").splitlines()[0]
        for node_id in ("first", "second")
    }
    assert len(workdirs) == 1
    workdir = Path(workdirs.pop())
    assert workdir.name == "source"
    assert not workdir.exists()
    assert completed.declared_pipeline is not None
    assert completed.declared_pipeline.working_path == repo.resolve()
    assert pipeline.working_path == repo.resolve()
    snapshot = json.loads(
        (orchestrator.store.run_artifact_dir(completed.id) / "source-snapshot.json").read_text(
            encoding="utf-8"
        )
    )
    assert snapshot == {
        "repositoryUrl": "https://example.test/owner/repository.git",
        "inputRef": "HEAD",
        "commitSha": commit_sha,
    }


@pytest.mark.asyncio
async def test_source_invalid_ref_fails_before_nodes(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    _git(repo, "config", "user.email", "tests@example.test")
    _git(repo, "config", "user.name", "AgentFlow Tests")
    (repo / "source.txt").write_text("source\n", encoding="utf-8")
    _git(repo, "add", "source.txt")
    _git(repo, "commit", "-q", "-m", "source")

    orchestrator = _orchestrator(tmp_path)
    pipeline = PipelineSpec.model_validate(
        {
            "name": "wrong-source",
            "working_dir": str(repo),
            "source_snapshot": {
                "repositoryUrl": "https://example.test/repository.git",
                "inputRef": "refs/heads/missing",
            },
            "nodes": [{"id": "never", "agent": "codex", "prompt": "never"}],
        }
    )

    submitted = await orchestrator.submit(pipeline)
    completed = await orchestrator.wait(submitted.id, timeout=5)

    assert completed.status == RunStatus.FAILED
    assert completed.nodes["never"].status == NodeStatus.SKIPPED
    assert any(event.type == "source_snapshot_failed" for event in orchestrator.store.get_events(completed.id))


@pytest.mark.asyncio
async def test_connector_command_is_run_scoped_and_injected_without_database_env(
    tmp_path: Path,
    monkeypatch,
):
    monkeypatch.setenv("BUGDB_SOURCE_URL", "postgresql://application-role")
    orchestrator = _orchestrator(tmp_path)
    pipeline = PipelineSpec.model_validate(
        {
            "name": "connector-lifecycle",
            "working_dir": str(tmp_path),
            "connectors": [
                {
                    "name": "bugdb",
                    "url": "http://127.0.0.1:{port}/mcp",
                    "command": "python3",
                    "args": ["-c", CONNECTOR_SERVER],
                    "env": {"TEST_CONNECTOR_PORT": "{port}"},
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
    assert node.mcps == []
    assert node.connector_bindings[0].name == "bugdb"
    assert "DATABASE_URL" not in node.env
    assert completed.nodes["deduplicate"].output == "DATABASE_URL=None BUGDB_SOURCE_URL=None"
    event_types = [event.type for event in orchestrator.store.get_events(completed.id)]
    assert "connectors_ready" in event_types
    assert "connectors_stopped" in event_types
    port = urlparse(node.connector_bindings[0].url).port
    assert port is not None
    with pytest.raises(OSError):
        await asyncio.open_connection("127.0.0.1", port)


@pytest.mark.asyncio
async def test_connector_stops_when_node_process_cannot_launch(tmp_path: Path):
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
                    "url": "http://127.0.0.1:{port}/mcp",
                    "command": "python3",
                    "args": ["-c", CONNECTOR_SERVER],
                    "env": {"TEST_CONNECTOR_PORT": "{port}"},
                    "tools": [{
                        "name": "noop",
                        "description": "No-op fixture tool",
                        "input_schema": {"type": "object"},
                    }],
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
    binding = completed.pipeline.node_map["cannot_launch"].connector_bindings[0]
    port = urlparse(binding.url).port
    assert port is not None
    with pytest.raises(OSError):
        await asyncio.open_connection("127.0.0.1", port)


@pytest.mark.asyncio
async def test_connector_stops_when_scheduler_crashes(tmp_path: Path):
    class CrashingOrchestrator(Orchestrator):
        def _register_shared_resources(self, pipeline):
            raise RuntimeError("scheduler crash")

    adapters = AdapterRegistry()
    adapters.register(AgentKind.CODEX, MockAdapter())
    orchestrator = CrashingOrchestrator(
        store=RunStore(tmp_path / "runs"),
        adapters=adapters,
        runners=RunnerRegistry(),
    )
    pipeline = PipelineSpec.model_validate(
        {
            "name": "scheduler-crash-cleanup",
            "working_dir": str(tmp_path),
            "connectors": [
                {
                    "name": "bugdb",
                    "url": "http://127.0.0.1:{port}/mcp",
                    "command": "python3",
                    "args": ["-c", CONNECTOR_SERVER],
                    "env": {"TEST_CONNECTOR_PORT": "{port}"},
                    "tools": [{
                        "name": "noop",
                        "description": "No-op fixture tool",
                        "input_schema": {"type": "object"},
                    }],
                }
            ],
            "nodes": [
                {
                    "id": "never",
                    "agent": "codex",
                    "prompt": "never",
                    "connectors": ["bugdb"],
                }
            ],
        }
    )

    submitted = await orchestrator.submit(pipeline)
    completed = await orchestrator.wait(submitted.id, timeout=5)

    assert completed.status == RunStatus.FAILED
    assert any(event.type == "scheduler_failed" for event in orchestrator.store.get_events(completed.id))
    binding = completed.pipeline.node_map["never"].connector_bindings[0]
    port = urlparse(binding.url).port
    assert port is not None
    with pytest.raises(OSError):
        await asyncio.open_connection("127.0.0.1", port)


@pytest.mark.asyncio
async def test_connector_backed_fanout_uses_durable_ids_and_writes_report_artifacts(tmp_path: Path):
    server_script = r'''
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

run_id = os.environ["AGENTFLOW_RUN_ID"]
nonce = os.environ["AGENTFLOW_CONNECTOR_NONCE"]
control_token = os.environ["AGENTFLOW_CONTROL_TOKEN"]
port = int(os.environ["AGENTFLOW_CONNECTOR_PORT"])

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.headers.get("x-agentflow-control-token") != control_token:
            self.send_response(403)
            self.end_headers()
            return
        if self.path == "/healthz":
            body = json.dumps({"ok": True, "runId": run_id, "nonce": nonce}).encode()
        else:
            body = json.dumps(
                ["hunt-file", "hunt-threat", "hunt-exhausted"]
                if self.path.endswith("/hunts")
                else ["finding-cross-file"]
            ).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *_args):
        pass

HTTPServer(("127.0.0.1", port), Handler).serve_forever()
'''
    orchestrator = _orchestrator(tmp_path)
    pipeline = PipelineSpec.model_validate(
        {
            "name": "durable-bugfinder-fixture",
            "working_dir": str(tmp_path),
            "fail_fast": False,
            "connectors": [
                {
                    "name": "bugdb",
                    "url": "http://127.0.0.1:{port}/mcp",
                    "control_url": "http://127.0.0.1:{port}/orchestration",
                    "command": "python3",
                    "args": ["-c", server_script],
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
    member = completed.pipeline.node_map["hunt_0"]
    headers = member.connector_bindings[0].headers
    assert headers["x-agentflow-item-id"] == "hunt-file"
    assert len(headers["x-agentflow-item-signature"]) == 64
    assert member.mcps == []
    persisted_run = (orchestrator.store.run_dir(completed.id) / "run.json").read_text(encoding="utf-8")
    assert headers["x-agentflow-item-signature"] not in persisted_run


@pytest.mark.asyncio
async def test_connector_backed_fanout_rejects_duplicate_durable_ids(tmp_path: Path):
    class DuplicateConnectorManager:
        async def start(self, _run_id, _pipeline, _run_dir):
            pass

        async def fetch_collection(self, _run_id, _connector, _resource):
            return ["same-hunt", "same-hunt"]

        async def stop(self, _run_id):
            pass

    orchestrator = _orchestrator(tmp_path)
    orchestrator._connector_manager = DuplicateConnectorManager()
    pipeline = PipelineSpec.model_validate(
        {
            "name": "duplicate-durable-fanout",
            "working_dir": str(tmp_path),
            "connectors": [
                {
                    "name": "bugdb",
                    "url": "http://127.0.0.1:{port}/mcp",
                    "control_url": "http://127.0.0.1:{port}/orchestration",
                    "command": "unused",
                }
            ],
            "nodes": [
                {"id": "rank", "agent": "codex", "prompt": "ranked"},
                {
                    "id": "hunt",
                    "agent": "codex",
                    "prompt": "hunt",
                    "fanout_from": {
                        "from": "rank",
                        "connector": "bugdb",
                        "resource": "hunts",
                    },
                },
            ],
        }
    )

    submitted = await orchestrator.submit(pipeline)
    completed = await orchestrator.wait(submitted.id, timeout=5)

    assert completed.status == RunStatus.FAILED
    assert completed.nodes["hunt"].status == NodeStatus.FAILED
    assert "duplicate stable IDs" in completed.nodes["hunt"].success_details[0]


@pytest.mark.asyncio
async def test_resume_rejects_connector_backed_runtime_fanout(tmp_path: Path):
    orchestrator = _orchestrator(tmp_path)
    pipeline = PipelineSpec.model_validate(
        {
            "name": "connector-recovery",
            "working_dir": str(tmp_path),
            "connectors": [
                {
                    "name": "bugdb",
                    "url": "http://127.0.0.1:{port}/mcp",
                    "control_url": "http://127.0.0.1:{port}/orchestration",
                    "command": "python3",
                }
            ],
            "nodes": [
                {"id": "rank", "agent": "codex", "prompt": "rank"},
                {
                    "id": "hunt",
                    "agent": "codex",
                    "prompt": "hunt",
                    "connectors": ["bugdb"],
                    "fanout_from": {
                        "from": "rank",
                        "connector": "bugdb",
                        "resource": "hunts",
                    },
                },
            ],
        }
    )
    failed = RunRecord(
        id=orchestrator.store.new_run_id(),
        status=RunStatus.FAILED,
        pipeline=pipeline.model_copy(deep=True),
        declared_pipeline=pipeline.model_copy(deep=True),
    )
    await orchestrator.store.create_run(failed)

    with pytest.raises(ValueError, match="connector-backed runtime fan-out"):
        await orchestrator.resume(failed.id)


@pytest.mark.asyncio
async def test_resume_rejects_source_pinned_run(tmp_path: Path):
    orchestrator = _orchestrator(tmp_path)
    pipeline = PipelineSpec.model_validate(
        {
            "name": "source-recovery",
            "working_dir": str(tmp_path),
            "source_snapshot": {
                "repositoryUrl": "https://example.test/repository.git",
                "inputRef": "main",
            },
            "nodes": [{"id": "scan", "agent": "codex", "prompt": "scan"}],
        }
    )
    failed = RunRecord(
        id=orchestrator.store.new_run_id(),
        status=RunStatus.FAILED,
        pipeline=pipeline.model_copy(deep=True),
        declared_pipeline=pipeline.model_copy(deep=True),
    )
    await orchestrator.store.create_run(failed)

    with pytest.raises(ValueError, match="source-pinned runs"):
        await orchestrator.resume(failed.id)


@pytest.mark.asyncio
async def test_recover_continues_source_pinned_connector_fanout_in_place(tmp_path: Path):
    class RecoveryConnectorManager:
        def __init__(self):
            self.started: list[str] = []
            self.fetched: list[tuple[str, str, str]] = []
            self.bound: list[tuple[str, str, str]] = []
            self.stopped: list[str] = []

        async def start(self, run_id, _pipeline, _run_dir):
            self.started.append(run_id)

        async def fetch_collection(self, run_id, connector, resource):
            self.fetched.append((run_id, connector, resource))
            return ["hunt-durable", "hunt-appended"]

        def bind_member(self, run_id, node, item_id):
            self.bound.append((run_id, node.id, item_id))

        async def stop(self, run_id):
            self.stopped.append(run_id)

    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    _git(repo, "config", "user.email", "tests@example.test")
    _git(repo, "config", "user.name", "AgentFlow Tests")
    (repo / "source.txt").write_text("pinned\n", encoding="utf-8")
    _git(repo, "add", "source.txt")
    _git(repo, "commit", "-q", "-m", "source")
    commit_sha = _git(repo, "rev-parse", "HEAD")

    adapters = AdapterRegistry()
    adapters.register(AgentKind.CODEX, FanoutRetryAdapter())
    orchestrator = Orchestrator(
        store=RunStore(tmp_path / "runs"),
        adapters=adapters,
        runners=RunnerRegistry(),
    )
    run_id = orchestrator.store.new_run_id()
    from agentflow.worktree import create_pinned_worktree, remove_worktree

    source_worktree = create_pinned_worktree(repo, run_id, commit_sha)
    declared = PipelineSpec.model_validate(
        {
            "name": "recover-connector-source",
            "working_dir": str(repo),
            "source_snapshot": {
                "repositoryUrl": "https://example.test/repository.git",
                "inputRef": "HEAD",
            },
            "connectors": [
                {
                    "name": "bugdb",
                    "url": "http://127.0.0.1:{port}/mcp",
                    "control_url": "http://127.0.0.1:{port}/orchestration",
                    "command": "unused",
                }
            ],
            "nodes": [
                {"id": "rank", "agent": "codex", "prompt": "rank"},
                {
                    "id": "hunt",
                    "agent": "codex",
                    "prompt": "hunt",
                    "retries": 1,
                    "retry_backoff_seconds": 0.5,
                    "depends_on": ["rank"],
                    "connectors": ["bugdb"],
                    "fanout_from": {
                        "from": "rank",
                        "connector": "bugdb",
                        "resource": "hunts",
                    },
                },
                {
                    "id": "report",
                    "agent": "codex",
                    "prompt": "report",
                    "depends_on": ["hunt"],
                },
            ],
        }
    )
    execution = declared.model_copy(deep=True)
    execution.working_dir = str(source_worktree)
    hunt_template = execution.node_map["hunt"]
    members, member_ids = expand_runtime_fanout_node(hunt_template, ["hunt-durable"])
    execution.nodes.extend(members)
    execution.fanouts["hunt"] = member_ids
    source = SourceSnapshotSpec(
        repositoryUrl="https://example.test/repository.git",
        inputRef="HEAD",
        commitSha=commit_sha,
    )
    interrupted_attempt = NodeAttempt(
        number=1,
        status=NodeStatus.RUNNING,
        started_at="2026-01-01T00:00:00+00:00",
    )
    record = RunRecord(
        id=run_id,
        status=RunStatus.RUNNING,
        pipeline=execution,
        declared_pipeline=declared,
        source_snapshot=source,
        nodes={
            "rank": NodeResult(
                node_id="rank",
                status=NodeStatus.RUNNING,
                attempts=[interrupted_attempt.model_copy(deep=True)],
            ),
            "hunt": NodeResult(
                node_id="hunt",
                status=NodeStatus.COMPLETED,
                structured_output=["hunt-durable"],
                success=True,
                finished_at="2026-01-01T00:00:01+00:00",
            ),
            "hunt_0": NodeResult(
                node_id="hunt_0",
                status=NodeStatus.RUNNING,
                attempts=[interrupted_attempt.model_copy(deep=True)],
            ),
            "report": NodeResult(node_id="report", status=NodeStatus.SKIPPED),
        },
    )
    await orchestrator.store.create_run(record)
    await orchestrator.store.write_run_artifact_json(
        run_id,
        "source-snapshot.json",
        source.model_dump(mode="json", by_alias=True),
    )
    remove_worktree(repo, source_worktree)
    assert not source_worktree.exists()
    connector_manager = RecoveryConnectorManager()
    orchestrator._connector_manager = connector_manager

    recovered = await orchestrator.recover(run_id, completed_nodes={"rank"})
    completed = await orchestrator.wait(recovered.id, timeout=5)

    assert recovered.id == run_id
    assert completed.status == RunStatus.COMPLETED
    assert completed.source_snapshot == source
    assert completed.nodes["rank"].status == NodeStatus.COMPLETED
    assert completed.nodes["hunt"].status == NodeStatus.COMPLETED
    assert completed.nodes["hunt_0"].status == NodeStatus.COMPLETED
    assert completed.nodes["hunt_1"].status == NodeStatus.COMPLETED
    assert completed.nodes["report"].status == NodeStatus.COMPLETED
    assert [attempt.number for attempt in completed.nodes["hunt_0"].attempts] == [1, 2, 3]
    assert completed.nodes["hunt_0"].attempts[0].status == NodeStatus.CANCELLED
    assert completed.nodes["hunt_0"].attempts[1].status == NodeStatus.FAILED
    assert completed.nodes["hunt_0"].attempts[2].status == NodeStatus.COMPLETED
    assert connector_manager.started == [run_id]
    assert connector_manager.fetched == [(run_id, "bugdb", "hunts")]
    assert connector_manager.bound == [
        (run_id, "hunt_0", "hunt-durable"),
        (run_id, "hunt_1", "hunt-appended"),
    ]
    assert connector_manager.stopped == [run_id]
    event_types = [event.type for event in orchestrator.store.get_events(run_id)]
    assert "run_recovery_queued" in event_types
    assert "run_recovery_started" in event_types
    assert "node_recovery_completed" in event_types
    assert "source_worktree_recreated" in event_types
    assert "source_snapshot_persisted" not in event_types
    assert not source_worktree.exists()


@pytest.mark.asyncio
async def test_runtime_fanout_refresh_rejects_reordered_stable_ids(tmp_path: Path):
    class ReorderedConnectorManager:
        async def fetch_collection(self, _run_id, _connector, _resource):
            return ["hunt-second", "hunt-first"]

    orchestrator = _orchestrator(tmp_path)
    pipeline = PipelineSpec.model_validate(
        {
            "name": "refresh-prefix",
            "working_dir": str(tmp_path),
            "connectors": [
                {
                    "name": "bugdb",
                    "url": "http://127.0.0.1:{port}/mcp",
                    "control_url": "http://127.0.0.1:{port}/orchestration",
                    "command": "unused",
                }
            ],
            "nodes": [
                {"id": "rank", "agent": "codex", "prompt": "rank"},
                {
                    "id": "hunt",
                    "agent": "codex",
                    "prompt": "hunt",
                    "depends_on": ["rank"],
                    "connectors": ["bugdb"],
                    "fanout_from": {
                        "from": "rank",
                        "connector": "bugdb",
                        "resource": "hunts",
                    },
                },
            ],
        }
    )
    template = pipeline.node_map["hunt"]
    members, member_ids = expand_runtime_fanout_node(template, ["hunt-first", "hunt-second"])
    pipeline.nodes.extend(members)
    pipeline.fanouts["hunt"] = member_ids
    run_id = orchestrator.store.new_run_id()
    record = RunRecord(
        id=run_id,
        status=RunStatus.QUEUED,
        pipeline=pipeline,
        declared_pipeline=pipeline.model_copy(deep=True),
        nodes={
            "rank": NodeResult(node_id="rank", status=NodeStatus.COMPLETED),
            "hunt": NodeResult(node_id="hunt", status=NodeStatus.PENDING),
            **{
                member.id: NodeResult(node_id=member.id, status=NodeStatus.COMPLETED)
                for member in members
            },
        },
    )
    await orchestrator.store.create_run(record)
    orchestrator._connector_manager = ReorderedConnectorManager()

    with pytest.raises(ValueError, match="persisted stable ID prefix"):
        await orchestrator._expand_runtime_fanout(
            run_id,
            template,
            node_map=record.pipeline.node_map,
            remaining={"hunt"},
        )


@pytest.mark.asyncio
async def test_recover_rejects_dirty_pinned_source_worktree(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    _git(repo, "config", "user.email", "tests@example.test")
    _git(repo, "config", "user.name", "AgentFlow Tests")
    (repo / "source.txt").write_text("pinned\n", encoding="utf-8")
    _git(repo, "add", "source.txt")
    _git(repo, "commit", "-q", "-m", "source")
    commit_sha = _git(repo, "rev-parse", "HEAD")

    orchestrator = _orchestrator(tmp_path)
    run_id = orchestrator.store.new_run_id()
    from agentflow.worktree import create_pinned_worktree, remove_worktree

    source_worktree = create_pinned_worktree(repo, run_id, commit_sha)
    declared = PipelineSpec.model_validate(
        {
            "name": "dirty-source-recovery",
            "working_dir": str(repo),
            "source_snapshot": {
                "repositoryUrl": "https://example.test/repository.git",
                "inputRef": "HEAD",
            },
            "nodes": [{"id": "scan", "agent": "codex", "prompt": "scan"}],
        }
    )
    execution = declared.model_copy(deep=True)
    execution.working_dir = str(source_worktree)
    source = SourceSnapshotSpec(
        repositoryUrl="https://example.test/repository.git",
        inputRef="HEAD",
        commitSha=commit_sha,
    )
    record = RunRecord(
        id=run_id,
        status=RunStatus.FAILED,
        pipeline=execution,
        declared_pipeline=declared,
        source_snapshot=source,
        nodes={"scan": NodeResult(node_id="scan", status=NodeStatus.FAILED)},
    )
    await orchestrator.store.create_run(record)
    await orchestrator.store.write_run_artifact_json(
        run_id,
        "source-snapshot.json",
        source.model_dump(mode="json", by_alias=True),
    )
    (source_worktree / "unexpected.txt").write_text("dirty\n", encoding="utf-8")

    try:
        with pytest.raises(ValueError, match="local changes"):
            await orchestrator.recover(run_id)
        assert record.status == RunStatus.FAILED
    finally:
        remove_worktree(repo, source_worktree)


@pytest.mark.asyncio
async def test_run_store_does_not_persist_resolved_connector_urls(tmp_path: Path):
    pipeline = PipelineSpec.model_validate(
        {
            "name": "runtime-url",
            "working_dir": str(tmp_path),
            "connectors": [
                {
                    "name": "bugdb",
                    "url": "http://127.0.0.1:{port}/mcp",
                    "command": "python3",
                }
            ],
            "nodes": [
                {
                    "id": "hunt",
                    "agent": "codex",
                    "prompt": "hunt",
                    "connectors": ["bugdb"],
                    "connector_bindings": [
                        {
                            "name": "bugdb",
                            "url": "http://127.0.0.1:54321/mcp",
                        }
                    ],
                }
            ],
        }
    )
    declared = pipeline.model_copy(deep=True)
    declared.node_map["hunt"].connector_bindings = []
    record = RunRecord(id="runtime-url", pipeline=pipeline, declared_pipeline=declared)
    store = RunStore(tmp_path / "runs")
    await store.create_run(record)

    persisted = (store.run_dir(record.id) / "run.json").read_text(encoding="utf-8")
    assert "http://127.0.0.1:54321/mcp" not in persisted
    assert record.pipeline.node_map["hunt"].connector_bindings[0].url == "http://127.0.0.1:54321/mcp"


@pytest.mark.asyncio
async def test_supervised_durable_goal_retries_from_connector_state(tmp_path: Path):
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
    output = completed.nodes["hunt"].output or ""
    assert "AgentFlow supervised durable-goal resume" in output
    assert "Do not repeat completed work" in output
    assert "persist useful progress incrementally" in output
    assert "before reaching the response limit" in output
    checkpoint = orchestrator.store.artifact_path(
        completed.id, "hunt", "durable-goal-checkpoint-attempt-1.json"
    )
    assert not checkpoint.exists()


@pytest.mark.asyncio
async def test_native_durable_goal_fails_without_a_tested_adapter_integration(tmp_path: Path):
    orchestrator = _orchestrator(tmp_path)
    pipeline = PipelineSpec.model_validate(
        {
            "name": "native-goal",
            "working_dir": str(tmp_path),
            "nodes": [
                {
                    "id": "hunt",
                    "agent": "codex",
                    "prompt": "continue",
                    "durable_goal": {"mode": "native"},
                }
            ],
        }
    )

    submitted = await orchestrator.submit(pipeline)
    completed = await orchestrator.wait(submitted.id, timeout=5)

    assert completed.status == RunStatus.FAILED
    assert "no tested native durable-goal integration" in completed.nodes["hunt"].success_details[0]


@pytest.mark.asyncio
async def test_workflow_deadline_cancels_running_and_pending_nodes(tmp_path: Path):
    orchestrator = _orchestrator(tmp_path)
    pipeline = PipelineSpec.model_validate(
        {
            "name": "workflow-deadline",
            "working_dir": str(tmp_path),
            "deadline_seconds": 1,
            "nodes": [
                {
                    "id": "slow",
                    "agent": "python",
                    "prompt": "import time; time.sleep(5)",
                },
                {
                    "id": "after",
                    "agent": "codex",
                    "prompt": "must not start",
                    "depends_on": ["slow"],
                },
            ],
        }
    )

    submitted = await orchestrator.submit(pipeline)
    completed = await orchestrator.wait(submitted.id, timeout=5)

    assert completed.status == RunStatus.FAILED
    assert completed.nodes["slow"].status == NodeStatus.CANCELLED
    assert completed.nodes["after"].status == NodeStatus.CANCELLED
    assert any(
        event.type == "run_deadline_exceeded"
        for event in orchestrator.store.get_events(completed.id)
    )
