from __future__ import annotations

import json
import os
import socket
from pathlib import Path

import pytest

from agentflow.agents.base import AgentAdapter
from agentflow.agents.registry import AdapterRegistry
from agentflow.orchestrator import Orchestrator
from agentflow.prepared import ExecutionPaths, PreparedExecution
from agentflow.runners.registry import RunnerRegistry
from agentflow.specs import AgentKind, NodeSpec, NodeStatus, PipelineSpec
from agentflow.store import RunStore


DATABASE_URL = os.environ.get("BUGFINDER_TEST_DATABASE_URL")
EXAMPLE_DIR = Path(__file__).resolve().parents[1] / "examples" / "bugfinder"


def _available_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class BugfinderFixtureAdapter(AgentAdapter):
    """Deterministic stand-in agents that use the real scoped connector tools."""

    def prepare(self, node: NodeSpec, prompt: str, paths: ExecutionPaths) -> PreparedExecution:
        binding = node.connector_bindings[0]
        endpoint = binding.url.removesuffix("/mcp") + "/tools/call"
        script = f'''
import json
import urllib.request

endpoint = {endpoint!r}
headers = {json.dumps(binding.headers)!r}
headers = json.loads(headers)
headers["content-type"] = "application/json"

def call(name, arguments):
    request = urllib.request.Request(
        endpoint,
        data=json.dumps({{"name": name, "arguments": arguments}}).encode(),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(request) as response:
        return json.loads(response.read())["result"]

node_id = {node.id!r}
fanout_group = {node.fanout_group!r}
text = "fixture complete"

if node_id == "rank_files":
    call("add_hunts", {{"hunts": [{{
        "callerKey": "file:src/parser.ts",
        "kind": "FILE",
        "objective": "Audit parse-mode cache construction.",
        "paths": ["src/parser.ts"],
    }}]}})
elif node_id == "threat_model":
    call("add_hunts", {{"hunts": [{{
        "callerKey": "threat:cross-mode-cache",
        "kind": "THREAT_MODEL",
        "objective": "Test cross-mode parser/cache confusion.",
        "paths": ["src/parser.ts", "src/cache.ts"],
    }}]}})
elif node_id == "roam_plan":
    call("add_hunts", {{"hunts": [{{
        "callerKey": "roam:v1",
        "kind": "ROAM",
        "objective": "Explore remaining shared-state seams.",
        "paths": [],
    }}]}})
elif fanout_group == "hunt":
    hunt = call("get_hunt", {{}})
    if hunt["kind"] == "ROAM":
        call("finish_hunt", {{
            "result": "EXHAUSTED",
            "resultSummary": "No additional concrete defect survived validation.",
        }})
    else:
        lead_key = "file-key-omits-mode" if hunt["kind"] == "FILE" else "threat-cache-reuses-mode"
        location = "src/parser.ts:42" if hunt["kind"] == "FILE" else "src/cache.ts:17"
        call("add_lead", {{
            "callerKey": lead_key,
            "claim": "Parser mode is omitted from a cache key reused across the parser/cache seam.",
            "locations": [location],
            "evidence": "The shared key contains source text but no parse mode.",
            "impact": "A caller can receive an AST produced under different grammar semantics.",
            "validationPlan": "Prime one mode and request the same source under another mode.",
        }})
        call("finish_hunt", {{
            "result": "BUG_FOUND",
            "resultSummary": "Committed one concrete cache-confusion Lead.",
        }})
elif node_id == "deduplicate":
    hunts = call("list_hunts_and_leads", {{}})
    lead_ids = [lead["id"] for hunt in hunts for lead in hunt["leads"]]
    call("create_findings", {{"findings": [{{
        "callerKey": "parser-mode-cache-confusion",
        "title": "Parser cache can return an AST for the wrong mode",
        "rootCause": "Parser mode is omitted from the shared cache key.",
        "impact": "Validation can use the wrong AST semantics.",
        "leadIds": lead_ids,
    }}]}})
elif fanout_group == "triage":
    call("get_finding", {{}})
    call("set_triage", {{
        "verdict": "CONFIRMED",
        "assessment": "Both cross-kind Leads demonstrate one root cause.",
    }})
elif fanout_group == "rereview":
    call("get_finding", {{}})
    call("set_rereview", {{
        "verdict": "CONFIRMED",
        "assessment": "Independent review confirms the mode-free cache key.",
    }})
elif fanout_group == "report":
    finding = call("get_finding", {{}})
    kinds = sorted({{lead["hunt"]["kind"] for lead in finding["leads"]}})
    text = (
        "# " + finding["title"] + "\\n\\n"
        "Disposition: CONFIRMED\\n\\n"
        f"Lead count: {{len(finding['leads'])}}\\n\\n"
        f"Hunt kinds: {{', '.join(kinds)}}\\n"
    )

print(json.dumps({{
    "type": "response.output_item.done",
    "item": {{"type": "message", "role": "assistant", "content": [{{"type": "output_text", "text": text}}]}},
}}))
'''
        relative_path = "fixture-agent.py"
        return PreparedExecution(
            command=["python3", str(Path(paths.target_runtime_dir) / relative_path)],
            env={},
            cwd=paths.target_workdir,
            trace_kind="codex",
            runtime_files={relative_path: script},
        )


@pytest.mark.skipif(not DATABASE_URL, reason="BUGFINDER_TEST_DATABASE_URL is not set")
@pytest.mark.asyncio
async def test_bugfinder_postgres_end_to_end_fixture(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("BUGFINDER_TEST_DATABASE_URL", DATABASE_URL or "")
    port = _available_port()
    connector = {
        "name": "bugdb",
        "url": f"http://127.0.0.1:{port}/mcp",
        "control_url": f"http://127.0.0.1:{port}/orchestration",
        "command": "npm",
        "args": ["run", "connector"],
        "cwd": str(EXAMPLE_DIR),
        "env": {"BUGDB_PORT": str(port)},
        "env_from": {"DATABASE_URL": "BUGFINDER_TEST_DATABASE_URL"},
        "tools": [
            {"name": name, "description": name.replace("_", " "), "input_schema": {"type": "object"}}
            for name in (
                "add_hunts",
                "get_hunt",
                "add_lead",
                "finish_hunt",
                "list_hunts_and_leads",
                "create_findings",
                "get_finding",
                "set_triage",
                "set_rereview",
            )
        ],
    }
    common = {"agent": "codex", "connectors": ["bugdb"], "prompt": "fixture"}
    pipeline = PipelineSpec.model_validate(
        {
            "name": "bugfinder-postgres-e2e",
            "working_dir": str(tmp_path),
            "source_snapshot": {
                "repositoryUrl": "https://example.test/fixture.git",
                "inputRef": "fixture",
                "commitSha": "0123456789abcdef0123456789abcdef01234567",
            },
            "concurrency": 8,
            "fail_fast": False,
            "connectors": [connector],
            "nodes": [
                {**common, "id": "rank_files"},
                {**common, "id": "threat_model"},
                {**common, "id": "roam_plan"},
                {
                    **common,
                    "id": "hunt",
                    "depends_on": ["rank_files", "threat_model", "roam_plan"],
                    "fanout_from": {
                        "from": "rank_files",
                        "connector": "bugdb",
                        "resource": "hunts",
                    },
                },
                {**common, "id": "deduplicate", "depends_on": ["hunt"]},
                {
                    **common,
                    "id": "triage",
                    "fanout_from": {
                        "from": "deduplicate",
                        "connector": "bugdb",
                        "resource": "findings",
                    },
                },
                {
                    **common,
                    "id": "rereview",
                    "fanout_from": {
                        "from": "triage",
                        "connector": "bugdb",
                        "resource": "findings",
                    },
                },
                {
                    **common,
                    "id": "report",
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
    adapters = AdapterRegistry()
    adapters.register(AgentKind.CODEX, BugfinderFixtureAdapter())
    orchestrator = Orchestrator(
        store=RunStore(tmp_path / "runs"),
        adapters=adapters,
        runners=RunnerRegistry(),
    )

    submitted = await orchestrator.submit(pipeline)
    completed = await orchestrator.wait(submitted.id, timeout=20)

    assert completed.status.value == "completed"
    assert len(completed.pipeline.fanouts["hunt"]) == 3
    assert all(
        completed.nodes[node_id].status == NodeStatus.COMPLETED
        for node_id in completed.pipeline.fanouts["hunt"]
    )
    assert len(completed.pipeline.fanouts["triage"]) == 1
    assert len(completed.pipeline.fanouts["rereview"]) == 1
    assert len(completed.pipeline.fanouts["report"]) == 1
    report_id = completed.pipeline.fanouts["report"][0]
    report = orchestrator.store.read_artifact_text(completed.id, report_id, "report.md")
    assert "Lead count: 2" in report
    assert "Hunt kinds: FILE, THREAT_MODEL" in report
    assert completed.nodes["hunt"].status == NodeStatus.COMPLETED
    assert completed.nodes["rereview"].status == NodeStatus.COMPLETED
