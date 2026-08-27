from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from agentflow.agents.base import AgentAdapter
from agentflow.agents.registry import AdapterRegistry
from agentflow.orchestrator import Orchestrator
from agentflow.prepared import ExecutionPaths, PreparedExecution
from agentflow.runners.registry import RunnerRegistry
from agentflow.specs import AgentKind, NodeSpec
from agentflow.store import RunStore
from examples.bugfinder.pipeline import BugfinderConfig, build_pipeline


DATABASE_URL = os.environ.get("BUGFINDER_TEST_DATABASE_URL")
HISTORY_PATTERN = "HISTORICAL-CACHE-CROSS-MODE"


def _git(repository: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(repository), *args],
        text=True,
    ).strip()


def _fixture_repository(path: Path) -> str:
    path.mkdir()
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    _git(path, "config", "user.email", "fixture@example.test")
    _git(path, "config", "user.name", "Fixture")
    (path / "src").mkdir()
    (path / "src" / "parser.ts").write_text(
        "export const parser = 'fixture';\n",
        encoding="utf-8",
    )
    (path / "src" / "cache.ts").write_text(
        "export const cache = new Map();\n",
        encoding="utf-8",
    )
    _git(path, "add", ".")
    _git(path, "commit", "-qm", "fixture")
    return _git(path, "rev-parse", "HEAD")


class BugfinderFixtureAdapter(AgentAdapter):
    """Deterministic stand-in agents that use the real scoped connector tools."""

    def prepare(self, node: NodeSpec, prompt: str, paths: ExecutionPaths) -> PreparedExecution:
        binding = node.connector_bindings[0]
        endpoint = binding.url.removesuffix("/mcp") + "/tools/call"
        script = f'''
import json
import urllib.request

endpoint = {endpoint!r}
headers = json.loads({json.dumps(json.dumps(binding.headers))})
headers["content-type"] = "application/json"

def call(name, arguments):
    request = urllib.request.Request(
        endpoint,
        data=json.dumps({{"name": name, "arguments": arguments}}).encode(),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(request) as response:
        result = json.loads(response.read())["result"]
    print(json.dumps({{
        "type": "item.completed",
        "item": {{
            "type": "mcp_tool_call",
            "server": "bugdb",
            "tool": name,
            "status": "completed",
            "error": None,
        }},
    }}), flush=True)
    return result

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
    objective = "Apply historical pattern {HISTORY_PATTERN} to parser/cache confusion."
    call("add_hunts", {{"hunts": [{{
        "callerKey": "threat:cross-mode-cache",
        "kind": "THREAT_MODEL",
        "objective": objective,
        "paths": ["src/parser.ts", "src/cache.ts"],
    }}]}})
    text = objective
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

print(json.dumps({{
    "type": "response.output_item.done",
    "item": {{
        "type": "message",
        "role": "assistant",
        "content": [{{"type": "output_text", "text": text}}],
    }},
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
async def test_bugfinder_minimal_production_graph(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", DATABASE_URL or "")
    repository = tmp_path / "repository"
    commit_sha = _fixture_repository(repository)
    pipeline = build_pipeline(
        BugfinderConfig(
            repository=repository,
            repository_url="https://example.test/fixture.git",
            input_ref="HEAD",
            historical_context=HISTORY_PATTERN,
            environment={
                "BUGFINDER_AGENT": "codex",
                "BUGFINDER_RETRIES": "0",
                "BUGFINDER_NODE_TIMEOUT": "20",
                "BUGFINDER_DEADLINE_SECONDS": "60",
            },
        )
    ).to_spec()

    assert pipeline.connectors[0].tools == []
    assert pipeline.node_map["rank_files"].connector_tools == {"bugdb": ["add_hunts"]}
    assert pipeline.node_map["report"].agent == AgentKind.PYTHON
    assert all(node.repo_instructions_mode.value == "ignore" for node in pipeline.nodes)

    adapters = AdapterRegistry()
    adapters.register(AgentKind.CODEX, BugfinderFixtureAdapter())
    orchestrator = Orchestrator(
        store=RunStore(tmp_path / "runs"),
        adapters=adapters,
        runners=RunnerRegistry(),
    )

    submitted = await orchestrator.submit(pipeline)
    completed = await orchestrator.wait(submitted.id, timeout=30)

    assert completed.status.value == "completed"
    assert completed.source_snapshot is not None
    assert completed.source_snapshot.commit_sha == commit_sha
    assert completed.nodes["rank_files"].output == "fixture complete"
    assert HISTORY_PATTERN in (completed.nodes["threat_model"].output or "")
    assert len(completed.pipeline.fanouts["hunt"]) == 3
    assert len(completed.pipeline.fanouts["triage"]) == 1
    assert len(completed.pipeline.fanouts["rereview"]) == 1
    assert len(completed.pipeline.fanouts["report"]) == 1
    report_id = completed.pipeline.fanouts["report"][0]
    report = orchestrator.store.read_artifact_text(completed.id, report_id, "report.md")
    assert "**Disposition:** CONFIRMED" in report
    assert "src/parser.ts:42" in report
    assert "src/cache.ts:17" in report
