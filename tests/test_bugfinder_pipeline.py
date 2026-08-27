from __future__ import annotations

import json
from pathlib import Path
import re

from agentflow.context import render_node_prompt
from agentflow.specs import AgentKind
from examples.bugfinder.pipeline import BugfinderConfig, build_pipeline


EXAMPLE_DIR = Path(__file__).resolve().parents[1] / "examples" / "bugfinder"


def test_bugfinder_factory_builds_the_production_graph(tmp_path: Path):
    pipeline = build_pipeline(
        BugfinderConfig(
            repository=tmp_path,
            repository_url="https://example.test/repository.git",
            input_ref="main",
            historical_context="Prior bug in {{ dangerous_template }}.",
            environment={"BUGFINDER_AGENT": "codex", "BUGFINDER_RETRIES": "4"},
        )
    ).to_spec()

    assert pipeline.source_snapshot is not None
    assert pipeline.source_snapshot.model_dump(mode="json", by_alias=True) == {
        "repositoryUrl": "https://example.test/repository.git",
        "inputRef": "main",
    }
    assert [node.id for node in pipeline.nodes] == [
        "rank_files",
        "threat_model",
        "roam_plan",
        "hunt",
        "deduplicate",
        "triage",
        "rereview",
        "report",
    ]
    assert set(pipeline.node_map["hunt"].depends_on) == {"rank_files", "threat_model", "roam_plan"}
    assert pipeline.node_map["report"].agent == AgentKind.PYTHON
    assert pipeline.node_map["report"].capture.value == "trace"
    assert pipeline.node_map["report"].output_artifact == "report.md"
    assert pipeline.node_map["report"].connector_tools == {"bugdb": ["get_finding"]}
    assert all(node.repo_instructions_mode.value == "ignore" for node in pipeline.nodes)
    assert pipeline.connectors[0].url == "http://127.0.0.1:{port}/mcp"
    assert pipeline.connectors[0].tools == []
    assert pipeline.deadline_seconds == 14400
    assert pipeline.node_map["hunt"].durable_goal is not None
    assert pipeline.node_map["deduplicate"].durable_goal is not None
    assert pipeline.node_map["deduplicate"].durable_goal.mode == "supervised"
    assert pipeline.node_map["rank_files"].durable_goal is None
    assert pipeline.node_map["deduplicate"].retries == 4
    assert "at most 1,500 tokens" in pipeline.node_map["deduplicate"].prompt
    assert "your next substantive action" in pipeline.node_map["deduplicate"].prompt
    assert "before reaching the response limit" in pipeline.node_map["deduplicate"].prompt
    assert "historical category or bug pattern" in pipeline.node_map["threat_model"].prompt
    threat = pipeline.node_map["threat_model"]
    assert threat.input == {
        "repositoryUrl": "https://example.test/repository.git",
        "historicalContext": "Prior bug in {{ dangerous_template }}.",
    }
    assert "dangerous_template" not in render_node_prompt(pipeline, threat, {})


def test_bugfinder_schema_and_scripts_stay_minimal():
    schema = (EXAMPLE_DIR / "prisma" / "schema.prisma").read_text(encoding="utf-8")
    migration = (
        EXAMPLE_DIR / "prisma" / "migrations" / "20260826000000_init" / "migration.sql"
    ).read_text(encoding="utf-8")
    package = json.loads((EXAMPLE_DIR / "package.json").read_text(encoding="utf-8"))

    assert re.findall(r"^model\s+(\w+)", schema, flags=re.MULTILINE) == ["Hunt", "Lead", "Finding"]
    assert re.findall(r"^enum\s+(\w+)", schema, flags=re.MULTILINE) == [
        "HuntKind",
        "HuntResult",
        "FindingVerdict",
    ]
    assert not re.search(r"\bJson\??\b", schema)
    assert "ALTER DEFAULT PRIVILEGES" not in migration
    assert package["scripts"]["prebuild"] == "npm run prisma:generate"
    assert package["scripts"]["pretest"] == "npm run prisma:generate"


def test_bugfinder_configures_glm_pi_capabilities_and_xhigh_reasoning_for_every_pi_role(
    tmp_path: Path,
):
    pipeline = build_pipeline(
        BugfinderConfig(
            repository=tmp_path,
            repository_url="https://example.test/repository.git",
            input_ref="main",
            environment={
                "BUGFINDER_AGENT": "pi",
                "BUGFINDER_PI_MODEL": "openrouter/z-ai/glm-5.3",
            },
        )
    ).to_spec()

    pi_nodes = [node for node in pipeline.nodes if node.agent == AgentKind.PI]
    assert {node.id for node in pi_nodes} == {
        "rank_files",
        "threat_model",
        "roam_plan",
        "hunt",
        "deduplicate",
        "triage",
        "rereview",
    }
    for node in pi_nodes:
        assert node.provider is not None
        assert node.provider.model_reasoning is True
        assert node.provider.model_context_window == 1048576
        assert node.provider.model_max_tokens == 65536
        assert node.extra_args[-2:] == ["--thinking", "xhigh"]
