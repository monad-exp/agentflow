from __future__ import annotations

import ast
import json
from pathlib import Path
import re
import subprocess
import sys
from types import SimpleNamespace

import pytest

from agentflow.context import render_node_prompt
from agentflow.dsl import Graph
from agentflow.specs import AgentKind, NodeResult, NodeStatus, PipelineSpec, RunStatus
from agentflow.utils import render_template
from examples.bugfinder.v3 import run as runner
from examples.bugfinder.v3.config import load_config, profiles_for, resolve_budget, select_target
from examples.bugfinder.v3.pipeline import (
    INPUT_POINTER_HEADING,
    PYTHON_NODE_TIMEOUT_SECONDS,
    agent_node,
    build_pipeline,
    checkout_path,
    context_slots,
    hunt_slots,
    impact_profile_id,
    python_collector_code,
    read_history_text,
    slot_key,
    validity_slots,
)
from examples.bugfinder.v3.prompts import PHASES, phase_timeout_minutes


BUDGETS = ("low", "medium", "high")
TARGET = "monad"
HISTORY = "Issue #1: reorg handling {{ not jinja }} {% nor this %} {# nor a comment #}\n"
SHA = "a" * 40
AGENTS = {AgentKind.CODEX, AgentKind.CLAUDE, AgentKind.PI}
FIXED_NODES = {
    "snapshot",
    "rank_files",
    "plan_file_hunts",
    "plan_context_workers",
    "collect_threat_drafts",
    "threat_synthesis",
    "collect_threat_model",
    "goal_plan",
    "plan_goal_hunts",
    "collect_leads",
    "deduplicate",
    "collect_findings",
    "triage_context",
    "collect_contexts",
    "collect_validity",
    "triage_impact",
    "trusted_report",
    "report",
    "collect_reports",
}
HISTORY_NODES = {"collect_history_candidates", "history_synthesis", "collect_history_model"}
# Node id (or `__` prefix) -> prompt phase; the timeout is the phase's budget field (prompts.PHASE_TIMEOUT_FIELDS).
PHASE_OF_NODE = {
    "rank_files": "rank",
    "file_hunt__": "file-hunt",
    "goal_hunt__": "goal-common",
    "threat_model__": "threat",
    "history_risk__": "historical-risk-classes",
    "threat_synthesis": "threat-synthesis",
    "history_synthesis": "historical-synthesis",
    "goal_plan": "goal-plan",
    "deduplicate": "deduplicate",
    "triage_context": "triager-1-context",
    "triage_validity__": "triager-2-validity",
    "triage_impact": "triager-3-impact",
    "report": "report",
}


@pytest.fixture
def config():
    return load_config()


@pytest.fixture
def workspace(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    monkeypatch.delenv("BUGFINDER_REPO_PATH", raising=False)
    monkeypatch.delenv("BUGFINDER_KNOWN_FINDINGS", raising=False)
    monkeypatch.setenv("BUGFINDER_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    return tmp_path


def with_history(config, history_file: str | None):
    target = select_target(config, TARGET).model_copy(update={"historyFile": history_file})
    targets = [target if item.id == TARGET else item for item in config.targets]
    return config.model_copy(update={"targets": targets})


def build_spec(config, budget: str, **kwargs) -> PipelineSpec:
    return build_pipeline(with_history(config, None), TARGET, budget=budget, **kwargs).to_spec()


def agent_nodes(pipeline: PipelineSpec):
    return [node for node in pipeline.nodes if node.agent in AGENTS]


def python_nodes(pipeline: PipelineSpec):
    return [node for node in pipeline.nodes if node.agent == AgentKind.PYTHON]


def templates(pipeline: PipelineSpec):
    return [node for node in pipeline.nodes if node.fanout_from is not None]


def prefixed(pipeline: PipelineSpec, prefix: str) -> list[str]:
    return [node.id for node in pipeline.nodes if node.id.startswith(prefix)]


def collector_params(pipeline: PipelineSpec, node_id: str) -> dict:
    """Decode the JSON params literal embedded in a collector node without executing it."""

    module = ast.parse(pipeline.node_map[node_id].prompt)
    call = module.body[-1].value
    assert isinstance(call, ast.Call) and call.func.attr == "run"
    assert call.args[0].value == node_id
    return json.loads(call.args[1].args[0].value)


def phase_of(node_id: str) -> str:
    for prefix, phase in PHASE_OF_NODE.items():
        if node_id == prefix or (prefix.endswith("__") and node_id.startswith(prefix)):
            return phase
    raise AssertionError(f"no phase for {node_id}")


def git(repository: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repository), *args], check=True, capture_output=True, text=True).stdout.strip()


def init_repository(path: Path) -> str:
    path.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(path)], check=True)
    return commit(path, "one")


def commit(path: Path, text_value: str) -> str:
    (path / "README.md").write_text(text_value + "\n", encoding="utf-8")
    git(path, "add", ".")
    git(path, "-c", "user.name=t", "-c", "user.email=t@example.test", "commit", "-qm", text_value)
    return git(path, "rev-parse", "HEAD")


def test_slot_key_replaces_dashes_and_appends_replica():
    assert slot_key("codex-gpt-5-6-sol", 1) == "codex_gpt_5_6_sol_r1"
    assert slot_key("pi-glm-5-3", 2) == "pi_glm_5_3_r2"


@pytest.mark.parametrize("budget", BUDGETS)
def test_slot_helpers_follow_budget_matrix(config, budget):
    profile = resolve_budget(config, budget)
    workers = profiles_for(config, "workerSmart")
    profile_count = {"low": 2, "medium": 3, "high": len(workers)}[budget]
    replicas = {"low": 1, "medium": 1, "high": 2}[budget]

    slots = hunt_slots(config, profile)
    assert [slot.profile_id for slot in slots] == [pid for pid in workers[:profile_count] for _ in range(replicas)]
    assert [slot.replica for slot in slots] == list(range(1, replicas + 1)) * profile_count
    assert len({slot.key for slot in slots}) == len(slots)
    assert len(context_slots(config, profile)) == len(slots)

    impact_model = config.profiles[impact_profile_id(config)].model
    validity = validity_slots(config, profile)
    assert validity
    assert all(config.profiles[slot.profile_id].model != impact_model for slot in validity)
    assert all(slot.replica == 1 for slot in validity)
    eligible = [pid for pid in workers if config.profiles[pid].model != impact_model]
    assert [slot.profile_id for slot in validity] == eligible[: {"low": 2, "medium": 3, "high": len(eligible)}[budget]]


@pytest.mark.parametrize("budget", BUDGETS)
def test_node_ids_cover_every_lane_without_history(config, workspace, budget):
    profile = resolve_budget(config, budget)
    pipeline = build_spec(config, budget)
    hunt_keys = [slot.key for slot in hunt_slots(config, profile)]
    context_keys = [slot.key for slot in context_slots(config, profile)]
    validity_keys = [slot.key for slot in validity_slots(config, profile)]

    expected = set(FIXED_NODES)
    expected |= {f"file_hunt__{key}" for key in hunt_keys}
    expected |= {f"goal_hunt__threat__{key}" for key in hunt_keys}
    expected |= {f"goal_hunt__roam__{key}" for key in hunt_keys}
    expected |= {f"threat_model__{key}" for key in context_keys}
    expected |= {f"triage_validity__{key}" for key in validity_keys}
    assert {node.id for node in pipeline.nodes} == expected
    assert len(pipeline.nodes) == len(expected)
    assert not prefixed(pipeline, "history_risk__") and not prefixed(pipeline, "goal_hunt__historical__")
    assert pipeline.name == f"bugfinder-v3-{TARGET}"


def test_low_budget_counts(config, workspace):
    pipeline = build_spec(config, "low")
    assert len(prefixed(pipeline, "file_hunt__")) == 2
    assert len(prefixed(pipeline, "threat_model__")) == 2
    assert len(prefixed(pipeline, "goal_hunt__")) == 4
    assert len(prefixed(pipeline, "triage_validity__")) == 2
    assert collector_params(pipeline, "plan_context_workers") == {
        "snapshotNode": "snapshot",
        "slots": [
            {"slotKey": slot.key, "profileId": slot.profile_id, "replica": slot.replica}
            for slot in context_slots(config, resolve_budget(config, "low"))
        ],
        "history": False,
        "historyText": None,
    }
    assert collector_params(pipeline, "plan_goal_hunts")["historyModelNode"] is None


def test_history_lane_appears_only_with_history_file(config, workspace, tmp_path):
    history_file = tmp_path / "history.md"
    history_file.write_text(HISTORY, encoding="utf-8")
    pipeline = build_pipeline(with_history(config, f"file://{history_file}"), TARGET, budget="low").to_spec()
    context_keys = [slot.key for slot in context_slots(config, resolve_budget(config, "low"))]
    hunt_keys = [slot.key for slot in hunt_slots(config, resolve_budget(config, "low"))]

    assert HISTORY_NODES <= {node.id for node in pipeline.nodes}
    assert prefixed(pipeline, "history_risk__") == [f"history_risk__{key}" for key in context_keys]
    assert prefixed(pipeline, "goal_hunt__historical__") == [f"goal_hunt__historical__{key}" for key in hunt_keys]
    for key in context_keys:
        worker = pipeline.node_map[f"history_risk__{key}"]
        assert worker.fanout_from.from_ == "plan_context_workers"
        assert worker.fanout_from.path == f"$.history.{key}"
    assert set(pipeline.node_map["collect_history_candidates"].depends_on) == set(prefixed(pipeline, "history_risk__"))
    assert pipeline.node_map["history_synthesis"].depends_on[0] == "collect_history_candidates"
    assert pipeline.node_map["collect_history_model"].depends_on == ["history_synthesis"]
    assert {"collect_threat_model", "collect_history_model"} <= set(pipeline.node_map["goal_plan"].depends_on)
    for key in hunt_keys:
        assert pipeline.node_map[f"goal_hunt__historical__{key}"].fanout_from.path == f"$.lanes.historical__{key}"
    assert collector_params(pipeline, "plan_context_workers")["history"] is True
    assert collector_params(pipeline, "plan_context_workers")["historyText"] == HISTORY
    assert collector_params(pipeline, "plan_goal_hunts")["historyModelNode"] == "collect_history_model"
    assert collector_params(pipeline, "collect_history_candidates")["templates"] == prefixed(pipeline, "history_risk__")
    assert collector_params(pipeline, "collect_history_model") == {
        "synthesisNode": "history_synthesis",
        "candidatesNode": "collect_history_candidates",
        "snapshotNode": "snapshot",
        "targetId": TARGET,
    }


def test_dependencies_follow_section_five(config, workspace):
    pipeline = build_spec(config, "medium")
    nodes = pipeline.node_map
    hunt_keys = [slot.key for slot in hunt_slots(config, resolve_budget(config, "medium"))]
    validity_keys = [slot.key for slot in validity_slots(config, resolve_budget(config, "medium"))]

    assert nodes["snapshot"].depends_on == []
    assert nodes["plan_context_workers"].depends_on == ["snapshot"]
    assert nodes["rank_files"].depends_on == ["snapshot"]
    assert {"rank_files", "snapshot"} <= set(nodes["plan_file_hunts"].depends_on)
    for key in hunt_keys:
        hunt = nodes[f"file_hunt__{key}"]
        assert hunt.fanout_from.from_ == "plan_file_hunts"
        assert hunt.fanout_from.path == f"$.lanes.{key}"
        assert hunt.fanout_from.as_ == "attempt"
        assert {"plan_file_hunts", "snapshot"} <= set(hunt.depends_on)
        for lane in ("threat", "roam"):
            goal = nodes[f"goal_hunt__{lane}__{key}"]
            assert goal.fanout_from.from_ == "plan_goal_hunts"
            assert goal.fanout_from.path == f"$.lanes.{lane}__{key}"
            assert goal.fanout_from.as_ == "attempt"
    for worker_id in prefixed(pipeline, "threat_model__"):
        worker = nodes[worker_id]
        assert worker.fanout_from.from_ == "plan_context_workers"
        assert worker.fanout_from.path == f"$.threat.{worker_id.removeprefix('threat_model__')}"
    assert set(nodes["collect_threat_drafts"].depends_on) == set(prefixed(pipeline, "threat_model__"))
    assert "collect_threat_drafts" in nodes["threat_synthesis"].depends_on
    assert nodes["collect_threat_model"].depends_on == ["threat_synthesis"]
    assert "collect_threat_model" in nodes["goal_plan"].depends_on
    assert "collect_history_model" not in nodes["goal_plan"].depends_on
    assert nodes["plan_goal_hunts"].depends_on == ["goal_plan"]
    hunt_ids = prefixed(pipeline, "file_hunt__") + prefixed(pipeline, "goal_hunt__")
    assert set(nodes["collect_leads"].depends_on) == set(hunt_ids)
    assert collector_params(pipeline, "collect_leads")["templates"] == hunt_ids
    assert "collect_leads" in nodes["deduplicate"].depends_on
    assert nodes["collect_findings"].depends_on == ["deduplicate"]
    assert nodes["triage_context"].fanout_from.model_dump(by_alias=True) == {
        "from": "collect_findings",
        "path": "$.items",
        "as": "finding",
        "max_items": resolve_budget(config, "medium").triageFindingCap,
        "connector": None,
        "resource": None,
    }
    assert nodes["collect_contexts"].depends_on == ["triage_context"]
    for key in validity_keys:
        validity = nodes[f"triage_validity__{key}"]
        assert validity.fanout_from.from_ == "collect_contexts"
        assert validity.fanout_from.path == f"$.validity.{key}"
        assert validity.fanout_from.as_ == "finding"
    assert set(nodes["collect_validity"].depends_on) == {*prefixed(pipeline, "triage_validity__"), "collect_contexts"}
    assert nodes["triage_impact"].fanout_from.from_ == "collect_validity"
    assert nodes["triage_impact"].fanout_from.path == "$.items"
    assert nodes["trusted_report"].depends_on == ["triage_impact"]
    assert nodes["report"].fanout_from.from_ == "trusted_report"
    assert nodes["report"].fanout_from.path == "$.items"
    assert nodes["report"].fanout_from.as_ == "finding"
    assert nodes["collect_reports"].depends_on == ["report"]
    for template in templates(pipeline):
        assert nodes[template.fanout_from.from_].agent == AgentKind.PYTHON
        assert template.fanout_from.connector is None


INPUT_POINTERS = {
    "rank_files": ["snapshot"],
    "threat_synthesis": ["collect_threat_drafts"],
    "history_synthesis": ["collect_history_candidates"],
    "goal_plan": ["collect_threat_model", "collect_history_model"],
    "deduplicate": ["collect_leads"],
}


def test_principal_consumers_point_at_collector_artifacts(config, workspace, tmp_path):
    history_file = tmp_path / "history.md"
    history_file.write_text(HISTORY, encoding="utf-8")
    pipeline = build_pipeline(with_history(config, str(history_file)), TARGET, budget="low").to_spec()
    python_ids = {node.id for node in python_nodes(pipeline)}
    for node in pipeline.nodes:
        sources = INPUT_POINTERS.get(node.id, [])
        assert (INPUT_POINTER_HEADING in node.prompt) == bool(sources), node.id
        for source in sources:
            assert f"{{{{ nodes.{source}.artifacts.result_json }}}}" in node.prompt
            assert source in node.depends_on
        referenced = set(re.findall(r"nodes\.([A-Za-z_][A-Za-z0-9_]*)", node.prompt))
        assert referenced <= python_ids
        assert referenced <= set(node.depends_on)
    without_history = build_spec(config, "low")
    assert "collect_history_model" not in without_history.node_map["goal_plan"].prompt
    assert "{{ nodes.collect_threat_model.artifacts.result_json }}" in without_history.node_map["goal_plan"].prompt


def test_input_pointer_renders_to_the_collector_result_path(config, workspace, tmp_path):
    pipeline = build_spec(config, "low")
    results = {node.id: NodeResult(node_id=node.id, status=NodeStatus.PENDING) for node in pipeline.nodes}
    results["snapshot"].status = NodeStatus.COMPLETED
    results["snapshot"].structured_output = {"sourceCommit": SHA}
    rendered = render_node_prompt(
        pipeline,
        pipeline.node_map["rank_files"],
        results,
        run_id="run-1",
        artifacts_base_dir=tmp_path / "runs",
    )
    expected = (tmp_path / "runs").resolve() / "run-1" / "artifacts" / "snapshot" / "result.json"
    assert f"- `snapshot`: `{expected}`" in rendered
    assert "{{" not in rendered and "{%" not in rendered


@pytest.mark.parametrize("budget", BUDGETS)
def test_agent_nodes_obey_safety_rules(config, workspace, budget):
    pipeline = build_spec(config, budget)
    assert all(node.input is None for node in pipeline.nodes)
    assert all(node.repo_instructions_mode.value == "ignore" for node in pipeline.nodes)
    agents = agent_nodes(pipeline)
    assert len(agents) + len(python_nodes(pipeline)) == len(pipeline.nodes)
    for node in agents:
        assert node.retries == config.workflow.retries == 1
        assert node.retry_backoff_seconds == 2
        assert node.concurrency_pool == f"{node.agent.value}-provider"
        assert node.concurrency_pool in pipeline.concurrency_pools
        assert node.model
        criteria = [criterion.model_dump(by_alias=True) for criterion in node.success_criteria]
        assert len(criteria) == 1 and criteria[0]["kind"] == "output_json_schema"
        assert criteria[0]["schema"].get("type") == "object"
        assert criteria[0]["schema"].get("additionalProperties") is False
        read_write = node.id.startswith("triage_validity__") or node.id == "triage_impact"
        assert node.tools.value == ("read_write" if read_write else "read_only")
        assert "{{ item." not in node.prompt


@pytest.mark.parametrize("budget", BUDGETS)
def test_timeouts_pools_and_limits_follow_budget(config, workspace, budget):
    profile = resolve_budget(config, budget)
    pipeline = build_spec(config, budget)
    assert pipeline.concurrency == profile.engineConcurrency
    assert pipeline.concurrency_pools == {
        "codex-provider": profile.pools.codex,
        "claude-provider": profile.pools.claude,
        "pi-provider": profile.pools.pi,
    }
    expected_deadline = None if profile.deadlineHours is None else int(profile.deadlineHours) * 3600
    assert pipeline.deadline_seconds == expected_deadline
    assert pipeline.fail_fast is False
    for node in agent_nodes(pipeline):
        assert node.timeout_seconds == phase_timeout_minutes(phase_of(node.id), profile) * 60, node.id
    assert set(PHASE_OF_NODE.values()) <= set(PHASES)
    for node in python_nodes(pipeline):
        assert node.timeout_seconds == PYTHON_NODE_TIMEOUT_SECONDS
    for template in templates(pipeline):
        if template.id.startswith(("file_hunt__", "goal_hunt__")):
            assert template.fanout_from.max_items == profile.maxItemsPerSlot
        elif template.id.startswith("threat_model__"):
            assert template.fanout_from.max_items == 1
        else:
            assert template.fanout_from.max_items == profile.triageFindingCap
    assert collector_params(pipeline, "plan_file_hunts")["threshold"] == profile.fileRankThreshold
    assert collector_params(pipeline, "plan_file_hunts")["maxItemsPerSlot"] == profile.maxItemsPerSlot
    assert collector_params(pipeline, "plan_goal_hunts")["maxRoamGoals"] == profile.maxRoamGoals
    assert collector_params(pipeline, "plan_goal_hunts")["maxItemsPerSlot"] == profile.maxItemsPerSlot
    assert collector_params(pipeline, "collect_findings")["cap"] == profile.triageFindingCap


def test_impact_model_differs_from_context_and_validity_models(config, workspace):
    pipeline = build_spec(config, "high")
    impact = pipeline.node_map["triage_impact"]
    assert impact.model == config.profiles[impact_profile_id(config)].model
    assert impact.model != pipeline.node_map["triage_context"].model
    validity_models = {pipeline.node_map[node_id].model for node_id in prefixed(pipeline, "triage_validity__")}
    assert validity_models and impact.model not in validity_models
    assert impact.model != pipeline.node_map["rank_files"].model


def test_agent_node_maps_profiles_onto_harness_kwargs(config):
    schema = {"type": "object"}
    with Graph("harness-map"):
        nodes = {
            profile_id: agent_node(config, profile_id, task_id=f"n_{index}", prompt="p", schema=schema, timeout_seconds=60)
            for index, profile_id in enumerate(("codex-gpt-5-6-sol", "claude-code-fable-5", "pi-glm-5-3"))
        }
    codex_profile = config.profiles["codex-gpt-5-6-sol"]
    codex_node = nodes["codex-gpt-5-6-sol"].to_spec()
    assert codex_node.agent == AgentKind.CODEX
    assert codex_node.model == codex_profile.model
    assert codex_node.extra_args == ["-c", f'model_reasoning_effort="{codex_profile.reasoning}"']
    assert codex_node.concurrency_pool == "codex-provider"

    claude_profile = config.profiles["claude-code-fable-5"]
    claude_node = nodes["claude-code-fable-5"].to_spec()
    assert claude_node.agent == AgentKind.CLAUDE
    assert claude_node.model == claude_profile.model
    assert claude_node.extra_args == [
        "--effort",
        claude_profile.reasoning,
        "--settings",
        '{"switchModelsOnFlag":false}',
    ]

    pi_profile = config.profiles["pi-glm-5-3"]
    pi_node = nodes["pi-glm-5-3"].to_spec()
    assert pi_node.agent == AgentKind.PI
    assert pi_node.model == pi_profile.model
    assert pi_node.extra_args == ["--thinking", pi_profile.reasoning]
    assert pi_node.provider is not None
    assert pi_node.provider.name == pi_profile.provider.name
    assert pi_node.provider.base_url == pi_profile.provider.base_url
    assert pi_node.provider.api_key_env == pi_profile.provider.api_key_env
    assert pi_node.provider.wire_api == pi_profile.provider.wire_api
    for node in nodes.values():
        spec = node.to_spec()
        assert spec.repo_instructions_mode.value == "ignore"
        assert spec.retries == 1 and spec.retry_backoff_seconds == 2 and spec.timeout_seconds == 60
        assert [criterion.kind for criterion in spec.success_criteria] == ["output_json_schema"]


def test_agent_node_rejects_unknown_harness(config):
    broken = config.profiles["codex-gpt-5-6-sol"].model_copy(update={"harness": "opencode"})
    patched = config.model_copy(update={"profiles": {**config.profiles, "opencode-x": broken}})
    with Graph("bad-harness"), pytest.raises(ValueError, match="unsupported harness"):
        agent_node(patched, "opencode-x", task_id="n", prompt="p", schema={}, timeout_seconds=60)


def test_python_nodes_use_executable_root_and_jinja_free_params(config, workspace):
    pipeline = build_spec(config, "low", python_executable="/opt/py/bin/python3", agentflow_root=Path("/srv/agentflow"))
    collectors = python_nodes(pipeline)
    assert {node.id for node in collectors} == {
        node_id for node_id in FIXED_NODES if node_id not in {
            "rank_files", "threat_synthesis", "goal_plan", "deduplicate", "triage_context", "triage_impact", "report",
        }
    }
    for node in collectors:
        assert node.executable == "/opt/py/bin/python3"
        assert node.timeout_seconds == PYTHON_NODE_TIMEOUT_SECONDS
        assert node.repo_instructions_mode.value == "ignore"
        assert node.fanout_from is None
        assert "sys.path.insert(0, '/srv/agentflow')" in node.prompt
        assert "from examples.bugfinder.v3 import collectors" in node.prompt
        assert "{{" not in node.prompt and "{%" not in node.prompt and "{#" not in node.prompt
        assert isinstance(collector_params(pipeline, node.id), dict)
    default = build_spec(config, "low")
    assert all(node.executable == sys.executable for node in python_nodes(default))
    assert all(f"sys.path.insert(0, {str(Path(__file__).resolve().parents[1])!r})" in node.prompt for node in python_nodes(default))


def test_collector_params_match_design(config, workspace, monkeypatch):
    target = select_target(config, TARGET)
    pipeline = build_spec(config, "medium")
    profile = resolve_budget(config, "medium")
    slots = [slot.to_params() for slot in hunt_slots(config, profile)]
    assert collector_params(pipeline, "snapshot") == {
        "targetId": target.id,
        "repositoryUrl": target.repositoryUrl,
        "sourceRef": target.sourceRef,
        "include": list(target.scope.include),
        "exclude": list(target.scope.exclude),
    }
    assert collector_params(pipeline, "plan_file_hunts") == {
        "rankNode": "rank_files",
        "snapshotNode": "snapshot",
        "threshold": profile.fileRankThreshold,
        "maxItemsPerSlot": profile.maxItemsPerSlot,
        "slots": slots,
    }
    assert collector_params(pipeline, "collect_threat_drafts") == {"templates": prefixed(pipeline, "threat_model__")}
    assert collector_params(pipeline, "collect_threat_model") == {
        "synthesisNode": "threat_synthesis",
        "draftsNode": "collect_threat_drafts",
        "snapshotNode": "snapshot",
        "targetId": target.id,
    }
    goal_params = collector_params(pipeline, "plan_goal_hunts")
    assert goal_params == {
        "goalPlanNode": "goal_plan",
        "threatModelNode": "collect_threat_model",
        "historyModelNode": None,
        "snapshotNode": "snapshot",
        "slots": slots,
        "maxRoamGoals": profile.maxRoamGoals,
        "maxItemsPerSlot": profile.maxItemsPerSlot,
        "templatesDir": goal_params["templatesDir"],
    }
    assert Path(goal_params["templatesDir"]) == Path(__file__).resolve().parents[1] / "examples/bugfinder/v3/templates"
    assert collector_params(pipeline, "collect_findings") == {
        "dedupNode": "deduplicate",
        "leadsNode": "collect_leads",
        "cap": profile.triageFindingCap,
        "knownFindingsPath": None,
    }
    assert collector_params(pipeline, "collect_contexts") == {
        "gateTemplate": "triage_context",
        "findingsNode": "collect_findings",
        "validitySlots": [slot.to_params() for slot in validity_slots(config, profile)],
    }
    assert collector_params(pipeline, "collect_validity") == {
        "validityTemplates": prefixed(pipeline, "triage_validity__"),
        "contextsNode": "collect_contexts",
    }
    trusted = collector_params(pipeline, "trusted_report")
    assert trusted["impactTemplate"] == "triage_impact" and trusted["validityNode"] == "collect_validity"
    assert trusted["policy"] == config.triagePolicy.model_dump(mode="json")
    assert collector_params(pipeline, "collect_reports") == {
        "reportTemplate": "report",
        "trustedNode": "trusted_report",
        "targetId": target.id,
        "repositoryUrl": target.repositoryUrl,
        "knownFindingsPath": None,
    }

    monkeypatch.setenv("BUGFINDER_KNOWN_FINDINGS", "/var/lib/bugfinder/known.jsonl")
    pinned = build_spec(config, "medium", source_ref=SHA)
    assert collector_params(pinned, "collect_findings")["knownFindingsPath"] == "/var/lib/bugfinder/known.jsonl"
    assert collector_params(pinned, "collect_reports") == {
        "reportTemplate": "report",
        "trustedNode": "trusted_report",
        "targetId": target.id,
        "repositoryUrl": target.repositoryUrl,
        "knownFindingsPath": "/var/lib/bugfinder/known.jsonl",
        "sourceCommit": SHA,
    }
    assert collector_params(pinned, "snapshot")["sourceRef"] == SHA
    # Every agent prompt names the pinned sha as the source ref, not the moving branch.
    for node in agent_nodes(pinned):
        assert f"- Source ref: {SHA}" in node.prompt and f"- Source ref: {target.sourceRef}" not in node.prompt, node.id
    assert all(f"- Source ref: {target.sourceRef}" in node.prompt for node in agent_nodes(pipeline))


def test_build_pipeline_reads_its_environment_argument_not_the_process(config, workspace, monkeypatch):
    monkeypatch.setenv("BUGFINDER_KNOWN_FINDINGS", "/process/known.jsonl")
    monkeypatch.setenv("BUGFINDER_REPO_PATH", str(workspace / "process-repo"))
    explicit = {"BUGFINDER_WORKSPACE_ROOT": str(workspace / "arg-ws"), "BUGFINDER_KNOWN_FINDINGS": "/arg/known.jsonl"}
    pipeline = build_pipeline(with_history(config, None), TARGET, budget="low", environment=explicit).to_spec()
    assert Path(pipeline.working_dir) == workspace / "arg-ws" / TARGET
    assert collector_params(pipeline, "collect_findings")["knownFindingsPath"] == "/arg/known.jsonl"
    assert collector_params(pipeline, "collect_reports")["knownFindingsPath"] == "/arg/known.jsonl"
    empty = build_pipeline(with_history(config, None), TARGET, budget="low", environment={}).to_spec()
    assert Path(empty.working_dir) == Path(".agentflow/workspaces") / TARGET
    assert collector_params(empty, "collect_findings")["knownFindingsPath"] is None


def test_workflow_retries_apply_to_every_agent_node(config, workspace):
    patched = config.model_copy(update={"workflow": config.workflow.model_copy(update={"retries": 2})})
    pipeline = build_pipeline(with_history(patched, None), TARGET, budget="low").to_spec()
    assert {node.retries for node in agent_nodes(pipeline)} == {2}
    assert {node.retries for node in agent_nodes(build_spec(config, "low"))} == {1}


def test_history_text_resolves_relative_paths_against_the_package(config, tmp_path, monkeypatch):
    target = select_target(config, TARGET)
    assert read_history_text(target) is None
    absolute = tmp_path / "history.txt"
    absolute.write_text(HISTORY, encoding="utf-8")
    assert read_history_text(target.model_copy(update={"historyFile": str(absolute)})) == HISTORY
    assert read_history_text(target.model_copy(update={"historyFile": f"file://{absolute}"})) == HISTORY
    package_dir = tmp_path / "package"
    (package_dir / "history").mkdir(parents=True)
    (package_dir / "history" / "monad.txt").write_text("relative corpus\n", encoding="utf-8")
    monkeypatch.setattr("examples.bugfinder.v3.pipeline.HERE", package_dir)
    assert read_history_text(target.model_copy(update={"historyFile": "history/monad.txt"})) == "relative corpus\n"


def test_python_collector_code_escapes_jinja_openers_and_round_trips():
    params = {
        "historyText": HISTORY,
        "nested": {"{{key": ["{%", "{#", "}}"], "count": 2},
        "unicode": "café {{",
        "empty": {},
    }
    code = python_collector_code("/srv/agentflow", "plan_context_workers", params)
    assert "{{" not in code and "{%" not in code and "{#" not in code
    assert render_template(code, {}).rstrip("\n") == code.rstrip("\n")
    module = ast.parse(code)
    call = module.body[-1].value
    assert call.args[0].value == "plan_context_workers"
    assert json.loads(call.args[1].args[0].value) == params
    assert code.splitlines()[:3] == [
        "import json, sys",
        "sys.path.insert(0, '/srv/agentflow')",
        "from examples.bugfinder.v3 import collectors",
    ]


def test_source_snapshot_and_working_dir(config, workspace, monkeypatch):
    target = select_target(config, TARGET)
    pipeline = build_spec(config, "low")
    assert pipeline.source_snapshot.model_dump(mode="json", by_alias=True) == {
        "repositoryUrl": target.repositoryUrl,
        "inputRef": target.sourceRef,
    }
    assert Path(pipeline.working_dir) == workspace / "workspaces" / TARGET

    pinned = build_spec(config, "low", source_ref=SHA)
    assert pinned.source_snapshot.input_ref == SHA

    monkeypatch.setenv("BUGFINDER_REPO_PATH", str(workspace / "explicit"))
    explicit = build_spec(config, "low")
    assert Path(explicit.working_dir) == workspace / "explicit"


def test_checkout_path_prefers_explicit_repo_then_workspace_root():
    assert checkout_path("monad", {"BUGFINDER_REPO_PATH": "/srv/monad"}) == Path("/srv/monad")
    assert checkout_path("monad", {"BUGFINDER_WORKSPACE_ROOT": "/srv/ws"}) == Path("/srv/ws/monad")
    assert checkout_path("monad", {}) == Path(".agentflow/workspaces/monad")
    assert checkout_path("monad", {"BUGFINDER_REPO_PATH": "", "BUGFINDER_WORKSPACE_ROOT": ""}) == Path(
        ".agentflow/workspaces/monad"
    )


@pytest.mark.parametrize("budget", BUDGETS)
def test_graph_json_round_trips_through_pipeline_spec(config, workspace, budget):
    graph = build_pipeline(with_history(config, None), TARGET, budget=budget)
    assert PipelineSpec.model_validate(json.loads(graph.to_json())) == graph.to_spec()


def test_ensure_checkout_clones_fetches_and_pins(tmp_path: Path):
    source = tmp_path / "source"
    first = init_repository(source)
    checkout = tmp_path / "workspaces" / "monad"

    assert runner.ensure_checkout(str(source), "main", checkout) == first
    assert git(checkout, "rev-parse", "HEAD") == first
    assert (checkout / "README.md").read_text(encoding="utf-8") == "one\n"
    assert subprocess.run(["git", "-C", str(checkout), "symbolic-ref", "-q", "HEAD"], capture_output=True).returncode != 0

    second = commit(source, "two")
    (checkout / "README.md").write_text("dirty\n", encoding="utf-8")
    assert runner.ensure_checkout(str(source), "main", checkout) == second
    assert git(checkout, "rev-parse", "HEAD") == second
    assert (checkout / "README.md").read_text(encoding="utf-8") == "two\n"


def test_resolve_source_uses_explicit_repo_path_head(config, tmp_path: Path):
    source = tmp_path / "source"
    sha = init_repository(source)
    target = select_target(config, TARGET)
    assert runner.resolve_source(target, {"BUGFINDER_REPO_PATH": str(source)}) == (source.resolve(), sha)


def test_main_print_emits_pipeline_json(config, workspace, monkeypatch, capsys):
    calls: list[tuple[str, str, Path]] = []

    def fake_checkout(repository_url: str, source_ref: str, path: Path) -> str:
        calls.append((repository_url, source_ref, path))
        return SHA

    monkeypatch.setattr(runner, "ensure_checkout", fake_checkout)
    assert runner.main(["--target", TARGET, "--budget", "low", "--print"]) == 0
    payload = json.loads(capsys.readouterr().out)
    target = select_target(config, TARGET)
    assert calls == [(target.repositoryUrl, target.sourceRef, (workspace / "workspaces" / TARGET).resolve())]
    assert payload["name"] == f"bugfinder-v3-{TARGET}"
    assert payload["source_snapshot"] == {"repositoryUrl": target.repositoryUrl, "inputRef": SHA}
    assert PipelineSpec.model_validate(payload).node_map["collect_reports"]


def test_main_exit_code_follows_run_status(config, workspace, monkeypatch, capsys):
    statuses = iter((RunStatus.COMPLETED, RunStatus.FAILED))
    seen: list[str] = []
    monkeypatch.setattr(runner, "resolve_source", lambda target, environment=None: (Path("/srv/monad"), SHA))

    def fake_run(graph, runs_dir: str):
        seen.append(runs_dir)
        assert graph.to_spec().source_snapshot.input_ref == SHA
        return SimpleNamespace(id="run-1", status=next(statuses))

    monkeypatch.setattr(runner, "run_graph", fake_run)
    assert runner.main(["--target", TARGET, "--runs-dir", str(workspace / "runs")]) == 0
    assert capsys.readouterr().out.strip() == f"bugfinder-v3 target={TARGET} run=run-1 status=completed"
    assert runner.main(["--target", TARGET]) == 1
    assert capsys.readouterr().out.strip() == f"bugfinder-v3 target={TARGET} run=run-1 status=failed"
    assert seen == [str(workspace / "runs"), runner.DEFAULT_RUNS_DIR]


def test_parse_args_requires_target():
    with pytest.raises(SystemExit):
        runner.parse_args([])
    args = runner.parse_args(["--target", "a", "--target", "b", "--config", "x.yaml"])
    assert args.targets == ["a", "b"] and args.config == Path("x.yaml") and args.budget is None
