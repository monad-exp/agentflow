"""Bugfinder v3 graph builder (DESIGN.md sections 5 and 11)."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Mapping, Sequence

from agentflow import Graph, claude, codex, fanout_from, pi, python_node
from agentflow.dsl import NodeBuilder
from examples.bugfinder.v3.collectors import load_schema
from examples.bugfinder.v3.config import (
    BudgetProfile,
    Profile,
    Target,
    V3Config,
    profiles_for,
    replicas_for,
    resolve_budget,
    select_target,
    validity_profile_ids,
)
from examples.bugfinder.v3.prompts import build_prompt, phase_timeout_minutes


HERE = Path(__file__).resolve().parent
AGENTFLOW_ROOT = HERE.parents[2]
TEMPLATES_DIR = HERE / "templates"
DEFAULT_WORKSPACE_ROOT = ".agentflow/workspaces"
WORKER_ROLE = "workerSmart"
PYTHON_NODE_TIMEOUT_SECONDS = 600
READ_ONLY = "read_only"
READ_WRITE = "read_write"
INPUT_POINTER_HEADING = "## Structured input"

_BUILDERS = {"codex": codex, "claude": claude, "pi": pi}
_PROVIDER_KEYS = ("name", "base_url", "api_key_env", "wire_api")
_JINJA_OPENER = re.compile(r"\{(?=[{%#])")
_COMMIT_SHA = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


@dataclass(frozen=True)
class Slot:
    """One (profile, replica) lane; `key` is the node id suffix."""

    profile_id: str
    replica: int

    @property
    def key(self) -> str:
        return slot_key(self.profile_id, self.replica)

    def to_params(self) -> dict[str, Any]:
        return {"slotKey": self.key, "profileId": self.profile_id, "replica": self.replica}


def slot_key(profile_id: str, replica: int) -> str:
    return profile_id.replace("-", "_") + f"_r{replica}"


def checkout_path(target_id: str, environment: Mapping[str, str] | None = None) -> Path:
    """Pinned worktree: BUGFINDER_REPO_PATH, else <BUGFINDER_WORKSPACE_ROOT>/<target>."""

    values = os.environ if environment is None else environment
    explicit = values.get("BUGFINDER_REPO_PATH")
    if explicit:
        return Path(explicit).expanduser()
    root = values.get("BUGFINDER_WORKSPACE_ROOT") or DEFAULT_WORKSPACE_ROOT
    return Path(root).expanduser() / target_id


def read_history_text(target: Target) -> str | None:
    """Text of `target.historyFile` (plain or file:// path; relative paths resolve against the v3 package)."""

    if not target.historyFile:
        return None
    path = Path(str(target.historyFile).removeprefix("file://")).expanduser()
    if not path.is_absolute():
        path = HERE / path
    return path.read_text(encoding="utf-8")


def _take(profiles: list[str], count: int | str) -> list[str]:
    return list(profiles) if count == "all" else list(profiles[: int(count)])


def _slots(profiles: list[str], replicas: int) -> list[Slot]:
    return [Slot(profile_id, replica) for profile_id in profiles for replica in range(1, replicas + 1)]


def hunt_slots(config: V3Config, budget: BudgetProfile) -> list[Slot]:
    profiles = _take(profiles_for(config, WORKER_ROLE), budget.huntProfiles)
    return _slots(profiles, replicas_for(config, budget, WORKER_ROLE))


def context_slots(config: V3Config, budget: BudgetProfile) -> list[Slot]:
    profiles = _take(profiles_for(config, WORKER_ROLE), budget.contextWorkerProfiles)
    return _slots(profiles, replicas_for(config, budget, WORKER_ROLE))


def impact_profile_id(config: V3Config) -> str:
    return config.phases.triageImpact.profile


def validity_slots(config: V3Config, budget: BudgetProfile) -> list[Slot]:
    """Validity lanes: `config.validity_profile_ids`, one replica each (Smithers parity)."""

    return _slots(_take(validity_profile_ids(config), budget.validityProfiles), 1)


def provider_kwargs(profile: Profile) -> dict[str, Any] | None:
    """The pi provider block as AgentFlow's ProviderConfig keys."""

    if profile.provider is None:
        return None
    return profile.provider.model_dump(include=set(_PROVIDER_KEYS), exclude_none=True)


def agent_node(
    config: V3Config,
    profile_id: str,
    *,
    task_id: str,
    prompt: str,
    schema: dict[str, Any],
    timeout_seconds: int,
    tools: str = READ_ONLY,
    depends_on: Sequence[NodeBuilder] = (),
) -> NodeBuilder:
    """Map a config profile onto a codex()/claude()/pi() node with the section 2 safety settings."""

    profile = config.profiles[profile_id]
    if profile.harness not in _BUILDERS:
        raise ValueError(f"profile {profile_id!r} uses unsupported harness {profile.harness!r}")
    kwargs: dict[str, Any] = {
        "task_id": task_id,
        "prompt": prompt,
        "model": profile.model,
        "tools": tools,
        "repo_instructions_mode": "ignore",
        "retries": config.workflow.retries,
        "retry_backoff_seconds": 2,
        "timeout_seconds": timeout_seconds,
        "concurrency_pool": f"{profile.harness}-provider",
        "success_criteria": [{"kind": "output_json_schema", "schema": schema}],
    }
    if profile.harness == "codex":
        kwargs["extra_args"] = ["-c", f'model_reasoning_effort="{profile.reasoning}"']
    elif profile.harness == "claude":
        kwargs["extra_args"] = ["--effort", profile.reasoning, "--settings", '{"switchModelsOnFlag":false}']
    else:
        kwargs["extra_args"] = ["--thinking", profile.reasoning]
        provider = provider_kwargs(profile)
        if provider is not None:
            kwargs["provider"] = provider
    node = _BUILDERS[profile.harness](**kwargs)
    node.depends_on.extend(dependency.id for dependency in depends_on)
    return node


def input_pointer(sources: Sequence[NodeBuilder]) -> str:
    """Section telling a plain principal node where its trusted collector input lives.

    Only fan-out members receive `node.input`; single principal consumers read the
    collector's `result.json` instead. The Jinja here resolves to orchestrator-produced
    artifact paths of python nodes, never to agent text.
    """

    lines = [
        INPUT_POINTER_HEADING,
        "",
        "The structured input described above is not inlined in this prompt. Read it from the",
        "`structured_output` value of each JSON file below; they are written by trusted collector nodes.",
        "",
    ]
    lines.extend(f"- `{source.id}`: `{{{{ nodes.{source.id}.artifacts.result_json }}}}`" for source in sources)
    return "\n".join(lines)


def python_collector_code(agentflow_root: Path | str, name: str, params: dict[str, Any]) -> str:
    """Python source for a collector node; params travel as a JSON literal free of Jinja openers."""

    compact = json.dumps(params, sort_keys=True, separators=(",", ":"))
    params_json = _JINJA_OPENER.sub(r"\\u007b", compact)
    code = "\n".join(
        [
            "import json, sys",
            f"sys.path.insert(0, {str(agentflow_root)!r})",
            "from examples.bugfinder.v3 import collectors",
            f"collectors.run({name!r}, json.loads({params_json!r}))",
            "",
        ]
    )
    if _JINJA_OPENER.search(code):
        raise ValueError(f"collector {name!r} code contains a Jinja opener after escaping: {code!r}")
    return code


@dataclass
class _Build:
    config: V3Config
    budget: BudgetProfile
    target: Target
    agentflow_root: Path
    python_executable: str
    source_ref: str
    history_text: str | None
    environment: Mapping[str, str]
    _prompts: dict[str, str] = field(default_factory=dict, init=False)
    _schemas: dict[str, dict[str, Any]] = field(default_factory=dict, init=False)

    @property
    def principal(self) -> str:
        return self.config.roles.principal.defaultProfile

    @property
    def cap(self) -> int:
        return self.budget.triageFindingCap

    def schema(self, name: str) -> dict[str, Any]:
        if name not in self._schemas:
            self._schemas[name] = load_schema(name)
        return self._schemas[name]

    def prompt(self, phase: str, schema: str) -> str:
        if phase not in self._prompts:
            self._prompts[phase] = build_prompt(
                phase,
                config=self.config,
                budget=self.budget,
                target=self.target,
                schema=self.schema(schema),
                source_ref=self.source_ref,
            )
        return self._prompts[phase]

    def agent(
        self,
        task_id: str,
        profile_id: str,
        *,
        phase: str,
        schema: str,
        tools: str = READ_ONLY,
        depends_on: Sequence[NodeBuilder] = (),
        input_from: Sequence[NodeBuilder] = (),
    ) -> NodeBuilder:
        """An agent node of `phase`; its timeout is the budget field `prompts.PHASE_TIMEOUT_FIELDS[phase]`."""

        prompt = self.prompt(phase, schema)
        if input_from:
            prompt = f"{prompt.rstrip()}\n\n{input_pointer(input_from)}\n"
        return agent_node(
            self.config,
            profile_id,
            task_id=task_id,
            prompt=prompt,
            schema=self.schema(schema),
            timeout_seconds=phase_timeout_minutes(phase, self.budget) * 60,
            tools=tools,
            depends_on=[*input_from, *depends_on],
        )

    def collector(
        self,
        name: str,
        params: dict[str, Any],
        *,
        depends_on: Sequence[NodeBuilder] = (),
    ) -> NodeBuilder:
        node = python_node(
            task_id=name,
            code=python_collector_code(self.agentflow_root, name, params),
            executable=self.python_executable,
            timeout_seconds=PYTHON_NODE_TIMEOUT_SECONDS,
            repo_instructions_mode="ignore",
        )
        node.depends_on.extend(dependency.id for dependency in depends_on)
        return node

    def fanout_agent(
        self,
        task_id: str,
        profile_id: str,
        *,
        phase: str,
        schema: str,
        source: NodeBuilder,
        path: str,
        as_: str,
        max_items: int,
        snapshot: NodeBuilder,
        tools: str = READ_ONLY,
    ) -> NodeBuilder:
        """A fan-out template over one lane of a collector; every member gets its item as `node.input`."""

        template = self.agent(task_id, profile_id, phase=phase, schema=schema, tools=tools, depends_on=[snapshot])
        return fanout_from(template, source, path=path, as_=as_, max_items=max_items)

    def hunt(self, task_id: str, slot: Slot, *, phase: str, source: NodeBuilder, path: str, snapshot: NodeBuilder) -> NodeBuilder:
        return self.fanout_agent(
            task_id,
            slot.profile_id,
            phase=phase,
            schema="hunt-result",
            source=source,
            path=path,
            as_="attempt",
            max_items=self.budget.maxItemsPerSlot,
            snapshot=snapshot,
        )

    def gate(self, task_id: str, profile_id: str, *, phase: str, schema: str, tools: str, source: NodeBuilder, path: str, snapshot: NodeBuilder) -> NodeBuilder:
        return self.fanout_agent(
            task_id,
            profile_id,
            phase=phase,
            schema=schema,
            source=source,
            path=path,
            as_="finding",
            max_items=self.cap,
            snapshot=snapshot,
            tools=tools,
        )

    def assemble(self) -> None:
        snapshot = self.collector(
            "snapshot",
            {
                "targetId": self.target.id,
                "repositoryUrl": self.target.repositoryUrl,
                "sourceRef": self.source_ref,
                "include": list(self.target.scope.include),
                "exclude": list(self.target.scope.exclude),
            },
        )
        hunts = self.file_hunts(snapshot)
        plan_context = self.collector(
            "plan_context_workers",
            {
                "snapshotNode": snapshot.id,
                "slots": [slot.to_params() for slot in context_slots(self.config, self.budget)],
                "history": self.history_text is not None,
                "historyText": self.history_text,
            },
            depends_on=[snapshot],
        )
        threat_model = self.threat_lane(plan_context, snapshot)
        history_model = None if self.history_text is None else self.history_lane(plan_context, snapshot)
        hunts.extend(self.goal_hunts(threat_model, history_model, snapshot))
        leads = self.collector("collect_leads", {"templates": [hunt.id for hunt in hunts]}, depends_on=hunts)
        self.triage(leads, snapshot)

    def file_hunts(self, snapshot: NodeBuilder) -> list[NodeBuilder]:
        rank = self.agent("rank_files", self.principal, phase="rank", schema="rank", input_from=[snapshot])
        slots = hunt_slots(self.config, self.budget)
        plan = self.collector(
            "plan_file_hunts",
            {
                "rankNode": rank.id,
                "snapshotNode": snapshot.id,
                "threshold": self.budget.fileRankThreshold,
                "maxItemsPerSlot": self.budget.maxItemsPerSlot,
                "slots": [slot.to_params() for slot in slots],
            },
            depends_on=[rank, snapshot],
        )
        return [
            self.hunt(f"file_hunt__{slot.key}", slot, phase="file-hunt", source=plan, path=f"$.lanes.{slot.key}", snapshot=snapshot)
            for slot in slots
        ]

    def context_lane(
        self,
        lane: str,
        node_prefix: str,
        *,
        worker_phase: str,
        worker_schema: str,
        collector_name: str,
        synthesis_id: str,
        synthesis_phase: str,
        synthesis_schema: str,
        model_name: str,
        source_key: str,
        plan_context: NodeBuilder,
        snapshot: NodeBuilder,
    ) -> NodeBuilder:
        """Workers over one lane of plan_context_workers, their collector, the principal synthesis and the frozen model."""

        workers = [
            self.fanout_agent(
                f"{node_prefix}{slot.key}",
                slot.profile_id,
                phase=worker_phase,
                schema=worker_schema,
                source=plan_context,
                path=f"$.{lane}.{slot.key}",
                as_="item",
                max_items=1,
                snapshot=snapshot,
            )
            for slot in context_slots(self.config, self.budget)
        ]
        collected = self.collector(collector_name, {"templates": [worker.id for worker in workers]}, depends_on=workers)
        synthesis = self.agent(
            synthesis_id,
            self.principal,
            phase=synthesis_phase,
            schema=synthesis_schema,
            input_from=[collected],
            depends_on=[snapshot],
        )
        return self.collector(
            model_name,
            {
                "synthesisNode": synthesis.id,
                source_key: collected.id,
                "snapshotNode": snapshot.id,
                "targetId": self.target.id,
            },
            depends_on=[synthesis],
        )

    def threat_lane(self, plan_context: NodeBuilder, snapshot: NodeBuilder) -> NodeBuilder:
        return self.context_lane(
            "threat",
            "threat_model__",
            worker_phase="threat",
            worker_schema="threat-model-draft",
            collector_name="collect_threat_drafts",
            synthesis_id="threat_synthesis",
            synthesis_phase="threat-synthesis",
            synthesis_schema="threat-model-canonical",
            model_name="collect_threat_model",
            source_key="draftsNode",
            plan_context=plan_context,
            snapshot=snapshot,
        )

    def history_lane(self, plan_context: NodeBuilder, snapshot: NodeBuilder) -> NodeBuilder:
        return self.context_lane(
            "history",
            "history_risk__",
            worker_phase="historical-risk-classes",
            worker_schema="history-candidates",
            collector_name="collect_history_candidates",
            synthesis_id="history_synthesis",
            synthesis_phase="historical-synthesis",
            synthesis_schema="history-catalog",
            model_name="collect_history_model",
            source_key="candidatesNode",
            plan_context=plan_context,
            snapshot=snapshot,
        )

    def goal_hunts(
        self,
        threat_model: NodeBuilder,
        history_model: NodeBuilder | None,
        snapshot: NodeBuilder,
    ) -> list[NodeBuilder]:
        models = [threat_model] if history_model is None else [threat_model, history_model]
        goal_plan = self.agent("goal_plan", self.principal, phase="goal-plan", schema="goal-plan", input_from=models, depends_on=[snapshot])
        slots = hunt_slots(self.config, self.budget)
        plan = self.collector(
            "plan_goal_hunts",
            {
                "goalPlanNode": goal_plan.id,
                "threatModelNode": threat_model.id,
                "historyModelNode": None if history_model is None else history_model.id,
                "snapshotNode": snapshot.id,
                "slots": [slot.to_params() for slot in slots],
                "maxRoamGoals": self.budget.maxRoamGoals,
                "maxItemsPerSlot": self.budget.maxItemsPerSlot,
                "templatesDir": str(TEMPLATES_DIR),
            },
            depends_on=[goal_plan],
        )
        lanes = ["threat", "roam"] if history_model is None else ["threat", "historical", "roam"]
        return [
            self.hunt(
                f"goal_hunt__{lane}__{slot.key}",
                slot,
                phase="goal-common",
                source=plan,
                path=f"$.lanes.{lane}__{slot.key}",
                snapshot=snapshot,
            )
            for lane in lanes
            for slot in slots
        ]

    def triage(self, leads: NodeBuilder, snapshot: NodeBuilder) -> None:
        known_findings = self.environment.get("BUGFINDER_KNOWN_FINDINGS") or None
        dedup = self.agent("deduplicate", self.principal, phase="deduplicate", schema="dedup", input_from=[leads], depends_on=[snapshot])
        findings = self.collector(
            "collect_findings",
            {"dedupNode": dedup.id, "leadsNode": leads.id, "cap": self.cap, "knownFindingsPath": known_findings},
            depends_on=[dedup],
        )
        context = self.gate(
            "triage_context",
            self.principal,
            phase="triager-1-context",
            schema="triage-context",
            tools=READ_ONLY,
            source=findings,
            path="$.items",
            snapshot=snapshot,
        )
        slots = validity_slots(self.config, self.budget)
        contexts = self.collector(
            "collect_contexts",
            {
                "gateTemplate": context.id,
                "findingsNode": findings.id,
                "validitySlots": [slot.to_params() for slot in slots],
            },
            depends_on=[context],
        )
        validity = [
            self.gate(
                f"triage_validity__{slot.key}",
                slot.profile_id,
                phase="triager-2-validity",
                schema="triage-evidence",
                tools=READ_WRITE,
                source=contexts,
                path=f"$.validity.{slot.key}",
                snapshot=snapshot,
            )
            for slot in slots
        ]
        validity_bundle = self.collector(
            "collect_validity",
            {"validityTemplates": [node.id for node in validity], "contextsNode": contexts.id},
            depends_on=[*validity, contexts],
        )
        impact = self.gate(
            "triage_impact",
            impact_profile_id(self.config),
            phase="triager-3-impact",
            schema="triage-impact",
            tools=READ_WRITE,
            source=validity_bundle,
            path="$.items",
            snapshot=snapshot,
        )
        trusted = self.collector(
            "trusted_report",
            {
                "impactTemplate": impact.id,
                "validityNode": validity_bundle.id,
                "policy": self.config.triagePolicy.model_dump(mode="json"),
            },
            depends_on=[impact],
        )
        report = self.gate(
            "report",
            self.principal,
            phase="report",
            schema="report",
            tools=READ_ONLY,
            source=trusted,
            path="$.items",
            snapshot=snapshot,
        )
        params: dict[str, Any] = {
            "reportTemplate": report.id,
            "trustedNode": trusted.id,
            "targetId": self.target.id,
            "repositoryUrl": self.target.repositoryUrl,
            "knownFindingsPath": known_findings,
        }
        if _COMMIT_SHA.match(self.source_ref):
            params["sourceCommit"] = self.source_ref
        self.collector("collect_reports", params, depends_on=[report])


def build_pipeline(
    config: V3Config,
    target_id: str,
    *,
    budget: str | None = None,
    agentflow_root: Path | None = None,
    python_executable: str | None = None,
    source_ref: str | None = None,
    environment: Mapping[str, str] | None = None,
) -> Graph:
    """One AgentFlow run per target.

    `source_ref` (the sha run.py resolved) overrides `target.sourceRef`; `environment`
    (default `os.environ`) supplies BUGFINDER_REPO_PATH, BUGFINDER_WORKSPACE_ROOT and
    BUGFINDER_KNOWN_FINDINGS.
    """

    values = os.environ if environment is None else environment
    target = select_target(config, target_id)
    profile = resolve_budget(config, budget)
    build = _Build(
        config=config,
        budget=profile,
        target=target,
        agentflow_root=Path(agentflow_root or AGENTFLOW_ROOT),
        python_executable=python_executable or sys.executable,
        source_ref=source_ref or target.sourceRef,
        history_text=read_history_text(target),
        environment=values,
    )
    with Graph(
        f"bugfinder-v3-{target.id}",
        description="Bugfinder v3: ranked file hunts, threat-model goals and three-gate triage",
        working_dir=str(checkout_path(target.id, values)),
        source_snapshot={"repositoryUrl": target.repositoryUrl, "inputRef": build.source_ref},
        concurrency=profile.engineConcurrency,
        deadline_seconds=None if profile.deadlineHours is None else int(profile.deadlineHours) * 3600,
        fail_fast=False,
        concurrency_pools={
            "codex-provider": profile.pools.codex,
            "claude-provider": profile.pools.claude,
            "pi-provider": profile.pools.pi,
        },
    ) as graph:
        build.assemble()
    return graph
