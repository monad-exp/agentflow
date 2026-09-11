"""End-to-end run of the bugfinder v3 graph with deterministic fixture agents (DESIGN.md section 12).

The fixture adapter stands in for codex, claude and pi. Each agent node prints one
event in the stream format its harness parser expects, whose text is a canned JSON
object chosen by node id prefix and by the structured input the orchestrator hands
the node (`node.input`). Plain principal nodes read their upstream collector's
`result.json`, exactly as the `## Structured input` section tells a real agent to.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from agentflow.agents.base import AgentAdapter
from agentflow.agents.registry import AdapterRegistry
from agentflow.orchestrator import Orchestrator
from agentflow.prepared import ExecutionPaths, PreparedExecution
from agentflow.runners.registry import RunnerRegistry
from agentflow.specs import AgentKind, NodeSpec, NodeStatus, RunRecord
from agentflow.store import RunStore
from examples.bugfinder.v3.config import load_config
from examples.bugfinder.v3.pipeline import build_pipeline

REPOSITORY_URL = "https://github.com/category-labs/monad"
DOCS_URL = "https://docs.monad.xyz/developer-essentials/differences"
BOUNTY_URL = "https://gist.github.com/aviggiano/bbae44300630a2cc9642a7a58ef28fd0"
BOUNTY_REVISION = "908010ff44cbb1c66a96f0215ddd4f926946421b"
FINDING_KEY = "parser-mode-cache-confusion"
HUNT_LEADS = {
    "FILE": ("file-key-omits-mode", "src/parser.ts:42"),
    "THREAT_MODEL": ("threat-cache-reuses-mode", "src/cache.ts:17"),
}
FIXTURE_AGENTS = (AgentKind.CODEX, AgentKind.CLAUDE, AgentKind.PI)
HUNT_SLOTS = ("codex_gpt_5_6_sol_r1", "claude_code_fable_5_r1")
VALIDITY_SLOTS = ("codex_gpt_5_6_sol_r1", "claude_code_opus_5_r1")
INPUT_BLOCK = "AgentFlow structured input (JSON):\n```json"

ACTOR = {
    "key": "tx-sender",
    "name": "Transaction sender",
    "role": "Unprivileged network user",
    "capabilities": ["submit signed transactions"],
    "controlledInputs": ["calldata"],
    "excludedPowers": ["validator keys"],
    "sourceRefs": ["src/parser.ts"],
}
ASSET = {
    "key": "parse-cache",
    "name": "Parser cache",
    "protectedResource": "Cached parse results",
    "securityProperties": ["integrity"],
    "compromiseConsequences": ["execution under the wrong grammar semantics"],
    "sourceRefs": ["src/cache.ts"],
}
BOUNDARY = {
    "key": "rpc",
    "name": "RPC boundary",
    "sides": ["client", "node"],
    "entryPoints": ["eth_sendRawTransaction"],
    "enforcedChecks": ["signature verification"],
    "sourceRefs": ["src/parser.ts"],
}
THREAT = {
    "key": "cache-mode-confusion",
    "title": "Parser cache ignores parse mode",
    "violation": "A cached parse result is reused under a different parse mode",
    "securityProperty": "integrity",
    "attackSurface": ["src/cache.ts"],
    "preconditions": ["two callers parse the same source under different modes"],
    "expectedImpact": "Consensus-relevant validation runs against the wrong AST",
    "existingControls": [],
    "confidence": "high",
    "openQuestions": [],
    "actorKeys": ["tx-sender"],
    "assetKeys": ["parse-cache"],
    "boundaryKeys": ["rpc"],
    "sourceRefs": ["src/cache.ts:17"],
}


def _git(repository: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repository), *args], text=True).strip()


def _fixture_repository(path: Path) -> str:
    path.mkdir()
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    _git(path, "config", "user.email", "fixture@example.test")
    _git(path, "config", "user.name", "Fixture")
    (path / "src").mkdir()
    (path / "src" / "parser.ts").write_text("export const parser = 'fixture';\n", encoding="utf-8")
    (path / "src" / "cache.ts").write_text("export const cache = new Map();\n", encoding="utf-8")
    _git(path, "add", ".")
    _git(path, "commit", "-qm", "fixture")
    return _git(path, "rev-parse", "HEAD")


def _citations() -> list[dict[str, str]]:
    return [
        {
            "kind": "documentation",
            "url": DOCS_URL,
            "revision": "2026-09-01",
            "excerpt": "Execution follows Ethereum semantics unless documented otherwise.",
        },
        {
            "kind": "bounty-terms",
            "url": BOUNTY_URL,
            "revision": BOUNTY_REVISION,
            "excerpt": "Execution and consensus client bugs are in scope.",
        },
    ]


def _guidance() -> dict[str, Any]:
    return {
        "expectedBehavior": "A cache key must include every input that changes the cached result.",
        "documentationStatus": "SUPPORTED",
        "bountyStatus": "IN_SCOPE",
        "references": _citations(),
    }


def _unknown_guidance() -> dict[str, Any]:
    return {
        "expectedBehavior": "Not assessed.",
        "documentationStatus": "UNKNOWN",
        "bountyStatus": "UNKNOWN",
        "references": [],
    }


def _draft() -> dict[str, Any]:
    return {
        "summary": "Parser and cache seam of the fixture repository.",
        "scope": "src/parser.ts and src/cache.ts",
        "assumptions": ["honest validators run unmodified code"],
        "exclusions": ["physical access"],
        "actors": [ACTOR],
        "assets": [ASSET],
        "trustBoundaries": [BOUNDARY],
        "threats": [THREAT],
    }


def _canonical(attempt_ids: list[str]) -> dict[str, Any]:
    entities = (("actor", ACTOR), ("asset", ASSET), ("trust_boundary", BOUNDARY), ("threat", THREAT))
    return {
        **_draft(),
        "sourceModels": [{"attemptId": attempt_id} for attempt_id in attempt_ids],
        "entityMappings": [
            {
                "sourceAttemptId": attempt_id,
                "entityType": entity_type,
                "sourceKey": entity["key"],
                "canonicalKey": entity["key"],
                "disposition": "RETAINED",
                "rationale": None,
            }
            for attempt_id in attempt_ids
            for entity_type, entity in entities
        ],
        "disagreements": [],
    }


def _goal_plan(threat_id: str) -> dict[str, Any]:
    return {
        "goals": [
            {
                "callerKey": "goal-cache-mode",
                "kind": "THREAT_MODEL",
                "threatId": threat_id,
                "outcome": "Show a cached parse result served under the wrong mode.",
                "scope": "src/cache.ts and src/parser.ts",
                "attackerCapabilities": ["submit signed transactions"],
                "excludedPreconditions": ["validator keys"],
                "evidenceBar": "A unit test that primes one mode and observes the other.",
            }
        ],
        "historyDispositions": [],
    }


def _hunt_result(attempt: dict[str, Any]) -> dict[str, Any]:
    caller_key, location = HUNT_LEADS[attempt["kind"]]
    return {
        "result": "BUG_FOUND",
        "summary": "Committed one concrete cache-confusion lead.",
        "leads": [
            {
                "callerKey": caller_key,
                "claim": "Parser mode is omitted from a cache key reused across the parser/cache seam.",
                "locations": [location],
                "evidence": "The shared key contains source text but no parse mode.",
                "attackerPreconditions": None,
                "impact": "A caller can receive an AST produced under different grammar semantics.",
                "validationPlan": "Prime one mode and request the same source under another mode.",
            }
        ],
    }


def _context(finding: dict[str, Any]) -> dict[str, Any]:
    commit = finding["leads"][0]["sourceCommit"]
    if finding["finding"]["origin"] == "singleton":
        return {
            "disposition": "INCONCLUSIVE",
            "rationale": "A single unreviewed lead without corroboration.",
            "guidanceReview": _unknown_guidance(),
            "knownIssueSearch": {"status": "PARTIAL", "sources": [], "matches": []},
            "targetCommit": commit,
            "fixCommit": None,
            "validityRequired": False,
            "impactRequired": False,
            "existingEvidenceIds": [],
            "validityMethods": [],
            "impactMethods": [],
        }
    return {
        "disposition": "REVIEW",
        "rationale": "No known issue matches; the documented behaviour contradicts the observed one.",
        "guidanceReview": _guidance(),
        "knownIssueSearch": {
            "status": "COMPLETE",
            "sources": ["github:category-labs/monad issues", "known-findings corpus"],
            "matches": [],
        },
        "targetCommit": commit,
        "fixCommit": None,
        "validityRequired": True,
        "impactRequired": True,
        "existingEvidenceIds": [],
        "validityMethods": ["UNIT"],
        "impactMethods": ["SOLONET"],
    }


def _validity() -> dict[str, Any]:
    return {
        "stage": "VALIDITY",
        "state": "PROVEN",
        "summary": "A unit test primes one mode and observes the cached AST under the other.",
        "guidanceReview": _guidance(),
        "evidenceIds": ["ev-unit-1"],
        "methods": ["UNIT"],
        "productionAssessment": None,
        "differentialResults": [],
    }


def _impact(finding: dict[str, Any]) -> dict[str, Any]:
    if finding["context"]["disposition"] != "REVIEW":
        return {
            "decision": "INCONCLUSIVE",
            "reason": "UNPROVEN",
            "mechanism": "UNKNOWN",
            "reachability": "UNKNOWN",
            "impactSupport": "UNKNOWN",
            "guidanceReview": _unknown_guidance(),
            "evidenceIds": [],
            "rationale": "Echoing the context gate: no experiments were scheduled.",
            "limitations": [],
            "nonRuntimeJustification": None,
            "impactEvidence": [],
            "impact": None,
            "likelihood": None,
            "ambiguousCellChoice": None,
            "pocProvided": False,
            "pocEnvironment": "none",
            "localFullNodeDemonstrated": False,
            "publicEntryPointDemonstrated": False,
        }
    commit = finding["context"]["targetCommit"]
    return {
        "decision": "CONFIRMED",
        "reason": None,
        "mechanism": "SUPPORTED",
        "reachability": "SUPPORTED",
        "impactSupport": "SUPPORTED",
        "guidanceReview": _guidance(),
        "evidenceIds": ["ev-unit-1", "ev-solonet-1"],
        "rationale": "A solonet transaction reproduces the wrong-mode AST on an unmodified full node.",
        "limitations": [],
        "nonRuntimeJustification": None,
        "impactEvidence": [
            {
                "stage": "IMPACT",
                "state": "PROVEN",
                "summary": "Solonet reproduction against unmodified honest nodes.",
                "guidanceReview": _guidance(),
                "evidenceIds": ["ev-solonet-1"],
                "methods": ["SOLONET"],
                "productionAssessment": {
                    "network": "solonet",
                    "executionCommit": commit,
                    "consensusCommit": commit,
                    "protocolRevision": "v1",
                    "attackerCapabilities": ["unprivileged transaction sender"],
                    "entryPath": ["eth_sendRawTransaction", "parser.parse"],
                    "defenseChecks": ["cache key validation"],
                    "honestNodesUnmodified": True,
                    "mutationManifestRef": "manifests/none.json",
                    "environmentEquivalent": True,
                    "evidenceIds": ["ev-solonet-1"],
                },
                "differentialResults": [],
            }
        ],
        "impact": "HIGH",
        "likelihood": "HIGH",
        "ambiguousCellChoice": None,
        "pocProvided": True,
        "pocEnvironment": "solonet",
        "localFullNodeDemonstrated": True,
        "publicEntryPointDemonstrated": True,
    }


def _report(handoff: dict[str, Any]) -> dict[str, Any]:
    finding_id = handoff["findingId"]
    commit = handoff["context"]["targetCommit"]
    markdown = (
        f"# {handoff['finding']['title']}\n\n"
        f"Finding `{finding_id}`, severity {handoff['severity']}.\n\n"
        f"Location: {REPOSITORY_URL}/blob/{commit}/src/parser.ts#L42\n"
    )
    return {"findingId": finding_id, "markdown": markdown}


def _event_line(agent: AgentKind, text: str) -> str:
    """One stream event carrying the final assistant text, in the parser format of `agent`."""

    if agent == AgentKind.CODEX:
        payload: dict[str, Any] = {
            "type": "response.output_item.done",
            "item": {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": text}]},
        }
    elif agent == AgentKind.CLAUDE:
        payload = {"type": "result", "subtype": "success", "result": text}
    elif agent == AgentKind.PI:
        payload = {"type": "message_end", "message": {"role": "assistant", "content": [{"type": "text", "text": text}]}}
    else:
        raise AssertionError(f"no fixture event format for {agent}")
    return json.dumps(payload)


class V3FixtureAdapter(AgentAdapter):
    """Deterministic stand-in for every model harness: one canned JSON response per node."""

    def __init__(self, *, omit_lead: bool = False) -> None:
        self.omit_lead = omit_lead
        self.omitted_lead_ids: list[str] = []
        self.prompts: dict[str, str] = {}

    def prepare(self, node: NodeSpec, prompt: str, paths: ExecutionPaths) -> PreparedExecution:
        self.prompts[node.id] = prompt
        run_dir = Path(node.env["AGENTFLOW_RUN_DIR"])
        response = self.response(node.id, node.input, run_dir)
        return PreparedExecution(
            command=["cat", str(Path(paths.target_runtime_dir) / "events.jsonl")],
            env={},
            cwd=paths.target_workdir,
            trace_kind=node.agent.value,
            runtime_files={"events.jsonl": _event_line(node.agent, json.dumps(response)) + "\n"},
        )

    def response(self, node_id: str, item: Any, run_dir: Path) -> dict[str, Any]:
        def upstream(collector: str) -> dict[str, Any]:
            path = run_dir / "artifacts" / collector / "result.json"
            return json.loads(path.read_text(encoding="utf-8"))["structured_output"]

        if node_id == "rank_files":
            return {
                "rankedFiles": [
                    {
                        "path": path,
                        "score": 5 if path.endswith("parser.ts") else 2,
                        "securityObjective": "Audit parse-mode cache construction.",
                        "rationale": "Parser output feeds validation.",
                    }
                    for path in upstream("snapshot")["scopeFiles"]
                ]
            }
        if node_id.startswith(("file_hunt__", "goal_hunt__")):
            return _hunt_result(item)
        if node_id.startswith("threat_model__"):
            return _draft()
        if node_id == "threat_synthesis":
            return _canonical([draft["attemptId"] for draft in upstream("collect_threat_drafts")["drafts"]])
        if node_id == "goal_plan":
            return _goal_plan(upstream("collect_threat_model")["threatModel"]["threats"][0]["threatId"])
        if node_id == "deduplicate":
            leads = upstream("collect_leads")["leads"]
            if self.omit_lead:
                self.omitted_lead_ids.append(leads.pop()["leadId"])
            return {
                "findings": [
                    {
                        "callerKey": FINDING_KEY,
                        "title": "Parser cache can return an AST for the wrong mode",
                        "rootCause": "Parser mode is omitted from the shared cache key.",
                        "impact": "Validation can use the wrong AST semantics.",
                        "leadIds": [lead["leadId"] for lead in leads],
                    }
                ]
            }
        if node_id.startswith("triage_context"):
            return _context(item)
        if node_id.startswith("triage_validity__"):
            return _validity()
        if node_id.startswith("triage_impact"):
            return _impact(item)
        if node_id.startswith("report"):
            return _report(item)
        raise AssertionError(f"unexpected agent node {node_id}")


async def _run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, adapter: V3FixtureAdapter) -> tuple[RunRecord, RunStore, str]:
    repository = tmp_path / "repository"
    sha = _fixture_repository(repository)
    monkeypatch.setenv("BUGFINDER_REPO_PATH", str(repository))
    monkeypatch.setenv("BUGFINDER_KNOWN_FINDINGS", str(tmp_path / "known" / "findings.jsonl"))
    pipeline = build_pipeline(load_config(), "monad", budget="low", source_ref=sha).to_spec()

    adapters = AdapterRegistry()
    for kind in FIXTURE_AGENTS:
        adapters.register(kind, adapter)
    store = RunStore(tmp_path / "runs")
    orchestrator = Orchestrator(store=store, adapters=adapters, runners=RunnerRegistry())
    submitted = await orchestrator.submit(pipeline)
    completed = await orchestrator.wait(submitted.id, timeout=180)
    return completed, store, sha


def _assert_all_nodes_completed(completed: RunRecord) -> None:
    statuses = {node_id: result.status for node_id, result in completed.nodes.items()}
    assert completed.status.value == "completed", statuses
    assert all(status == NodeStatus.COMPLETED for status in statuses.values()), statuses
    retried = {node_id: len(result.attempts) for node_id, result in completed.nodes.items() if len(result.attempts) > 1}
    assert not retried, retried


def _artifact(store: RunStore, run_id: str, node_id: str, name: str) -> Any:
    return json.loads(store.read_artifact_text(run_id, node_id, name))


@pytest.mark.asyncio
async def test_low_budget_run_confirms_one_high_finding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    adapter = V3FixtureAdapter()
    completed, store, sha = await _run(tmp_path, monkeypatch, adapter)
    _assert_all_nodes_completed(completed)
    assert completed.source_snapshot is not None and completed.source_snapshot.commit_sha == sha

    fanouts = completed.pipeline.fanouts
    for slot in HUNT_SLOTS:
        assert len(fanouts[f"file_hunt__{slot}"]) == 1
        assert len(fanouts[f"threat_model__{slot}"]) == 1
        assert len(fanouts[f"goal_hunt__threat__{slot}"]) == 1
        assert fanouts[f"goal_hunt__roam__{slot}"] == []
    assert len(fanouts["triage_context"]) == 1
    assert all(len(fanouts[f"triage_validity__{slot}"]) == 1 for slot in VALIDITY_SLOTS)
    assert len(fanouts["triage_impact"]) == 1 and len(fanouts["report"]) == 1

    leads = completed.nodes["collect_leads"].structured_output["leads"]
    assert len(leads) == 4 and {lead["sourceCommit"] for lead in leads} == {sha}
    assert completed.nodes["collect_threat_model"].structured_output["threatModel"]["sourceCommit"] == sha

    trusted = _artifact(store, completed.id, "trusted_report", "trusted-report.json")
    [finding_id] = trusted["findingIds"]
    assert trusted["dispositions"] == [
        {"findingId": finding_id, "decision": "CONFIRMED", "reason": None, "severity": "HIGH", "blockers": []}
    ]
    assert trusted["deferredFindingIds"] == []
    [handoff] = completed.nodes["trusted_report"].structured_output["items"]
    assert sorted(handoff["finding"]["leadIds"]) == sorted(lead["leadId"] for lead in leads)
    impact = handoff["impactDecision"]
    assert (impact["impact"], impact["likelihood"]) == ("HIGH", "HIGH")
    assert impact["pocProvided"] is True and impact["pocEnvironment"] == "solonet"
    assert len(handoff["validityAttempts"]) == 2

    report = store.read_artifact_text(completed.id, "collect_reports", f"reports/{finding_id}.md")
    assert report.startswith("# ") and finding_id in report and f"blob/{sha}/" in report
    summary = _artifact(store, completed.id, "collect_reports", "run-summary.json")
    assert summary["runId"] == completed.id and summary["sourceCommit"] == sha
    assert summary["findingIds"] == [finding_id] and summary["rejected"] == [] and summary["missing"] == []
    assert [entry["findingId"] for entry in summary["reports"]] == [finding_id]

    known = (tmp_path / "known" / "findings.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(known) == 1
    record = json.loads(known[0])
    assert record["findingId"] == finding_id and record["runId"] == completed.id
    assert (record["decision"], record["severity"], record["targetId"], record["sourceCommit"]) == (
        "CONFIRMED",
        "HIGH",
        "monad",
        sha,
    )
    assert record["reportPath"].endswith(f"reports/{finding_id}.md")

    leads_result = str(store.artifact_path(completed.id, "collect_leads", "result.json"))
    assert leads_result in adapter.prompts["deduplicate"]
    assert INPUT_BLOCK not in adapter.prompts["deduplicate"]
    [impact_member] = fanouts["triage_impact"]
    assert sha in adapter.prompts[impact_member]
    assert INPUT_BLOCK in adapter.prompts[impact_member]
    assert all("{{" not in prompt for prompt in adapter.prompts.values())


@pytest.mark.asyncio
async def test_dedup_omitting_a_lead_yields_a_singleton_finding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    adapter = V3FixtureAdapter(omit_lead=True)
    completed, store, sha = await _run(tmp_path, monkeypatch, adapter)
    _assert_all_nodes_completed(completed)
    [omitted] = adapter.omitted_lead_ids

    findings = _artifact(store, completed.id, "collect_findings", "findings.json")
    assert [item["finding"]["origin"] for item in findings["items"]] == ["dedup", "singleton"]
    dedup_item, singleton_item = findings["items"]
    assert omitted not in dedup_item["finding"]["leadIds"] and len(dedup_item["finding"]["leadIds"]) == 3
    singleton = singleton_item["finding"]
    assert singleton["leadIds"] == [omitted] and singleton["callerKey"] == f"singleton:{omitted}"
    assert f"lead {omitted} was not assigned by dedup; created a singleton finding" in findings["log"]

    fanouts = completed.pipeline.fanouts
    assert len(fanouts["triage_context"]) == 2 and len(fanouts["triage_impact"]) == 2
    assert all(len(fanouts[f"triage_validity__{slot}"]) == 1 for slot in VALIDITY_SLOTS)
    assert len(fanouts["report"]) == 1

    trusted = _artifact(store, completed.id, "trusted_report", "trusted-report.json")
    assert trusted["findingIds"] == [dedup_item["findingId"]]
    dispositions = {entry["findingId"]: entry for entry in trusted["dispositions"]}
    assert dispositions[dedup_item["findingId"]]["decision"] == "CONFIRMED"
    assert dispositions[singleton["findingId"]] == {
        "findingId": singleton["findingId"],
        "decision": "INCONCLUSIVE",
        "reason": "UNPROVEN",
        "severity": None,
        "blockers": [],
    }
    summary = _artifact(store, completed.id, "collect_reports", "run-summary.json")
    assert [entry["findingId"] for entry in summary["reports"]] == [dedup_item["findingId"]]
    assert summary["rejected"] == [] and summary["missing"] == [] and summary["sourceCommit"] == sha
    known = (tmp_path / "known" / "findings.jsonl").read_text(encoding="utf-8").splitlines()
    assert sorted(json.loads(line)["decision"] for line in known) == ["CONFIRMED", "INCONCLUSIVE"]
