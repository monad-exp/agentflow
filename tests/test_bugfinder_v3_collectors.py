from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from agentflow.contracts import parse_json_output
from agentflow.output_capture import BoundedLineBuffer
from examples.bugfinder.v3 import collectors, rendering
from examples.bugfinder.v3.collectors import CollectorError, RunView
from examples.bugfinder.v3.policy import Decision
from tests.test_bugfinder_v3_schemas import (
    BOUNTY_CITATION,
    DOC_CITATION,
    ISSUE_CITATION,
    sample_canonical,
    sample_candidate,
    sample_catalog,
    sample_context,
    sample_dedup,
    sample_draft,
    sample_evidence,
    sample_goal,
    sample_goal_plan,
    sample_guidance,
    sample_hunt,
    sample_impact,
    sample_lead,
    sample_rank,
    sample_report,
    sample_threat,
)

COMMIT = "c" * 40
SLOTS = [{"slotKey": "p1_r1", "profileId": "p1", "replica": 1}, {"slotKey": "p2_r1", "profileId": "p2", "replica": 1}]
SNAPSHOT = {"targetId": "monad", "sourceCommit": COMMIT, "scopeFiles": ["src/a.rs", "src/b.rs", "src/c.rs"]}
FILE_HUNT_PARAMS = {"rankNode": "rank_files", "snapshotNode": "snapshot", "threshold": 3, "maxItemsPerSlot": 256, "slots": SLOTS}
CONTEXT_WORKER_PARAMS = {"snapshotNode": "snapshot", "slots": SLOTS, "history": True, "historyText": "issue #1: quorum"}
REPOSITORY_URL = "https://github.com/category-labs/monad"
_UNSET = object()


class FakeRun:
    """Builds ``<runs>/<run>/run.json`` plus ``artifacts/<node>/result.json`` fixtures."""

    def __init__(self, root: Path, run_id: str = "run-1", node_id: str = "collector") -> None:
        self.run_dir = root / "runs" / run_id
        self.run_id = run_id
        self.node_id = node_id
        self.fanouts: dict[str, list[str]] = {}
        self.specs: list[dict[str, Any]] = []
        self.states: dict[str, str] = {}
        self.outputs: dict[str, Any] = {}

    def node(self, node_id: str, output: Any = _UNSET, *, status: str = "completed", input: Any = None) -> "FakeRun":
        self.specs.append({"id": node_id, "input": input})
        self.states[node_id] = status
        if output is not _UNSET:
            self.outputs[node_id] = output
        return self

    def member(self, template: str, output: Any = _UNSET, *, status: str = "completed", input: Any = None) -> str:
        members = self.fanouts.setdefault(template, [])
        node_id = f"{template}_{len(members)}"
        members.append(node_id)
        self.node(node_id, output, status=status, input=input)
        return node_id

    def run_json(self) -> dict[str, Any]:
        return {
            "id": self.run_id,
            "status": "running",
            "pipeline": {"name": "fake", "fanouts": self.fanouts, "nodes": self.specs},
            "nodes": {node_id: {"node_id": node_id, "status": status} for node_id, status in self.states.items()},
        }

    def view(self) -> RunView:
        self.run_dir.mkdir(parents=True, exist_ok=True)
        (self.run_dir / "run.json").write_text(json.dumps(self.run_json(), indent=2), encoding="utf-8")
        for node_id, output in self.outputs.items():
            artifact_dir = self.run_dir / "artifacts" / node_id
            artifact_dir.mkdir(parents=True, exist_ok=True)
            (artifact_dir / "result.json").write_text(
                json.dumps({"node_id": node_id, "status": self.states[node_id], "structured_output": output}), encoding="utf-8"
            )
        return RunView(self.run_dir, self.run_id, self.node_id)


def attempt_item(kind: str, work_item_id: str, slot: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {
        "attemptId": collectors.attempt_id(kind, work_item_id, slot["profileId"], slot["replica"]),
        "kind": kind,
        "workItemId": work_item_id,
        "profileId": slot["profileId"],
        "replica": slot["replica"],
        "slotKey": slot["slotKey"],
        "sourceCommit": COMMIT,
        **extra,
    }


def lead_row(attempt: str, caller_key: str, **extra: Any) -> dict[str, Any]:
    lead = sample_lead(caller_key)
    return {
        "leadId": collectors.lead_id(attempt, caller_key),
        "attemptId": attempt,
        "kind": "FILE",
        "workItemId": "file:src/a.rs",
        "path": "src/a.rs",
        "threatId": None,
        "sourceCommit": COMMIT,
        **lead,
        **extra,
    }


def finding_item(finding_id_key: str, leads: list[dict[str, Any]], title: str = "Minority quorum") -> dict[str, Any]:
    finding = {
        "findingId": collectors.finding_id(finding_id_key),
        "callerKey": finding_id_key,
        "title": title,
        "rootCause": "unweighted quorum",
        "impact": "safety",
        "leadIds": sorted(lead["leadId"] for lead in leads),
        "origin": "dedup",
    }
    return {"findingId": finding["findingId"], "finding": finding, "leads": leads, "discoveryOutcomes": [], "knownFindingCandidates": []}


# --------------------------------------------------------------------------- RunView


def test_run_view_retries_a_half_written_run_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    fake = FakeRun(tmp_path).node("a", {"x": 1}, input={"attemptId": "A"})
    fake.fanouts["tmpl"] = ["a"]
    view = fake.view()
    complete = (fake.run_dir / "run.json").read_text(encoding="utf-8")
    (fake.run_dir / "run.json").write_text(complete[: len(complete) // 2], encoding="utf-8")
    sleeps: list[float] = []

    def finish_write(seconds: float) -> None:
        sleeps.append(seconds)
        (fake.run_dir / "run.json").write_text(complete, encoding="utf-8")

    monkeypatch.setattr(collectors.time, "sleep", finish_write)
    assert view.fanout_members("tmpl") == ["a"]
    assert sleeps == [collectors.RUN_JSON_RETRY_SECONDS]
    assert view.node_status("a") == "completed"
    assert view.structured_output("a") == {"x": 1}
    assert view.structured_output("missing") is None
    assert view.node_input("a") == {"attemptId": "A"}
    assert view.fanout_members("never-expanded") == []
    with pytest.raises(CollectorError):
        view.node_status("unknown")


def test_run_view_gives_up_after_three_attempts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    fake = FakeRun(tmp_path)
    fake.run_dir.mkdir(parents=True)
    (fake.run_dir / "run.json").write_text("{not json", encoding="utf-8")
    sleeps: list[float] = []
    monkeypatch.setattr(collectors.time, "sleep", sleeps.append)
    with pytest.raises(CollectorError, match="not valid JSON after 3 attempts"):
        RunView(fake.run_dir, "run-1", "collector").fanout_members("x")
    assert len(sleeps) == 2


def test_run_view_writes_artifacts_under_its_own_node(tmp_path: Path):
    view = FakeRun(tmp_path, node_id="collect_reports").view()
    path = view.write_json("reports/finding_x.json", {"b": 1, "a": [2]})
    assert path == tmp_path / "runs" / "run-1" / "artifacts" / "collect_reports" / "reports" / "finding_x.json"
    assert path.read_text(encoding="utf-8") == '{\n  "a": [\n    2\n  ],\n  "b": 1\n}\n'


def test_run_dispatches_by_name_and_prints_compact_sorted_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys):
    fake = FakeRun(tmp_path, node_id="plan_context_workers").node("snapshot", SNAPSHOT)
    fake.view()
    monkeypatch.setenv("AGENTFLOW_RUN_DIR", str(fake.run_dir))
    monkeypatch.setenv("AGENTFLOW_RUN_ID", fake.run_id)
    monkeypatch.setenv("AGENTFLOW_NODE_ID", fake.node_id)
    collectors.run("plan_context_workers", {"snapshotNode": "snapshot", "slots": SLOTS[:1], "history": False, "historyText": ""})
    out = capsys.readouterr().out
    assert out.endswith("\n") and "\n" not in out[:-1] and ": " not in out and ", " not in out
    assert json.loads(out) == {
        "history": {},
        "sourceCommit": COMMIT,
        "threat": {
            "p1_r1": [
                {
                    "attemptId": "THREAT_DRAFT:threat-model:p1:r1",
                    "kind": "THREAT_DRAFT",
                    "profileId": "p1",
                    "replica": 1,
                    "slotKey": "p1_r1",
                    "sourceCommit": COMMIT,
                    "targetId": "monad",
                    "workItemId": "threat-model",
                }
            ]
        },
    }
    with pytest.raises(CollectorError, match="unknown collector"):
        collectors.run("nope", {})
    monkeypatch.delenv("AGENTFLOW_NODE_ID")
    with pytest.raises(CollectorError, match="AGENTFLOW_NODE_ID"):
        collectors.run("plan_context_workers", {})


def test_run_refuses_output_above_the_retained_stream_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys):
    # Why the cap exists: AgentFlow keeps the newest 1 MiB of a node's stdout per attempt, so a
    # single JSON line above that is cut to its tail and the fan-out source no longer parses.
    oversized = collectors.dumps({"lanes": {"slot_0": [{"attemptId": f"FILE:file:{i}", "path": f"src/{i}.rs"} for i in range(30_000)]}})
    assert len(oversized.encode("utf-8")) > collectors.MAX_OUTPUT_BYTES
    buffer = BoundedLineBuffer()
    buffer.append(oversized)
    retained = "\n".join(buffer.as_list())
    assert retained.startswith("[AgentFlow output truncated")
    value, error = parse_json_output(retained)
    assert value is None and error is not None

    fake = FakeRun(tmp_path, node_id="plan_context_workers").node("snapshot", SNAPSHOT)
    fake.view()
    monkeypatch.setenv("AGENTFLOW_RUN_DIR", str(fake.run_dir))
    monkeypatch.setenv("AGENTFLOW_RUN_ID", fake.run_id)
    monkeypatch.setenv("AGENTFLOW_NODE_ID", fake.node_id)
    monkeypatch.setattr(collectors, "MAX_OUTPUT_BYTES", 256)
    with pytest.raises(CollectorError, match=r"output is \d+ bytes, above the 256-byte limit"):
        collectors.run("plan_context_workers", {"snapshotNode": "snapshot", "slots": SLOTS, "history": False, "historyText": ""})
    assert capsys.readouterr().out == ""


# --------------------------------------------------------------------------- planners


def test_snapshot_resolves_head_and_applies_scope_globs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repo = tmp_path / "repo"
    for relative in ("src/a.rs", "src/gen/x.rs", "docs/guide.md", "README.md"):
        path = repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x\n", encoding="utf-8")
    env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "init"], cwd=repo, check=True, env={**env, "PATH": "/usr/bin:/bin"})
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()
    monkeypatch.chdir(repo)
    view = FakeRun(tmp_path, node_id="snapshot").view()
    params = {"targetId": "monad", "repositoryUrl": "https://example.test/monad.git", "sourceRef": "main", "include": ["src/**"], "exclude": ["**/gen/**"]}
    result = collectors.collect_snapshot(view, params)
    assert result["sourceCommit"] == head
    assert result["scopeFiles"] == ["src/a.rs"]
    assert result["trackedFileCount"] == 4
    assert Path(result["scopeFilesPath"]).read_text(encoding="utf-8") == "src/a.rs\n"
    everything = collectors.collect_snapshot(view, {**params, "include": [], "exclude": ["*.md"]})
    assert everything["scopeFiles"] == ["src/a.rs", "src/gen/x.rs"]


def test_plan_file_hunts_filters_by_threshold_and_repairs_unranked_files(tmp_path: Path):
    rank = sample_rank()
    rank["rankedFiles"] += [
        {"path": "src/b.rs", "score": 3, "securityObjective": "rpc", "rationale": "parsing"},
        {"path": "src/a.rs", "score": 2, "securityObjective": "dup", "rationale": "dup"},
        {"path": "ghost.rs", "score": 5, "securityObjective": "x", "rationale": "hallucinated"},
    ]
    fake = FakeRun(tmp_path, node_id="plan_file_hunts").node("rank_files", rank).node("snapshot", SNAPSHOT)
    result = collectors.collect_plan_file_hunts(fake.view(), FILE_HUNT_PARAMS)
    assert set(result["lanes"]) == {"p1_r1", "p2_r1"}
    assert [item["path"] for item in result["lanes"]["p1_r1"]] == ["src/a.rs", "src/b.rs"]
    rank_path = fake.run_dir / "artifacts" / "plan_file_hunts" / "ranked-files.json"
    assert result["lanes"]["p1_r1"][0] == {
        "attemptId": "FILE:file:src/a.rs:p1:r1",
        "kind": "FILE",
        "workItemId": "file:src/a.rs",
        "profileId": "p1",
        "replica": 1,
        "slotKey": "p1_r1",
        "sourceCommit": COMMIT,
        "path": "src/a.rs",
        "score": 5,
        "rankPath": str(rank_path),
    }
    # Objective and rationale are read from the rank artifact, not repeated in every slot.
    assert result["rankPath"] == str(rank_path)
    assert json.loads(rank_path.read_text(encoding="utf-8")) == {
        "src/a.rs": {"score": 5, "securityObjective": "consensus safety", "rationale": "votes"},
        "src/b.rs": {"score": 3, "securityObjective": "rpc", "rationale": "parsing"},
        "src/c.rs": {"score": 1, "securityObjective": "unranked", "rationale": "unranked"},
    }
    assert result["unranked"] == ["src/c.rs"] and result["unrankedCount"] == 1
    assert result["belowThreshold"] == 1 and result["selectedCount"] == 2
    assert result["deferredCount"] == 0 and result["deferred"] == []
    assert result["log"] == ["duplicate rank for src/a.rs; kept the first", "dropped ranked path outside scope: ghost.rs"]
    with pytest.raises(CollectorError, match="no structured output"):
        collectors.collect_plan_file_hunts(FakeRun(tmp_path, run_id="r2").node("rank_files", status="failed").node("snapshot", SNAPSHOT).view(), FILE_HUNT_PARAMS)


def test_plan_file_hunts_defers_files_beyond_the_slot_cap_and_the_output_budget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    paths = [f"src/f{index:03d}.rs" for index in range(40)]
    rank = {"rankedFiles": [{"path": path, "score": 5 - index % 3, "securityObjective": "o", "rationale": "r"} for index, path in enumerate(paths)]}
    snapshot = {**SNAPSHOT, "scopeFiles": paths}
    view = FakeRun(tmp_path).node("rank_files", rank).node("snapshot", snapshot).view()
    by_priority = [entry["path"] for entry in sorted(rank["rankedFiles"], key=lambda e: (-e["score"], e["path"]))]

    capped = collectors.collect_plan_file_hunts(view, {**FILE_HUNT_PARAMS, "threshold": 3, "maxItemsPerSlot": 30})
    assert capped["selectedCount"] == 30 and capped["deferredCount"] == 10
    assert [item["path"] for item in capped["lanes"]["p2_r1"]] == by_priority[:30]
    assert capped["deferred"] == by_priority[30:]
    assert capped["log"] == ["deferred 10 ranked files above maxItemsPerSlot=30"]

    monkeypatch.setattr(collectors, "OUTPUT_BUDGET_BYTES", 6000)
    fitted = collectors.collect_plan_file_hunts(view, {**FILE_HUNT_PARAMS, "threshold": 3, "maxItemsPerSlot": 30})
    assert len(collectors.dumps(fitted).encode("utf-8")) <= 6000
    planned = fitted["selectedCount"]
    assert 0 < planned < 30
    assert [item["path"] for item in fitted["lanes"]["p1_r1"]] == by_priority[:planned]
    assert fitted["deferred"] == by_priority[planned:] and fitted["deferredCount"] == 40 - planned
    assert fitted["log"][-1] == f"deferred {30 - planned} ranked files over the 6000-byte output budget"
    # One more item would not have fit: the budget is used, not padded.
    monkeypatch.setattr(collectors, "OUTPUT_BUDGET_BYTES", 10**9)
    unbounded = collectors.collect_plan_file_hunts(view, {**FILE_HUNT_PARAMS, "threshold": 3, "maxItemsPerSlot": planned + 1})
    assert len(collectors.dumps(unbounded).encode("utf-8")) > 6000


def test_plan_context_workers_emits_one_item_per_slot_per_lane(tmp_path: Path):
    view = FakeRun(tmp_path).node("snapshot", SNAPSHOT).view()
    result = collectors.collect_plan_context_workers(view, CONTEXT_WORKER_PARAMS)
    assert set(result["threat"]) == set(result["history"]) == {"p1_r1", "p2_r1"}
    assert [len(items) for items in result["threat"].values()] == [1, 1]
    assert result["sourceCommit"] == COMMIT
    item = result["history"]["p2_r1"][0]
    assert item["attemptId"] == "HISTORY:history:p2:r1"
    assert (item["targetId"], item["sourceCommit"]) == ("monad", COMMIT)
    # The corpus is a file, never inlined into every slot's item.
    assert "historyText" not in item and "historyText" not in json.dumps(result)
    assert Path(item["historyPath"]).read_text(encoding="utf-8") == "issue #1: quorum"
    threat_item = result["threat"]["p1_r1"][0]
    assert (threat_item["targetId"], threat_item["sourceCommit"]) == ("monad", COMMIT) and "historyPath" not in threat_item
    assert collectors.collect_plan_context_workers(view, {**CONTEXT_WORKER_PARAMS, "history": False, "historyText": None})["history"] == {}
    with pytest.raises(CollectorError, match="no structured output"):
        collectors.collect_plan_context_workers(FakeRun(tmp_path, run_id="r2").node("snapshot", status="failed").view(), CONTEXT_WORKER_PARAMS)


# --------------------------------------------------------------------------- context lane


def test_collect_threat_drafts_records_failed_and_invalid_members_as_gaps(tmp_path: Path):
    fake = FakeRun(tmp_path)
    ok = attempt_item("THREAT_DRAFT", "threat-model", SLOTS[0])
    fake.member("threat_model__p1_r1", sample_draft(), input=ok)
    fake.member("threat_model__p2_r1", status="timed_out", input=attempt_item("THREAT_DRAFT", "threat-model", SLOTS[1]))
    fake.member("threat_model__p2_r1", {"summary": "broken"}, input={**attempt_item("THREAT_DRAFT", "threat-model", SLOTS[1]), "attemptId": "bad"})
    result = collectors.collect_threat_drafts(fake.view(), {"templates": ["threat_model__p2_r1", "threat_model__p1_r1"]})
    assert [draft["attemptId"] for draft in result["drafts"]] == [ok["attemptId"]]
    assert result["drafts"][0]["draft"] == sample_draft() and result["drafts"][0]["nodeId"] == "threat_model__p1_r1_0"
    assert [(gap["attemptId"], gap["status"]) for gap in result["gaps"]] == [(ok["attemptId"].replace("p1", "p2"), "timed_out"), ("bad", "completed")]
    assert result["gaps"][0]["reasons"] == ["status timed_out"]
    assert result["gaps"][1]["reasons"][0].startswith("/: 'actors' is a required property")


def test_collect_history_candidates_flattens_candidates_with_provenance(tmp_path: Path):
    fake = FakeRun(tmp_path)
    item = attempt_item("HISTORY", "history", SLOTS[0])
    fake.member("history_risk__p1_r1", {"candidates": [sample_candidate("H2"), sample_candidate("H1"), sample_candidate("H1")]}, input=item)
    fake.member("history_risk__p2_r1", status="failed", input=attempt_item("HISTORY", "history", SLOTS[1]))
    result = collectors.collect_history_candidates(fake.view(), {"templates": ["history_risk__p1_r1", "history_risk__p2_r1"]})
    assert [(c["sourceAttemptId"], c["key"]) for c in result["candidates"]] == [(item["attemptId"], "H1"), (item["attemptId"], "H2")]
    assert result["attempts"] == [{"attemptId": item["attemptId"], "nodeId": "history_risk__p1_r1_0", "profileId": "p1", "replica": 1, "slotKey": "p1_r1", "candidateCount": 2}]
    assert result["gaps"][0]["status"] == "failed"
    assert result["log"] == [f"{item['attemptId']}: duplicate candidate key H1; kept the first"]


def test_collect_threat_model_validates_mappings_and_writes_markdown(tmp_path: Path):
    attempt = "THREAT_DRAFT:threat-model:p1:r1"
    drafts = {"drafts": [{"attemptId": attempt, "draft": sample_draft()}], "gaps": []}
    view = FakeRun(tmp_path, node_id="collect_threat_model").node("threat_synthesis", sample_canonical((attempt,))).node("collect_threat_drafts", drafts).node("snapshot", {"sourceCommit": COMMIT}).view()
    result = collectors.collect_threat_model(view, {"synthesisNode": "threat_synthesis", "draftsNode": "collect_threat_drafts", "snapshotNode": "snapshot", "targetId": "monad"})
    model = result["threatModel"]
    assert model["modelId"] == "tm_" + collectors.sha256_hex("run-1")[:12] and model["revision"] == 1
    assert model["threats"][0]["threatId"] == "T1" and model["sourceCommit"] == COMMIT
    assert result["log"] == []
    markdown = Path(result["markdownPath"]).read_text(encoding="utf-8")
    assert result["markdownPath"].endswith("/artifacts/collect_threat_model/threat-model.md")
    assert markdown == rendering.render_threat_model_markdown(model)
    assert markdown.startswith(f"# Threat model {model['modelId']}\n")

    broken = sample_canonical((attempt,))
    broken["entityMappings"] = [m for m in broken["entityMappings"] if m["sourceKey"] != "T1"]
    broken["entityMappings"][0] = {**broken["entityMappings"][0], "disposition": "DEDUPLICATED", "canonicalKey": "ghost"}
    broken["sourceModels"] = [{"attemptId": "other"}]
    broken["threats"][0]["assetKeys"] = ["missing-asset"]
    view = FakeRun(tmp_path, run_id="r2").node("threat_synthesis", broken).node("collect_threat_drafts", drafts).view()
    result = collectors.collect_threat_model(view, {"synthesisNode": "threat_synthesis", "draftsNode": "collect_threat_drafts"})
    assert result["log"] == [
        f"DEDUPLICATED mapping actor validator from {attempt} lacks a rationale",
        "mapping targets unknown canonical actor ghost",
        f"sourceModels omits completed draft {attempt}",
        "sourceModels references unknown draft other",
        "threat T1 references unknown asset missing-asset",
        f"unmapped threat T1 from draft {attempt}",
    ]
    assert result["threatModel"]["targetId"] is None and result["threatModel"]["sourceCommit"] is None


def test_collect_history_model_validates_candidate_coverage(tmp_path: Path):
    attempt = "HISTORY:history:p1:r1"
    candidates = {"candidates": [{**sample_candidate("H1"), "sourceAttemptId": attempt}, {**sample_candidate("H2"), "sourceAttemptId": attempt}], "attempts": [{"attemptId": attempt}]}
    catalog = sample_catalog((attempt,))
    catalog["mappings"].append({"sourceAttemptId": attempt, "sourceKey": "H3", "threatId": "hist-9", "disposition": "RETAINED"})
    view = FakeRun(tmp_path, node_id="collect_history_model").node("history_synthesis", catalog).node("collect_history_candidates", candidates).view()
    result = collectors.collect_history_model(view, {"synthesisNode": "history_synthesis", "candidatesNode": "collect_history_candidates"})
    assert result["historyModel"]["modelId"] == "hm_" + collectors.sha256_hex("run-1")[:12]
    assert result["historyModel"]["items"][0]["threatId"] == "hist-1"
    assert result["log"] == [
        f"mapping references unknown candidate H3 from attempt {attempt}",
        "mapping targets unknown historical threat hist-9",
        f"unmapped candidate H2 from attempt {attempt}",
    ]
    assert Path(result["markdownPath"]).read_text(encoding="utf-8") == rendering.render_history_markdown(result["historyModel"])


def write_goal_templates(root: Path) -> Path:
    templates = root / "templates"
    templates.mkdir()
    (templates / "goal-threat-model.md").write_text(
        "## THREAT_MODEL goal: {{THREAT_ID}}\n\nTest {{THREAT_STATEMENT}} in model {{THREAT_MODEL_ID}} rev {{THREAT_MODEL_REVISION}}.\n\n{{THREAT_CONTEXT}}\n", encoding="utf-8"
    )
    (templates / "goal-historical.md").write_text(
        "## HISTORICAL goal: {{THREAT_ID}}\n\n{{STATEMENT}}\nCapability: {{ATTACKER_CAPABILITY}}\nExcluded: {{EXCLUDED_PRECONDITIONS}}\nIssues: {{SOURCE_ISSUE_REFS}}\nConfidence: {{THREAT_CONFIDENCE}}\n", encoding="utf-8"
    )
    (templates / "goal-roam.md").write_text("## ROAM goal\n\n{{GOAL_OUTCOME}} within {{SCOPE}}\n", encoding="utf-8")
    return templates


def goal_hunt_run(tmp_path: Path, plan: dict, *, history: bool = True) -> FakeRun:
    threat_model = {"threatModel": {"modelId": "tm_abc", "revision": 1, "sourceCommit": COMMIT, **sample_draft(), "threats": [{**sample_threat(), "threatId": "T1"}]}, "markdownPath": "/runs/x/threat-model.md"}
    fake = FakeRun(tmp_path).node("goal_plan", plan).node("collect_threat_model", threat_model)
    if history:
        catalog = sample_catalog(("HISTORY:history:p1:r1",))
        catalog["items"].append({**catalog["items"][0], "threatId": "hist-2"})
        fake.node("collect_history_model", {"historyModel": {"modelId": "hm_abc", "revision": 1, **catalog}, "markdownPath": "/runs/x/history-catalog.md"})
    return fake


def test_plan_goal_hunts_validates_goals_renders_overlays_and_caps_roam(tmp_path: Path):
    templates = write_goal_templates(tmp_path)
    plan = sample_goal_plan()
    plan["goals"] += [
        sample_goal("bad-threat", "THREAT_MODEL", "T9"),
        sample_goal("bad-hist", "HISTORICAL", "hist-2"),
        sample_goal("roam-2", "ROAM", None),
        sample_goal("g1", "ROAM", None),
    ]
    view = goal_hunt_run(tmp_path, plan).view()
    params = {"goalPlanNode": "goal_plan", "threatModelNode": "collect_threat_model", "historyModelNode": "collect_history_model", "slots": SLOTS, "maxRoamGoals": 1, "maxItemsPerSlot": 256, "templatesDir": str(templates)}
    result = collectors.collect_plan_goal_hunts(view, params)
    assert set(result["lanes"]) == {f"{lane}__{slot['slotKey']}" for lane in ("threat", "historical", "roam") for slot in SLOTS}
    assert [(goal["kind"], goal["callerKey"], goal["threatId"]) for goal in result["goals"]] == [("THREAT_MODEL", "g1", "T1"), ("HISTORICAL", "g2", "hist-1"), ("ROAM", "g3", None)]
    assert result["deferredGoals"] == []
    assert result["log"] == [
        "missing disposition for historical threat hist-2",
        "dropped THREAT_MODEL goal bad-threat: unknown threatId T9",
        "dropped HISTORICAL goal bad-hist: historical threat hist-2 is not ELIGIBLE",
        "dropped ROAM goal roam-2: maxRoamGoals=1",
        "duplicate goal callerKey g1; dropped",
    ]
    threat_item = result["lanes"]["threat__p2_r1"][0]
    assert threat_item["attemptId"] == "THREAT_MODEL:THREAT_MODEL:tm_abc:1:T1:p2:r1"
    assert threat_item["workItemId"] == "THREAT_MODEL:tm_abc:1:T1" and threat_item["sourceCommit"] == COMMIT
    assert threat_item["goal"] == sample_goal() and threat_item["threatId"] == "T1"
    assert threat_item["overlay"].startswith("## THREAT_MODEL goal: T1\n\nTest A minority of stake finalizes a block in model tm_abc rev 1.\n\n{")
    context = json.loads(threat_item["overlay"].split("\n\n", 2)[2])
    assert context["threat"]["threatId"] == "T1" and [actor["key"] for actor in context["actors"]] == ["validator"]
    historical = result["lanes"]["historical__p1_r1"][0]["overlay"]
    assert historical == (
        "## HISTORICAL goal: hist-1\n\nBlock proposals with duplicate transactions were accepted\nCapability: proposer\n"
        'Excluded: ["compromised keys"]\nIssues: ["issue-42"]\nConfidence: high\n'
    )
    assert result["lanes"]["roam__p1_r1"][0]["overlay"] == "## ROAM goal\n\nminority stake finalizes a block within src/a.rs\n"
    assert result["lanes"]["roam__p1_r1"][0]["workItemId"] == "ROAM:g3"
    assert "{{" not in json.dumps(result)

    without_history = goal_hunt_run(tmp_path / "nohist", plan, history=False).view()
    result = collectors.collect_plan_goal_hunts(without_history, {**params, "historyModelNode": None, "maxRoamGoals": 0})
    assert [goal["kind"] for goal in result["goals"]] == ["THREAT_MODEL"]
    assert "dropped HISTORICAL goal g2: unknown historical threat hist-1" in result["log"]
    assert "disposition for unknown historical threat hist-1 ignored" in result["log"]
    assert result["lanes"]["historical__p1_r1"] == [] and result["lanes"]["roam__p1_r1"] == []


def test_plan_goal_hunts_defers_goals_beyond_the_slot_cap_and_the_output_budget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    templates = write_goal_templates(tmp_path)
    plan = sample_goal_plan()
    plan["goals"].insert(1, sample_goal("g1b", "THREAT_MODEL", "T2"))
    fake = goal_hunt_run(tmp_path, plan)
    model = fake.outputs["collect_threat_model"]
    model["threatModel"]["threats"].append({**sample_threat("T2"), "threatId": "T2"})
    view = fake.view()
    params = {"goalPlanNode": "goal_plan", "threatModelNode": "collect_threat_model", "historyModelNode": "collect_history_model", "slots": SLOTS, "maxRoamGoals": 1, "maxItemsPerSlot": 1, "templatesDir": str(templates)}
    capped = collectors.collect_plan_goal_hunts(view, params)
    assert [goal["callerKey"] for goal in capped["goals"]] == ["g1", "g2", "g3"]
    assert [goal["callerKey"] for goal in capped["deferredGoals"]] == ["g1b"]
    assert [item["threatId"] for item in capped["lanes"]["threat__p1_r1"]] == ["T1"]
    assert "deferred 1 THREAT_MODEL goals above maxItemsPerSlot=1" in capped["log"]

    monkeypatch.setattr(collectors, "OUTPUT_BUDGET_BYTES", len(collectors.dumps(capped).encode("utf-8")) - 1)
    fitted = collectors.collect_plan_goal_hunts(view, params)
    assert len(collectors.dumps(fitted).encode("utf-8")) <= collectors.OUTPUT_BUDGET_BYTES
    assert [goal["callerKey"] for goal in fitted["goals"]] == ["g1", "g2"]
    assert [goal["callerKey"] for goal in fitted["deferredGoals"]] == ["g1b", "g3"]
    assert fitted["lanes"]["roam__p1_r1"] == [] and fitted["log"][-1].startswith("deferred 1 goals over the ")


def test_plan_goal_hunts_fails_loudly_on_unresolved_template_placeholders(tmp_path: Path):
    templates = write_goal_templates(tmp_path)
    (templates / "goal-threat-model.md").write_text("{{THREAT_ID}} {{NOT_A_FIELD}} {{ lower_case }}\n", encoding="utf-8")
    view = goal_hunt_run(tmp_path, sample_goal_plan()).view()
    params = {"goalPlanNode": "goal_plan", "threatModelNode": "collect_threat_model", "historyModelNode": None, "slots": SLOTS, "maxRoamGoals": 1, "maxItemsPerSlot": 256, "templatesDir": str(templates)}
    with pytest.raises(CollectorError, match=r"unresolved placeholders \['NOT_A_FIELD'\]"):
        collectors.collect_plan_goal_hunts(view, params)


# --------------------------------------------------------------------------- discovery


def test_collect_leads_builds_attempt_rows_and_stable_lead_ids(tmp_path: Path):
    fake = FakeRun(tmp_path, node_id="collect_leads")
    found = attempt_item("FILE", "file:src/a.rs", SLOTS[0], path="src/a.rs", score=5)
    fake.member("file_hunt__p1_r1", sample_hunt(leads=[sample_lead("dup"), sample_lead("dup"), sample_lead("other")]), input=found)
    empty = attempt_item("FILE", "file:src/b.rs", SLOTS[0], path="src/b.rs", score=4)
    fake.member("file_hunt__p1_r1", sample_hunt(leads=[]), input=empty)
    failed = attempt_item("THREAT_MODEL", "THREAT_MODEL:tm:1:T1", SLOTS[1], threatId="T1")
    fake.member("goal_hunt__threat__p2_r1", status="failed", input=failed)
    timed_out = attempt_item("ROAM", "ROAM:g3", SLOTS[1])
    fake.member("goal_hunt__roam__p2_r1", None, status="timed_out", input=timed_out)
    invalid = attempt_item("FILE", "file:src/c.rs", SLOTS[1], path="src/c.rs", score=3)
    fake.member("file_hunt__p2_r1", {"result": "BLOCKED", "leads": []}, input=invalid)
    result = collectors.collect_leads(fake.view(), {"templates": ["file_hunt__p1_r1", "file_hunt__p2_r1", "goal_hunt__threat__p2_r1", "goal_hunt__roam__p2_r1"]})

    by_attempt = {attempt["attemptId"]: attempt for attempt in result["attempts"]}
    assert set(by_attempt) == {found["attemptId"], empty["attemptId"], failed["attemptId"], timed_out["attemptId"], invalid["attemptId"]}
    assert by_attempt[found["attemptId"]]["terminalState"] == "BUG_FOUND"
    assert by_attempt[found["attemptId"]]["leadIds"] == sorted(collectors.lead_id(found["attemptId"], key) for key in ("dup", "other"))
    assert by_attempt[found["attemptId"]]["notes"] == ["duplicate lead callerKey dup; kept the first"]
    assert by_attempt[empty["attemptId"]]["terminalState"] == "EXHAUSTED"
    assert by_attempt[empty["attemptId"]]["notes"] == ["BUG_FOUND without leads downgraded to EXHAUSTED"]
    assert by_attempt[failed["attemptId"]]["terminalState"] == "FAILED" and by_attempt[failed["attemptId"]]["threatId"] == "T1"
    assert by_attempt[timed_out["attemptId"]]["terminalState"] == "TIMED_OUT" and by_attempt[timed_out["attemptId"]]["summary"] is None
    assert by_attempt[invalid["attemptId"]]["terminalState"] == "FAILED"
    assert by_attempt[invalid["attemptId"]]["notes"] == ["/: 'summary' is a required property"]
    assert [lead["leadId"] for lead in result["leads"]] == sorted(lead["leadId"] for lead in result["leads"])
    assert {lead["callerKey"] for lead in result["leads"]} == {"dup", "other"}
    assert result["leads"][0]["path"] == "src/a.rs" and result["leads"][0]["sourceCommit"] == COMMIT
    assert json.loads((fake.run_dir / "artifacts" / "collect_leads" / "leads.json").read_text(encoding="utf-8")) == result


def test_collect_findings_repairs_the_partition_and_matches_known_findings(tmp_path: Path):
    attempt = "FILE:file:src/a.rs:p1:r1"
    leads = [lead_row(attempt, key) for key in ("l1", "l2", "l3", "l4")]
    l1, l2, l3, l4 = (lead["leadId"] for lead in leads)
    leads_output = {"attempts": [{"attemptId": attempt, "terminalState": "BUG_FOUND", "leadIds": [l1, l2, l3, l4]}], "leads": leads}
    dedup = sample_dedup([l1, "lead_unknown", l2])
    dedup["findings"].append({"callerKey": "shadow", "title": "Same again", "rootCause": "dup", "impact": "x", "leadIds": [l2]})
    dedup["findings"].append({"callerKey": "quorum", "title": "Dup key", "rootCause": "dup", "impact": "x", "leadIds": [l3]})
    corpus = tmp_path / "known" / "findings.jsonl"
    corpus.parent.mkdir()
    corpus.write_text(
        json.dumps({"findingId": "finding_old", "runId": "run-0", "title": "Minority quorum finalization", "rootCause": "unweighted quorum check", "locations": ["src/a.rs"], "decision": "CONFIRMED", "reason": None, "severity": "HIGH"})
        + "\n"
        + json.dumps({"findingId": "finding_rpc", "title": "RPC crash", "rootCause": "null deref", "locations": ["rpc.rs"], "decision": "REJECTED", "reason": "FALSE"})
        + "\nnot json\n[1, 2]\n\n",
        encoding="utf-8",
    )
    fake = FakeRun(tmp_path, node_id="collect_findings").node("deduplicate", dedup).node("collect_leads", leads_output)
    result = collectors.collect_findings(fake.view(), {"dedupNode": "deduplicate", "leadsNode": "collect_leads", "cap": 2, "knownFindingsPath": str(corpus)})

    singletons = sorted([l3, l4])
    assert [item["finding"]["callerKey"] for item in result["items"]] == ["quorum", f"singleton:{singletons[0]}"]
    assert result["deferredFindingIds"] == [collectors.finding_id(f"singleton:{singletons[1]}")] and result["findingCount"] == 3
    quorum = result["items"][0]
    assert quorum["findingId"] == collectors.finding_id("quorum")
    assert quorum["finding"]["leadIds"] == sorted([l1, l2]) and quorum["finding"]["origin"] == "dedup"
    assert [lead["leadId"] for lead in quorum["leads"]] == sorted([l1, l2])
    assert quorum["discoveryOutcomes"] == leads_output["attempts"]
    assert [candidate["knownFindingId"] for candidate in quorum["knownFindingCandidates"]] == ["finding_old"]
    assert quorum["knownFindingCandidates"][0]["sharedTokens"] == ["minority", "quorum", "src", "unweighted"]
    singleton = result["items"][1]
    assert singleton["finding"]["origin"] == "singleton" and singleton["finding"]["title"] == "Unchecked vote quorum lets a minority finalize a block"
    assert singleton["finding"]["rootCause"] == sample_lead()["claim"] and singleton["finding"]["impact"] == "consensus safety violation"
    assert result["log"] == [
        "known findings line 3 is not valid JSON",
        "known findings line 4 is not an object",
        "finding quorum: unknown leadId lead_unknown dropped",
        f"finding shadow: leadId {l2} already assigned; kept the first assignment",
        "finding shadow has no valid leads; dropped",
        "duplicate finding callerKey quorum; dropped",
        f"lead {singletons[0]} was not assigned by dedup; created a singleton finding",
        f"lead {singletons[1]} was not assigned by dedup; created a singleton finding",
    ]
    assert json.loads((fake.run_dir / "artifacts" / "collect_findings" / "findings.json").read_text(encoding="utf-8")) == result
    assert collectors.collect_findings(fake.view(), {"dedupNode": "deduplicate", "leadsNode": "collect_leads", "cap": 8, "knownFindingsPath": None})["items"][0]["knownFindingCandidates"] == []


# --------------------------------------------------------------------------- triage


def contexts_fixture(tmp_path: Path) -> tuple[FakeRun, list[dict[str, Any]]]:
    attempt = "FILE:file:src/a.rs:p1:r1"
    items = [finding_item("f1", [lead_row(attempt, "l1")]), finding_item("f2", [lead_row(attempt, "l2")]), finding_item("f3", [lead_row(attempt, "l3")])]
    fake = FakeRun(tmp_path, node_id="collect_contexts").node("collect_findings", {"items": items, "deferredFindingIds": ["finding_deferred"]})
    fake.member("triage_context", sample_context(), input=items[0])
    known = {**sample_context(), "disposition": "KNOWN", "validityRequired": False, "impactRequired": False, "validityMethods": [], "impactMethods": [], "existingEvidenceIds": ["ev-0"]}
    fake.member("triage_context", known, input=items[1])
    fake.member("triage_context", sample_context(), input={"findingId": "finding_ghost"})
    return fake, items


def test_collect_contexts_schedules_validity_and_turns_invalid_contexts_into_gaps(tmp_path: Path):
    fake, items = contexts_fixture(tmp_path)
    result = collectors.collect_contexts(fake.view(), {"gateTemplate": "triage_context", "findingsNode": "collect_findings", "validitySlots": SLOTS})
    by_id = {entry["findingId"]: entry for entry in result["findings"]}
    assert list(by_id) == sorted(item["findingId"] for item in items)
    f1, f2, f3 = (by_id[item["findingId"]] for item in items)
    assert f1["gap"] is None and f1["validityScheduled"] is True and f1["context"] == sample_context() and f1["contextNodeId"] == "triage_context_0"
    assert f2["gap"] == "knownIssueSearch.matches: KNOWN requires an exact issue, PR, known-finding, or documentation match"
    assert f2["context"]["disposition"] == "INCONCLUSIVE" and f2["context"]["targetCommit"] == COMMIT and f2["validityScheduled"] is False
    assert collectors.schema_errors(f2["context"], "triage-context") == [] and collectors.context_issues(f2["context"]) == []
    assert f3["gap"] == "no context member" and f3["contextNodeId"] is None
    assert set(result["validity"]) == {"p1_r1", "p2_r1"}
    item = result["validity"]["p2_r1"][0]
    assert len(result["validity"]["p2_r1"]) == 1 and item["findingId"] == items[0]["findingId"]
    assert item["attemptId"] == f"VALIDITY:{items[0]['findingId']}:p2:r1" and item["context"] == sample_context()
    # Lead records live in the per-finding bundle file; every validity slot copies its item.
    assert "leads" not in item and item["leadIds"] == items[0]["finding"]["leadIds"]
    bundle_path = Path(item["findingPath"])
    assert bundle_path == fake.run_dir / "artifacts" / "collect_contexts" / "findings" / f"{items[0]['findingId']}.json"
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    assert bundle["leads"] == items[0]["leads"] and bundle["context"] == sample_context() and bundle["finding"] == items[0]["finding"]
    assert set(bundle) == {"findingId", "finding", "leads", "context", "discoveryOutcomes", "knownFindingCandidates"}
    assert not (fake.run_dir / "artifacts" / "collect_contexts" / "findings" / f"{items[1]['findingId']}.json").exists()
    assert result["deferredFindingIds"] == ["finding_deferred"]
    assert result["log"] == ["context member triage_context_2 references unknown finding finding_ghost; ignored"]


def test_collect_contexts_logs_target_commit_mismatch_without_dropping_the_context(tmp_path: Path):
    items = [finding_item("f1", [lead_row("FILE:file:src/a.rs:p1:r1", "l1")])]
    fake = FakeRun(tmp_path).node("collect_findings", {"items": items, "deferredFindingIds": []})
    fake.member("triage_context", sample_context("d" * 40), input=items[0])
    result = collectors.collect_contexts(fake.view(), {"gateTemplate": "triage_context", "findingsNode": "collect_findings", "validitySlots": SLOTS[:1]})
    assert result["findings"][0]["gap"] is None
    assert result["log"] == [f"finding {items[0]['findingId']}: context targetCommit {'d' * 40} differs from source commit {COMMIT}"]


def validity_fixture(tmp_path: Path) -> tuple[FakeRun, dict[str, Any]]:
    fake, items = contexts_fixture(tmp_path)
    contexts = collectors.collect_contexts(fake.view(), {"gateTemplate": "triage_context", "findingsNode": "collect_findings", "validitySlots": SLOTS})
    fake = FakeRun(tmp_path / "validity", node_id="collect_validity").node("collect_contexts", contexts)
    scheduled = {slot: lane[0] for slot, lane in contexts["validity"].items()}
    fake.member("triage_validity__p1_r1", sample_evidence(), input=scheduled["p1_r1"])
    fake.member("triage_validity__p2_r1", None, status="failed", input=scheduled["p2_r1"])
    return fake, contexts


def test_collect_validity_bundles_attempts_and_gaps_per_finding(tmp_path: Path):
    fake, contexts = validity_fixture(tmp_path)
    result = collectors.collect_validity(fake.view(), {"validityTemplates": ["triage_validity__p1_r1", "triage_validity__p2_r1"], "contextsNode": "collect_contexts"})
    reviewed = next(entry for entry in contexts["findings"] if entry["gap"] is None)
    assert [item["findingId"] for item in result["items"]] == [reviewed["findingId"]]
    item = result["items"][0]
    assert [attempt["slotKey"] for attempt in item["validityAttempts"]] == ["p1_r1"] and item["validityAttempts"][0]["evidence"] == sample_evidence()
    assert item["gaps"] == [{"attemptId": f"VALIDITY:{reviewed['findingId']}:p2:r1", "nodeId": "triage_validity__p2_r1_0", "slotKey": "p2_r1", "status": "failed", "reasons": ["status failed"]}]
    assert item["context"] == sample_context() and item["leads"] == reviewed["leads"]
    assert [entry["gap"] for entry in result["skipped"]] == [entry["gap"] for entry in contexts["findings"] if entry["gap"]]
    assert result["deferredFindingIds"] == ["finding_deferred"] and result["log"] == []


def test_trusted_report_applies_policy_and_marks_missing_impact(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    fake, _ = validity_fixture(tmp_path)
    validity = collectors.collect_validity(fake.view(), {"validityTemplates": ["triage_validity__p1_r1", "triage_validity__p2_r1"], "contextsNode": "collect_contexts"})
    extra = finding_item("f4", [lead_row("FILE:file:src/a.rs:p1:r1", "l4")])
    validity["items"].append({**extra, "context": sample_context(), "validityAttempts": [], "gaps": []})
    fake = FakeRun(tmp_path / "trusted", node_id="trusted_report").node("collect_validity", validity)
    fake.member("triage_impact", sample_impact(), input=validity["items"][0])
    fake.member("triage_impact", None, status="timed_out", input=validity["items"][1])
    calls: list[tuple[Any, ...]] = []

    def derive_decision(context, attempts, impact, *, policy):
        calls.append((context["disposition"], len(attempts), impact is not None, policy))
        if impact is None:
            return Decision("INCONCLUSIVE", "UNPROVEN", None, ["missing impact decision"])
        return Decision("CONFIRMED", None, "CRITICAL", [])

    monkeypatch.setattr(collectors, "derive_decision", derive_decision)
    result = collectors.collect_trusted_report(fake.view(), {"impactTemplate": "triage_impact", "validityNode": "collect_validity", "policy": {"pocRequiredForSeverities": ["CRITICAL"]}})
    confirmed_id, missing_id = validity["items"][0]["findingId"], extra["findingId"]
    assert calls == [("REVIEW", 1, True, {"pocRequiredForSeverities": ["CRITICAL"]}), ("REVIEW", 0, False, {"pocRequiredForSeverities": ["CRITICAL"]})]
    assert result["findingIds"] == [confirmed_id]
    by_id = {disposition["findingId"]: disposition for disposition in result["dispositions"]}
    assert by_id[confirmed_id] == {"findingId": confirmed_id, "decision": "CONFIRMED", "reason": None, "severity": "CRITICAL", "blockers": []}
    assert by_id[missing_id] == {"findingId": missing_id, "decision": "INCONCLUSIVE", "reason": "UNPROVEN", "severity": None, "blockers": ["missing impact decision", "impact gap: triage_impact_1 status timed_out"]}
    skipped = [disposition for disposition in result["dispositions"] if disposition["findingId"] not in (confirmed_id, missing_id)]
    assert len(skipped) == 2 and all(d["decision"] == "INCONCLUSIVE" and d["blockers"][0].startswith("context gap: ") for d in skipped)
    assert [handoff["findingId"] for handoff in result["items"]] == [confirmed_id]
    handoff = result["items"][0]
    assert handoff["impactDecision"] == sample_impact() and handoff["severity"] == "CRITICAL" and handoff["disposition"]["decision"] == "CONFIRMED"
    assert handoff["validityAttempts"] == validity["items"][0]["validityAttempts"] and handoff["context"] == sample_context()
    assert {summary["findingId"] for summary in result["findings"]} == set(by_id)
    assert next(s for s in result["findings"] if s["findingId"] == confirmed_id)["locations"] == ["src/a.rs:10-20"]
    assert result["deferredFindingIds"] == ["finding_deferred"] and result["gaps"][0]["nodeId"] == "triage_impact_1"
    written = json.loads((fake.run_dir / "artifacts" / "trusted_report" / "trusted-report.json").read_text(encoding="utf-8"))
    assert written == {"findingIds": result["findingIds"], "dispositions": result["dispositions"], "deferredFindingIds": ["finding_deferred"]}


def test_trusted_report_rejects_impact_outputs_that_break_the_v3_rules(tmp_path: Path):
    item = {**finding_item("f1", [lead_row("FILE:file:src/a.rs:p1:r1", "l1")]), "context": sample_context(), "validityAttempts": [], "gaps": []}
    fake = FakeRun(tmp_path).node("collect_validity", {"items": [item], "skipped": [], "deferredFindingIds": []})
    impact = sample_impact()
    impact["guidanceReview"]["bountyStatus"] = "OUT_OF_SCOPE"
    fake.member("triage_impact", impact, input=item)
    # The real policy runs: the member's output fails the v3 rules, so the finding has no impact decision.
    result = collectors.collect_trusted_report(fake.view(), {"impactTemplate": "triage_impact", "validityNode": "collect_validity", "policy": {"pocRequiredForSeverities": ["CRITICAL", "HIGH"]}})
    assert result["items"] == []
    assert result["dispositions"][0]["blockers"] == [
        "missing impact decision",
        "impact gap: triage_impact_0 guidanceReview.bountyStatus: CONFIRMED requires a verified in-scope bounty claim",
    ]


def test_trusted_report_confirms_through_the_real_policy(tmp_path: Path):
    attempt = {"attemptId": "VALIDITY:f1:p1:r1", "nodeId": "triage_validity__p1_r1_0", "profileId": "p1", "replica": 1, "slotKey": "p1_r1", "evidence": sample_evidence()}
    item = {**finding_item("f1", [lead_row("FILE:file:src/a.rs:p1:r1", "l1")]), "context": sample_context(), "validityAttempts": [attempt], "gaps": []}
    fake = FakeRun(tmp_path).node("collect_validity", {"items": [item], "skipped": [], "deferredFindingIds": []})
    impact = sample_impact()
    impact["impactEvidence"][0]["methods"] = ["SOLONET"]
    impact["impactEvidence"][0]["evidenceIds"] = ["ev-2"]
    fake.member("triage_impact", impact, input=item)
    policy = {"pocRequiredForSeverities": ["CRITICAL", "HIGH"]}
    result = collectors.collect_trusted_report(fake.view(), {"impactTemplate": "triage_impact", "validityNode": "collect_validity", "policy": policy})
    assert result["dispositions"] == [{"findingId": item["findingId"], "decision": "CONFIRMED", "reason": None, "severity": "CRITICAL", "blockers": []}]
    assert result["items"][0]["severity"] == "CRITICAL" and result["items"][0]["disposition"]["decision"] == "CONFIRMED"

    fake.outputs["triage_impact_0"] = {**impact, "pocProvided": False, "pocEnvironment": "none"}
    result = collectors.collect_trusted_report(fake.view(), {"impactTemplate": "triage_impact", "validityNode": "collect_validity", "policy": policy})
    assert result["items"] == []
    assert result["dispositions"][0]["blockers"] == ["CRITICAL severity requires a working PoC on devnet or solonet"]


def test_collect_reports_validates_reports_and_appends_known_findings(tmp_path: Path):
    ids = {key: collectors.finding_id(key) for key in ("f1", "f5", "f6")}
    handoffs = [{"findingId": fid, "finding": {"callerKey": key, "title": "Minority quorum", "rootCause": "unweighted quorum", "impact": "safety", "leadIds": []}, "leads": []} for key, fid in ids.items()]
    summaries = [
        {"findingId": fid, "callerKey": key, "title": "Minority quorum finalization", "rootCause": "unweighted quorum check", "impact": "safety", "leadIds": [], "locations": ["src/a.rs"], "sourceCommit": COMMIT}
        for key, fid in ids.items()
    ]
    dispositions = [{"findingId": fid, "decision": "CONFIRMED", "reason": None, "severity": "HIGH", "blockers": []} for fid in ids.values()]
    dispositions.append({"findingId": "finding_rejected", "decision": "REJECTED", "reason": "FALSE", "severity": None, "blockers": ["falsified"]})
    trusted = {"items": handoffs, "findingIds": list(ids.values()), "dispositions": dispositions, "deferredFindingIds": ["finding_deferred"], "findings": summaries}
    fake = FakeRun(tmp_path, node_id="collect_reports").node("trusted_report", trusted)
    fake.member("report", sample_report(ids["f1"]), input=handoffs[0])
    fake.member("report", sample_report(ids["f1"]), input=handoffs[1])
    fake.member("report", sample_report(ids["f6"], "d" * 40), input=handoffs[2])
    corpus = tmp_path / "known" / "findings.jsonl"
    result = collectors.collect_reports(fake.view(), {"reportTemplate": "report", "trustedNode": "trusted_report", "knownFindingsPath": str(corpus), "targetId": "monad", "repositoryUrl": REPOSITORY_URL})

    assert result["sourceCommit"] == COMMIT
    assert [report["findingId"] for report in result["reports"]] == [ids["f1"]]
    report_path = Path(result["reports"][0]["path"])
    assert report_path == fake.run_dir / "artifacts" / "collect_reports" / "reports" / f"{ids['f1']}.md"
    assert report_path.read_text(encoding="utf-8") == sample_report(ids["f1"])["markdown"]
    assert [entry["findingId"] for entry in result["rejected"]] == sorted([ids["f5"], ids["f6"]])
    assert {entry["findingId"]: entry["reasons"] for entry in result["rejected"]} == {
        ids["f5"]: [f"findingId {ids['f1']} does not match the assigned finding {ids['f5']}", f"markdown does not mention the finding id {ids['f5']}"],
        ids["f6"]: [f"permalinks in category-labs/monad must use source commit {COMMIT}; found ['{'d' * 40}']"],
    }
    assert result["missing"] == [] and result["knownFindingsAppended"] == 4 and result["log"] == []
    summary = json.loads((fake.run_dir / "artifacts" / "collect_reports" / "run-summary.json").read_text(encoding="utf-8"))
    assert summary["dispositions"] == dispositions and summary["deferredFindingIds"] == ["finding_deferred"] and summary["runId"] == "run-1"
    lines = [json.loads(line) for line in corpus.read_text(encoding="utf-8").splitlines()]
    assert [line["findingId"] for line in lines] == [*ids.values(), "finding_rejected"]
    assert lines[0]["reportPath"] == str(report_path) and lines[1]["reportPath"] is None
    assert lines[0]["title"] == "Minority quorum finalization" and lines[0]["targetId"] == "monad" and lines[0]["decision"] == "CONFIRMED"
    assert lines[3] == {"recordedAt": lines[3]["recordedAt"], "runId": "run-1", "targetId": "monad", "sourceCommit": COMMIT, "findingId": "finding_rejected", "decision": "REJECTED", "reason": "FALSE", "severity": None, "blockers": ["falsified"], "reportPath": None}

    attempt = "FILE:file:src/a.rs:p1:r1"
    lead = lead_row(attempt, "l1")
    next_run = FakeRun(tmp_path, run_id="run-2").node("deduplicate", sample_dedup([lead["leadId"]])).node("collect_leads", {"attempts": [], "leads": [lead]})
    findings = collectors.collect_findings(next_run.view(), {"dedupNode": "deduplicate", "leadsNode": "collect_leads", "cap": 8, "knownFindingsPath": str(corpus)})
    candidates = findings["items"][0]["knownFindingCandidates"]
    assert [candidate["knownFindingId"] for candidate in candidates] == sorted(ids.values())
    assert candidates[0]["runId"] == "run-1" and candidates[0]["decision"] == "CONFIRMED" and candidates[0]["severity"] == "HIGH"


def test_collect_reports_records_missing_members_and_skips_permalink_check_without_commit(tmp_path: Path):
    fid = collectors.finding_id("f1")
    trusted = {"items": [{"findingId": fid, "finding": {}, "leads": []}], "findingIds": [fid], "dispositions": [], "deferredFindingIds": [], "findings": []}
    fake = FakeRun(tmp_path).node("trusted_report", trusted)
    fake.fanouts["report"] = []
    result = collectors.collect_reports(fake.view(), {"reportTemplate": "report", "trustedNode": "trusted_report"})
    assert result["missing"] == [fid] and result["reports"] == [] and "knownFindingsAppended" not in result
    assert result["log"] == ["source commit unknown; permalink check skipped"]
    assert collectors.report_issues(sample_report(fid, "d" * 40), fid, None) == []
    assert collectors.report_issues({"findingId": fid, "markdown": f"Report {fid}"}, fid, COMMIT) == ["markdown must start with a level-one heading"]


def test_report_permalink_check_is_scoped_to_the_target_repository(tmp_path: Path):
    fid = collectors.finding_id("f1")
    geth = "https://github.com/ethereum/go-ethereum/blob/" + "b" * 40 + "/core/vm/instructions.go#L10"
    spec = "https://github.com/ethereum/execution-specs/tree/v1.2.0/src/ethereum/prague"
    target = f"https://github.com/Category-Labs/monad/blob/{COMMIT}/src/x.cpp#L1-L2"
    report = {"findingId": fid, "markdown": f"# T\n\nFinding {fid}: {target} vs {geth} and {spec}.\n"}
    assert collectors.report_issues(report, fid, COMMIT, "category-labs/monad") == []
    # Without a repository every GitHub permalink is held to the source commit (the old rule).
    assert collectors.report_issues(report, fid, COMMIT) == [f"permalinks must use source commit {COMMIT}; found ['{'b' * 40}', 'v1.2.0']"]
    branch = {"findingId": fid, "markdown": f"# T\n\nFinding {fid}: https://github.com/category-labs/monad/blob/main/src/x.cpp and https://github.com/category-labs/monad/tree/{'d' * 40}/src\n"}
    assert collectors.report_issues(branch, fid, COMMIT, "category-labs/monad") == [
        f"permalinks in category-labs/monad must use source commit {COMMIT}; found ['{'d' * 40}', 'main']"
    ]
    assert collectors._repository_slug("https://github.com/category-labs/monad.git") == "category-labs/monad"
    assert collectors._repository_slug("https://example.test/monad") is None

    trusted = {"items": [{"findingId": fid, "finding": {}, "leads": []}], "findingIds": [fid], "dispositions": [], "deferredFindingIds": [], "findings": []}
    fake = FakeRun(tmp_path, node_id="collect_reports").node("trusted_report", trusted)
    fake.member("report", report, input={"findingId": fid})
    params = {"reportTemplate": "report", "trustedNode": "trusted_report", "sourceCommit": COMMIT, "repositoryUrl": REPOSITORY_URL}
    result = collectors.collect_reports(fake.view(), params)
    assert [entry["findingId"] for entry in result["reports"]] == [fid] and result["rejected"] == [] and result["log"] == []
    unscoped = collectors.collect_reports(FakeRun(tmp_path, run_id="r2", node_id="collect_reports").node("trusted_report", trusted).view(), {**params, "repositoryUrl": None})
    assert unscoped["log"] == ["repository unknown; every GitHub permalink must use the source commit"]


# --------------------------------------------------------------------------- v3 refinement rules


def test_context_rules_port_the_v3_super_refine():
    assert collectors.context_issues(sample_context()) == []
    intended = {**sample_context(), "disposition": "INTENDED", "validityRequired": False, "impactRequired": False, "validityMethods": [], "impactMethods": []}
    assert collectors.context_issues(intended) == ["guidanceReview: INTENDED requires authoritative documentation contradicting the finding's expected behavior"]
    fixed = {**sample_context(), "disposition": "FIXED"}
    assert collectors.context_issues(fixed) == [
        "fixCommit: FIXED requires the fix commit verified in the target snapshot",
        "disposition: non-REVIEW dispositions must not schedule validity or impact experiments",
    ]
    review = {**sample_context(), "validityRequired": False, "knownIssueSearch": {"status": "COMPLETE", "sources": [], "matches": []}, "guidanceReview": sample_guidance("SUPPORTED", "UNKNOWN")}
    review["guidanceReview"]["references"] = [BOUNTY_CITATION]
    assert collectors.context_issues(review) == [
        "guidanceReview.documentationStatus: a documentation judgment requires a documentation or specification citation",
        "knownIssueSearch.sources: a completed known-issue search must identify the sources searched",
        "existingEvidenceIds: skipping validity for a REVIEW finding requires existing evidence",
        "validityMethods: methods must be nonempty exactly when validity experiments are required",
    ]
    known = {**sample_context(), "disposition": "KNOWN", "validityRequired": False, "impactRequired": False, "validityMethods": [], "impactMethods": []}
    known["knownIssueSearch"] = {"status": "COMPLETE", "sources": ["github"], "matches": [ISSUE_CITATION]}
    assert collectors.context_issues(known) == []


def test_evidence_rules_cover_proven_impact_and_differentials():
    assert collectors.evidence_issues(sample_evidence(), "VALIDITY") == []
    assert collectors.evidence_issues(sample_evidence(), "IMPACT") == ["stage: expected IMPACT, got VALIDITY"]
    falsified = {**sample_evidence(state="FALSIFIED"), "evidenceIds": [], "methods": []}
    assert collectors.evidence_issues(falsified) == [
        "evidenceIds: a proven or falsified claim requires inspectable evidence",
        "methods: a proven or falsified claim must identify how it was tested",
    ]
    impact = sample_evidence("IMPACT")
    impact["productionAssessment"]["honestNodesUnmodified"] = False
    assert collectors.evidence_issues(impact) == ["productionAssessment: proven production impact requires a complete equivalent-environment assessment with unmodified honest nodes"]
    unproven = {**sample_evidence("IMPACT", "INCONCLUSIVE"), "productionAssessment": None, "guidanceReview": sample_guidance("UNKNOWN", "UNKNOWN")}
    assert collectors.evidence_issues(unproven) == []

    def differential(client: str, outcome: str, fork: str = "prague") -> dict:
        return {"client": client, "fixtureHash": "f", "prestateHash": "p", "fork": fork, "version": "1", "command": "run", "artifactRef": "a", "normalizedOutcome": outcome}

    proven = {**sample_evidence(), "methods": ["DIFFERENTIAL"], "differentialResults": [differential("monad", "revert"), differential("geth", "ok"), differential("nethermind", "ok")]}
    assert collectors.evidence_issues(proven) == []
    assert collectors.evidence_issues({**proven, "differentialResults": proven["differentialResults"][:2]}) == [
        "differentialResults: a proven differential requires one structured result each from Monad, geth, and Nethermind"
    ]
    disagreeing = {**proven, "differentialResults": [differential("monad", "revert"), differential("geth", "ok", "cancun"), differential("nethermind", "revert")]}
    assert collectors.evidence_issues(disagreeing) == [
        "differentialResults: differential results must use the same fork",
        "differentialResults: a proven differential requires agreeing reference clients and a different Monad outcome; a mismatch alone is not a bug",
    ]


def test_impact_rules_bind_decisions_to_reasons_and_evidence():
    assert collectors.impact_issues(sample_impact()) == []
    weak = {**sample_impact(), "reachability": "UNKNOWN", "evidenceIds": [], "reason": "UNPROVEN", "impact": None, "guidanceReview": sample_guidance("SUPPORTED", "IN_SCOPE")}
    weak["guidanceReview"]["references"] = [DOC_CITATION]
    assert collectors.impact_issues(weak) == [
        "guidanceReview.bountyStatus: a bounty-scope judgment requires a bounty-terms citation",
        "reachability: CONFIRMED requires supported reachability",
        "evidenceIds: CONFIRMED requires inspectable evidence",
        "guidanceReview.references: a proven finding requires a bounty-terms citation; unavailable guidance is not a completed check",
        "reason: CONFIRMED requires a null reason",
        "impact: CONFIRMED requires impact and likelihood levels for the severity matrix",
    ]
    rejected = {**sample_impact("REJECTED"), "reason": "KNOWN", "pocProvided": True, "guidanceReview": {**sample_guidance("UNKNOWN", "UNKNOWN"), "references": []}}
    assert collectors.impact_issues(rejected) == [
        "guidanceReview.references: KNOWN requires the matching known report or documentation citation",
        "pocEnvironment: pocProvided must agree with pocEnvironment (devnet or solonet when provided, none otherwise)",
    ]
    assert collectors.impact_issues({**sample_impact("INCONCLUSIVE"), "reason": None}) == ["reason: INCONCLUSIVE requires a reason"]
    informational = {**sample_impact("REJECTED"), "reason": "INFORMATIONAL", "mechanism": "UNKNOWN"}
    assert collectors.impact_issues(informational) == ["mechanism: INFORMATIONAL means a supported local mechanism with unestablished or limited production impact"]
    nested = sample_impact()
    nested["impactEvidence"][0]["evidenceIds"] = []
    assert collectors.impact_issues(nested) == ["impactEvidence[0].evidenceIds: a proven or falsified claim requires inspectable evidence"]


# --------------------------------------------------------------------------- rendering


def test_threat_model_markdown_is_deterministic_and_ordered_by_key():
    model = {"modelId": "tm_1", "revision": 1, "targetId": "monad", "sourceCommit": COMMIT, **sample_canonical()}
    model["actors"].append({**model["actors"][0], "key": "alpha", "name": "Pipe | user"})
    model["threats"].append({**sample_threat("A0"), "title": "First\nline"})
    model["entityMappings"].append({"sourceAttemptId": "a0", "entityType": "actor", "sourceKey": "x", "canonicalKey": "alpha", "disposition": "DEDUPLICATED", "rationale": "same"})
    markdown = rendering.render_threat_model_markdown(model)
    assert markdown == rendering.render_threat_model_markdown(json.loads(json.dumps(model)))
    headings = [line for line in markdown.splitlines() if line.startswith("#")]
    assert headings == [
        "# Threat model tm_1",
        "## Summary",
        "### Assumptions",
        "### Exclusions",
        "## Actors",
        "## Assets",
        "## Trust boundaries",
        "## Threats",
        "### A0: First line",
        "### T1: Minority quorum finalization",
        "## Mappings",
        "## Disagreements",
    ]
    assert "- Target: monad" in markdown and f"- Source commit: {COMMIT}" in markdown
    actor_rows = [line for line in markdown.splitlines() if line.startswith("| alpha") or line.startswith("| validator")]
    assert actor_rows[0].startswith("| alpha | Pipe \\| user |")
    mapping_rows = [line for line in markdown.splitlines() if line.startswith("| a0 |") or line.startswith("| THREAT_DRAFT")]
    assert mapping_rows == sorted(mapping_rows) and len(mapping_rows) == 5
    assert "| a0 | actor | x | alpha | DEDUPLICATED | same |" in mapping_rows
    assert markdown.endswith("## Disagreements\n\n- worker 2 rated T1 high confidence\n")


def test_history_markdown_lists_threats_and_mappings_in_order():
    catalog = {"modelId": "hm_1", "revision": 1, **sample_catalog(("a1",), "hist-2")}
    catalog["items"].append({**catalog["items"][0], "threatId": "hist-1"})
    markdown = rendering.render_history_markdown(catalog)
    assert markdown.startswith("# Historical risk catalog hm_1\n\n- Model: hm_1\n- Revision: 1\n- Target: unknown\n")
    assert [line for line in markdown.splitlines() if line.startswith("### ")] == ["### hist-1", "### hist-2"]
    assert "2 historical threats from 1 source attempts." in markdown
    assert "| a1 | H1 | hist-2 | RETAINED |" in markdown
    assert rendering.render_history_markdown({"modelId": "hm_0", "revision": 1, "items": [], "sourceAttemptIds": [], "mappings": []}).count("_(none)_") == 2
