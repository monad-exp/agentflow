"""Trusted python collectors for the bugfinder v3 pipeline.

Every python node in the v3 graph calls ``run(name, params)``. A collector reads
member outputs from ``artifacts/<node>/result.json`` and member statuses from
``run.json``, validates cross-member invariants, repairs or records gaps, and
prints one compact, key-sorted JSON object that downstream fan-outs consume.

Policy failures (invalid agent output, unmapped entities, unknown ids) are
recorded in the output under ``gaps``/``log``/``rejected``; a collector exits
non-zero only for programming errors or missing upstream artifacts.
"""

from __future__ import annotations

import functools
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping
from urllib.parse import urlsplit

from agentflow.contracts import validate_json_instance
from agentflow.utils import utcnow_iso
from examples.bugfinder.v3 import rendering
from examples.bugfinder.v3.policy import derive_decision
from examples.bugfinder.v3.prompts import TEMPLATE_PLACEHOLDER

RUN_DIR_ENV = "AGENTFLOW_RUN_DIR"
RUN_ID_ENV = "AGENTFLOW_RUN_ID"
NODE_ID_ENV = "AGENTFLOW_NODE_ID"

SCHEMAS_DIR = Path(__file__).resolve().parent / "schemas"
# AgentFlow retains at most 1 MiB of a node's stdout per attempt (RETAINED_STREAM_MAX_BYTES);
# a longer line is cut and the fan-out cannot parse it, so ``run`` refuses to print one.
MAX_OUTPUT_BYTES = 1 << 20
# Planners size their lanes to this budget and defer the rest, leaving headroom below the limit.
OUTPUT_BUDGET_BYTES = MAX_OUTPUT_BYTES - 4096
RUN_JSON_ATTEMPTS = 3
RUN_JSON_RETRY_SECONDS = 0.05
LIST_CAP = 200
KNOWN_FINDING_CANDIDATE_CAP = 10
KNOWN_FINDING_MIN_SHARED_TOKENS = 3

COMPLETED = "completed"
KNOWN_ISSUE_CITATION_KINDS = ("issue", "pull-request", "known-finding", "documentation")
ENTITY_FIELDS = {"actor": "actors", "asset": "assets", "trust_boundary": "trustBoundaries", "threat": "threats"}
GOAL_LANES = (("threat", "THREAT_MODEL"), ("historical", "HISTORICAL"), ("roam", "ROAM"))
GOAL_TEMPLATES = {"THREAT_MODEL": "goal-threat-model.md", "HISTORICAL": "goal-historical.md", "ROAM": "goal-roam.md"}

_PERMALINK = re.compile(r"github\.com/([^/\s)]+/[^/\s)]+)/(?:blob|tree)/([0-9A-Za-z._-]+)/")
_TOKEN = re.compile(r"[a-z0-9_]{3,}")
_STOPWORDS = frozenset(
    "the and for with that this from into when can not are was via has its all any but use used using may "
    "which where while would could should does did then than them they there their have been being will".split()
)


class CollectorError(RuntimeError):
    """Programming error or missing upstream artifact; exits the node non-zero."""


# --------------------------------------------------------------------------- helpers


def dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def attempt_id(kind: str, work_item_id: str, profile_id: str, replica: int) -> str:
    return f"{kind}:{work_item_id}:{profile_id}:r{replica}"


def lead_id(attempt: str, caller_key: str) -> str:
    return "lead_" + sha256_hex(attempt + "\0" + caller_key)[:16]


def finding_id(caller_key: str) -> str:
    return "finding_" + sha256_hex(caller_key)[:16]


@functools.lru_cache(maxsize=None)
def _schema_text(name: str) -> str:
    base = name.removesuffix(".json").removesuffix(".schema")
    path = SCHEMAS_DIR / f"{base}.schema.json"
    if not path.is_file():
        raise CollectorError(f"unknown schema {name!r}; expected one of {sorted(p.name for p in SCHEMAS_DIR.glob('*.schema.json'))}")
    return path.read_text(encoding="utf-8")


def load_schema(name: str) -> dict[str, Any]:
    """Load ``schemas/<name>.schema.json`` (``name`` may carry either suffix)."""

    return json.loads(_schema_text(name))


@functools.lru_cache(maxsize=None)
def _shared_schema(name: str) -> dict[str, Any]:
    return load_schema(name)


def schema_errors(instance: Any, schema: str | Mapping[str, Any]) -> list[str]:
    """``agentflow.contracts.validate_json_instance`` against a named or inline schema.

    Collectors and the orchestrator's retry feedback therefore describe the same
    violation with the same pointer text and cap.
    """

    resolved = _shared_schema(schema) if isinstance(schema, str) else dict(schema)
    return validate_json_instance(instance, resolved)


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout


@functools.lru_cache(maxsize=None)
def _glob_regex(pattern: str) -> re.Pattern[str]:
    out = ""
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if pattern.startswith("**/", index):
            out += "(?:.*/)?"
            index += 3
        elif pattern.startswith("**", index):
            out += ".*"
            index += 2
        elif char == "*":
            out += "[^/]*"
            index += 1
        elif char == "?":
            out += "[^/]"
            index += 1
        else:
            out += re.escape(char)
            index += 1
    return re.compile(f"^{out}$")


def _matches_any(path: str, patterns: Iterable[str]) -> bool:
    for pattern in patterns:
        regex = _glob_regex(pattern)
        if regex.match(path) or ("/" not in pattern and regex.match(path.rsplit("/", 1)[-1])):
            return True
    return False


def _screaming(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).upper()


def _placeholder_text(value: Any) -> str:
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, sort_keys=True)


def _tokens(*texts: Any) -> set[str]:
    joined = " ".join(_placeholder_text(text) for text in texts if text is not None).lower()
    return {token for token in _TOKEN.findall(joined) if token not in _STOPWORDS}


def _title_from_claim(claim: str) -> str:
    first = claim.strip().splitlines()[0] if claim.strip() else "Untitled lead"
    return first if len(first) <= 120 else first[:117].rstrip() + "..."


def _repository_slug(repository_url: str | None) -> str | None:
    """``owner/repo`` (lower-cased, without ``.git``) of a GitHub repository URL."""

    if not repository_url:
        return None
    segments = [segment for segment in urlsplit(str(repository_url)).path.split("/") if segment]
    if len(segments) < 2:
        return None
    return f"{segments[0]}/{segments[1].removesuffix('.git')}".lower()


def _fit_output(build: Callable[[int], dict[str, Any]], count: int) -> tuple[dict[str, Any], int]:
    """``build(n)`` for the largest ``n <= count`` that serializes within ``OUTPUT_BUDGET_BYTES``.

    Planners copy every work item into every slot lane, so their output grows with
    items x slots; the items past ``n`` are deferred and reported by the caller.
    """

    def fits(n: int) -> bool:
        return len(dumps(build(n)).encode("utf-8")) <= OUTPUT_BUDGET_BYTES

    if fits(count):
        return build(count), count
    if not fits(0):
        raise CollectorError(f"collector output exceeds {OUTPUT_BUDGET_BYTES} bytes without any work item")
    low, high = 0, count
    while high - low > 1:
        middle = (low + high) // 2
        if fits(middle):
            low = middle
        else:
            high = middle
    return build(low), low


# --------------------------------------------------------------------------- run view


class RunView:
    """Read-only view of one AgentFlow run directory plus the collector's own artifact dir."""

    def __init__(self, run_dir: str | Path, run_id: str, node_id: str) -> None:
        self.run_dir = Path(run_dir)
        self.run_id = run_id
        self.node_id = node_id
        self._record: dict[str, Any] | None = None
        self._inputs: dict[str, Any] | None = None

    @classmethod
    def from_environment(cls, environ: Mapping[str, str] | None = None) -> "RunView":
        env = os.environ if environ is None else environ
        missing = [name for name in (RUN_DIR_ENV, RUN_ID_ENV, NODE_ID_ENV) if not env.get(name)]
        if missing:
            raise CollectorError(f"missing environment variables: {', '.join(missing)}")
        return cls(env[RUN_DIR_ENV], env[RUN_ID_ENV], env[NODE_ID_ENV])

    @property
    def record(self) -> dict[str, Any]:
        if self._record is None:
            self._record = self._read_run_json()
        return self._record

    def _read_run_json(self) -> dict[str, Any]:
        path = self.run_dir / "run.json"
        last_error: json.JSONDecodeError | None = None
        for attempt in range(RUN_JSON_ATTEMPTS):
            if attempt:
                time.sleep(RUN_JSON_RETRY_SECONDS)
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                last_error = exc
        raise CollectorError(f"{path} is not valid JSON after {RUN_JSON_ATTEMPTS} attempts") from last_error

    @property
    def artifacts_dir(self) -> Path:
        return self.run_dir / "artifacts" / self.node_id

    def fanout_members(self, template_id: str) -> list[str]:
        members = self.record.get("pipeline", {}).get("fanouts", {}).get(template_id, [])
        return sorted(str(member) for member in members)

    def node_status(self, node_id: str) -> str:
        nodes = self.record.get("nodes", {})
        if node_id not in nodes:
            raise CollectorError(f"unknown node {node_id!r} in run {self.run_id}")
        return str(nodes[node_id].get("status") or "pending")

    def structured_output(self, node_id: str) -> Any | None:
        path = self.run_dir / "artifacts" / node_id / "result.json"
        if not path.is_file():
            return None
        return json.loads(path.read_text(encoding="utf-8")).get("structured_output")

    def node_input(self, node_id: str) -> Any | None:
        if self._inputs is None:
            self._inputs = {node.get("id"): node.get("input") for node in self.record.get("pipeline", {}).get("nodes", [])}
        return self._inputs.get(node_id)

    def write_artifact(self, name: str, text: str) -> Path:
        path = self.artifacts_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def write_json(self, name: str, value: Any) -> Path:
        return self.write_artifact(name, json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


@dataclass
class MemberRow:
    node_id: str
    template_id: str
    item: dict[str, Any]
    status: str
    output: Any | None
    errors: list[str]

    @property
    def ok(self) -> bool:
        return not self.errors

    @property
    def attempt_id(self) -> str:
        return str(self.item.get("attemptId") or self.node_id)

    def gap(self) -> dict[str, Any]:
        return {
            "attemptId": self.attempt_id,
            "nodeId": self.node_id,
            "slotKey": self.item.get("slotKey"),
            "status": self.status,
            "reasons": list(self.errors),
        }


def _member_rows(
    view: RunView,
    template_ids: Iterable[str],
    schema_name: str,
    validate: Callable[[dict[str, Any]], list[str]] | None = None,
) -> list[MemberRow]:
    rows: list[MemberRow] = []
    for template_id in sorted(template_ids):
        for node_id in view.fanout_members(template_id):
            raw_item = view.node_input(node_id)
            item = raw_item if isinstance(raw_item, dict) else {}
            status = view.node_status(node_id)
            output = view.structured_output(node_id)
            errors: list[str] = []
            if status != COMPLETED:
                errors.append(f"status {status}")
            elif output is None:
                errors.append("missing structured output")
            else:
                errors.extend(schema_errors(output, schema_name))
                if not errors and validate is not None:
                    errors.extend(validate(output))
            rows.append(MemberRow(node_id, template_id, item, status, output, errors))
    return rows


def _require_output(view: RunView, node_id: str, schema_name: str | None = None) -> dict[str, Any]:
    output = view.structured_output(node_id)
    if not isinstance(output, dict):
        raise CollectorError(f"node {node_id!r} has no structured output (status {view.node_status(node_id)})")
    if schema_name is not None:
        errors = schema_errors(output, schema_name)
        if errors:
            raise CollectorError(f"node {node_id!r} output violates {schema_name}: {errors[:5]}")
    return output


def _source_commit(view: RunView, params: Mapping[str, Any], *fallbacks: Mapping[str, Any] | None) -> str | None:
    if params.get("snapshotNode"):
        return _require_output(view, params["snapshotNode"]).get("sourceCommit")
    for candidate in fallbacks:
        if candidate and candidate.get("sourceCommit"):
            return str(candidate["sourceCommit"])
    return None


def _slot_fields(slot: Mapping[str, Any]) -> dict[str, Any]:
    return {"profileId": slot["profileId"], "replica": int(slot["replica"]), "slotKey": slot["slotKey"]}


# --------------------------------------------------------------------------- v3 refinement rules


def _has_citation(references: Iterable[Mapping[str, Any]], kinds: Iterable[str]) -> bool:
    wanted = set(kinds)
    return any(reference.get("kind") in wanted for reference in references)


def guidance_review_issues(review: Mapping[str, Any], prefix: str = "guidanceReview") -> list[str]:
    issues: list[str] = []
    references = review.get("references", [])
    if review.get("documentationStatus") != "UNKNOWN" and not _has_citation(references, ("documentation", "specification")):
        issues.append(f"{prefix}.documentationStatus: a documentation judgment requires a documentation or specification citation")
    if review.get("bountyStatus") != "UNKNOWN" and not _has_citation(references, ("bounty-terms",)):
        issues.append(f"{prefix}.bountyStatus: a bounty-scope judgment requires a bounty-terms citation")
    return issues


def _proven_citation_issues(review: Mapping[str, Any]) -> list[str]:
    return [
        f"guidanceReview.references: a proven finding requires a {kind} citation; unavailable guidance is not a completed check"
        for kind in ("documentation", "bounty-terms")
        if not _has_citation(review.get("references", []), (kind,))
    ]


def context_issues(context: Mapping[str, Any]) -> list[str]:
    """Port of the v3 ``triageContextSchema.superRefine`` rules."""

    issues = guidance_review_issues(context["guidanceReview"])
    search = context["knownIssueSearch"]
    disposition = context["disposition"]
    if search["status"] == "COMPLETE" and not search["sources"]:
        issues.append("knownIssueSearch.sources: a completed known-issue search must identify the sources searched")
    if disposition == "KNOWN" and not _has_citation(search["matches"], KNOWN_ISSUE_CITATION_KINDS):
        issues.append("knownIssueSearch.matches: KNOWN requires an exact issue, PR, known-finding, or documentation match")
    if disposition == "INTENDED" and (
        context["guidanceReview"]["documentationStatus"] != "CONTRADICTED"
        or not _has_citation(context["guidanceReview"]["references"], ("documentation",))
    ):
        issues.append("guidanceReview: INTENDED requires authoritative documentation contradicting the finding's expected behavior")
    if disposition == "FIXED" and context.get("fixCommit") is None:
        issues.append("fixCommit: FIXED requires the fix commit verified in the target snapshot")
    if disposition != "REVIEW":
        if context["validityRequired"] or context["impactRequired"] or context["validityMethods"] or context["impactMethods"]:
            issues.append("disposition: non-REVIEW dispositions must not schedule validity or impact experiments")
        return issues
    if not context["validityRequired"] and not context["existingEvidenceIds"]:
        issues.append("existingEvidenceIds: skipping validity for a REVIEW finding requires existing evidence")
    for stage in ("validity", "impact"):
        if bool(context[f"{stage}Required"]) != bool(context[f"{stage}Methods"]):
            issues.append(f"{stage}Methods: methods must be nonempty exactly when {stage} experiments are required")
    return issues


def evidence_issues(evidence: Mapping[str, Any], expected_stage: str | None = None) -> list[str]:
    """Port of the v3 ``triageEvidenceSchema.superRefine`` rules."""

    issues = guidance_review_issues(evidence["guidanceReview"])
    if expected_stage is not None and evidence["stage"] != expected_stage:
        issues.append(f"stage: expected {expected_stage}, got {evidence['stage']}")
    state = evidence["state"]
    if state != "INCONCLUSIVE":
        if not evidence["evidenceIds"]:
            issues.append("evidenceIds: a proven or falsified claim requires inspectable evidence")
        if not evidence["methods"]:
            issues.append("methods: a proven or falsified claim must identify how it was tested")
    if state != "PROVEN":
        return issues
    issues.extend(_proven_citation_issues(evidence["guidanceReview"]))
    if evidence["stage"] == "IMPACT":
        assessment = evidence.get("productionAssessment")
        if assessment is None or not assessment["honestNodesUnmodified"] or not assessment["environmentEquivalent"]:
            issues.append(
                "productionAssessment: proven production impact requires a complete equivalent-environment assessment with unmodified honest nodes"
            )
    if "DIFFERENTIAL" not in evidence["methods"]:
        return issues
    results = evidence["differentialResults"]
    by_client = {result["client"]: result for result in results}
    if len(results) != 3 or set(by_client) != {"monad", "geth", "nethermind"}:
        issues.append("differentialResults: a proven differential requires one structured result each from Monad, geth, and Nethermind")
        return issues
    monad, geth, nethermind = by_client["monad"], by_client["geth"], by_client["nethermind"]
    for field in ("fixtureHash", "prestateHash", "fork"):
        if any(result[field] != monad[field] for result in results):
            issues.append(f"differentialResults: differential results must use the same {field}")
    if geth["normalizedOutcome"] != nethermind["normalizedOutcome"] or monad["normalizedOutcome"] == geth["normalizedOutcome"]:
        issues.append(
            "differentialResults: a proven differential requires agreeing reference clients and a different Monad outcome; a mismatch alone is not a bug"
        )
    return issues


def impact_issues(review: Mapping[str, Any]) -> list[str]:
    """Port of the v3 ``triageImpactSchema.superRefine`` rules onto the three-outcome decision."""

    issues = guidance_review_issues(review["guidanceReview"])
    for index, evidence in enumerate(review["impactEvidence"]):
        issues.extend(f"impactEvidence[{index}].{issue}" for issue in evidence_issues(evidence, "IMPACT"))
    decision, reason = review["decision"], review.get("reason")
    if decision == "CONFIRMED":
        for dimension in ("mechanism", "reachability", "impactSupport"):
            if review[dimension] != "SUPPORTED":
                issues.append(f"{dimension}: CONFIRMED requires supported {dimension}")
        if not review["evidenceIds"]:
            issues.append("evidenceIds: CONFIRMED requires inspectable evidence")
        if review["guidanceReview"]["bountyStatus"] != "IN_SCOPE":
            issues.append("guidanceReview.bountyStatus: CONFIRMED requires a verified in-scope bounty claim")
        issues.extend(_proven_citation_issues(review["guidanceReview"]))
        if reason is not None:
            issues.append("reason: CONFIRMED requires a null reason")
        if review.get("impact") is None or review.get("likelihood") is None:
            issues.append("impact: CONFIRMED requires impact and likelihood levels for the severity matrix")
    elif reason is None:
        issues.append(f"reason: {decision} requires a reason")
    if reason == "INFORMATIONAL" and review["mechanism"] != "SUPPORTED":
        issues.append("mechanism: INFORMATIONAL means a supported local mechanism with unestablished or limited production impact")
    if reason == "KNOWN" and not _has_citation(review["guidanceReview"]["references"], KNOWN_ISSUE_CITATION_KINDS):
        issues.append("guidanceReview.references: KNOWN requires the matching known report or documentation citation")
    if reason == "INTENDED" and (
        review["guidanceReview"]["documentationStatus"] != "CONTRADICTED"
        or not _has_citation(review["guidanceReview"]["references"], ("documentation",))
    ):
        issues.append("guidanceReview: INTENDED requires authoritative documentation contradicting the finding's expected behavior")
    if bool(review["pocProvided"]) != (review["pocEnvironment"] != "none"):
        issues.append("pocEnvironment: pocProvided must agree with pocEnvironment (devnet or solonet when provided, none otherwise)")
    return issues


# --------------------------------------------------------------------------- collectors


def collect_snapshot(view: RunView, params: Mapping[str, Any]) -> dict[str, Any]:
    source_commit = _git("rev-parse", "HEAD").strip()
    files = [path for path in _git("ls-files", "-z").split("\0") if path]
    include = list(params.get("include") or ["**/*"])
    exclude = list(params.get("exclude") or [])
    scope = sorted(path for path in files if _matches_any(path, include) and not _matches_any(path, exclude))
    scope_path = view.write_artifact("scope-files.txt", "".join(f"{path}\n" for path in scope))
    return {
        "targetId": params["targetId"],
        "repositoryUrl": params["repositoryUrl"],
        "sourceRef": params["sourceRef"],
        "sourceCommit": source_commit,
        "scopeFiles": scope,
        "scopeFilesPath": str(scope_path),
        "trackedFileCount": len(files),
    }


def collect_plan_file_hunts(view: RunView, params: Mapping[str, Any]) -> dict[str, Any]:
    rank = _require_output(view, params["rankNode"], "rank")
    snapshot = _require_output(view, params["snapshotNode"])
    scope = [str(path) for path in snapshot.get("scopeFiles", [])]
    scope_set = set(scope)
    threshold = int(params["threshold"])
    log: list[str] = []
    ranked: dict[str, dict[str, Any]] = {}
    for entry in rank["rankedFiles"]:
        path = entry["path"]
        if path not in scope_set:
            log.append(f"dropped ranked path outside scope: {path}")
        elif path in ranked:
            log.append(f"duplicate rank for {path}; kept the first")
        else:
            ranked[path] = {
                "path": path,
                "score": int(entry["score"]),
                "securityObjective": entry["securityObjective"],
                "rationale": entry["rationale"],
            }
    unranked = sorted(path for path in scope if path not in ranked)
    for path in unranked:
        ranked[path] = {"path": path, "score": 1, "securityObjective": "unranked", "rationale": "unranked"}
    rank_path = view.write_json(
        "ranked-files.json",
        {path: {key: value for key, value in entry.items() if key != "path"} for path, entry in sorted(ranked.items())},
    )
    above_threshold = sorted(
        (entry for entry in ranked.values() if entry["score"] >= threshold),
        key=lambda entry: (-entry["score"], entry["path"]),
    )
    max_items = int(params["maxItemsPerSlot"])
    selected = above_threshold[:max_items]
    if len(above_threshold) > max_items:
        log.append(f"deferred {len(above_threshold) - max_items} ranked files above maxItemsPerSlot={max_items}")
    source_commit = snapshot.get("sourceCommit")

    def item(entry: Mapping[str, Any], slot: Mapping[str, Any]) -> dict[str, Any]:
        # Objective and rationale stay in ranked-files.json; every slot copies every item.
        return {
            "attemptId": attempt_id("FILE", f"file:{entry['path']}", slot["profileId"], int(slot["replica"])),
            "kind": "FILE",
            "workItemId": f"file:{entry['path']}",
            **_slot_fields(slot),
            "sourceCommit": source_commit,
            "path": entry["path"],
            "score": entry["score"],
            "rankPath": str(rank_path),
        }

    def build(count: int) -> dict[str, Any]:
        deferred = [entry["path"] for entry in above_threshold[count:]]
        return {
            "lanes": {slot["slotKey"]: [item(entry, slot) for entry in selected[:count]] for slot in params["slots"]},
            "threshold": threshold,
            "selectedCount": count,
            "deferredCount": len(deferred),
            "deferred": deferred[:LIST_CAP],
            "belowThreshold": len(ranked) - len(above_threshold),
            "unranked": unranked[:LIST_CAP],
            "unrankedCount": len(unranked),
            "sourceCommit": source_commit,
            "rankPath": str(rank_path),
            "log": log,
        }

    result, planned = _fit_output(build, len(selected))
    if planned < len(selected):
        log.append(f"deferred {len(selected) - planned} ranked files over the {OUTPUT_BUDGET_BYTES}-byte output budget")
    return result


def collect_plan_context_workers(view: RunView, params: Mapping[str, Any]) -> dict[str, Any]:
    snapshot = _require_output(view, params["snapshotNode"])
    threat: dict[str, list[dict[str, Any]]] = {}
    history: dict[str, list[dict[str, Any]]] = {}
    # The corpus travels as a file: one copy per slot would repeat it in every lane item.
    history_path = str(view.write_artifact("history.txt", str(params.get("historyText") or ""))) if params.get("history") else None
    for slot in params["slots"]:
        fields = {
            **_slot_fields(slot),
            "targetId": snapshot.get("targetId"),
            "sourceCommit": snapshot.get("sourceCommit"),
        }
        threat[slot["slotKey"]] = [
            {
                "attemptId": attempt_id("THREAT_DRAFT", "threat-model", slot["profileId"], int(slot["replica"])),
                "kind": "THREAT_DRAFT",
                "workItemId": "threat-model",
                **fields,
            }
        ]
        if history_path is not None:
            history[slot["slotKey"]] = [
                {
                    "attemptId": attempt_id("HISTORY", "history", slot["profileId"], int(slot["replica"])),
                    "kind": "HISTORY",
                    "workItemId": "history",
                    **fields,
                    "historyPath": history_path,
                }
            ]
    return {"threat": threat, "history": history, "sourceCommit": snapshot.get("sourceCommit")}


def collect_threat_drafts(view: RunView, params: Mapping[str, Any]) -> dict[str, Any]:
    rows = _member_rows(view, params["templates"], "threat-model-draft")
    drafts = [
        {
            "attemptId": row.attempt_id,
            "nodeId": row.node_id,
            "profileId": row.item.get("profileId"),
            "replica": row.item.get("replica"),
            "slotKey": row.item.get("slotKey"),
            "draft": row.output,
        }
        for row in rows
        if row.ok
    ]
    return {
        "drafts": sorted(drafts, key=lambda draft: draft["attemptId"]),
        "gaps": sorted((row.gap() for row in rows if not row.ok), key=lambda gap: gap["attemptId"]),
    }


def collect_history_candidates(view: RunView, params: Mapping[str, Any]) -> dict[str, Any]:
    rows = _member_rows(view, params["templates"], "history-candidates")
    candidates: list[dict[str, Any]] = []
    attempts: list[dict[str, Any]] = []
    log: list[str] = []
    for row in rows:
        if not row.ok:
            continue
        seen: set[str] = set()
        for candidate in row.output["candidates"]:
            if candidate["key"] in seen:
                log.append(f"{row.attempt_id}: duplicate candidate key {candidate['key']}; kept the first")
                continue
            seen.add(candidate["key"])
            candidates.append({**candidate, "sourceAttemptId": row.attempt_id})
        attempts.append(
            {
                "attemptId": row.attempt_id,
                "nodeId": row.node_id,
                "profileId": row.item.get("profileId"),
                "replica": row.item.get("replica"),
                "slotKey": row.item.get("slotKey"),
                "candidateCount": len(seen),
            }
        )
    return {
        "candidates": sorted(candidates, key=lambda c: (c["sourceAttemptId"], c["key"])),
        "attempts": sorted(attempts, key=lambda a: a["attemptId"]),
        "gaps": sorted((row.gap() for row in rows if not row.ok), key=lambda gap: gap["attemptId"]),
        "log": log,
    }


def _threat_model_issues(synthesis: Mapping[str, Any], drafts: list[dict[str, Any]]) -> list[str]:
    issues: list[str] = []
    canonical: dict[str, set[str]] = {}
    for entity_type, field in ENTITY_FIELDS.items():
        keys = [entity["key"] for entity in synthesis[field]]
        canonical[entity_type] = set(keys)
        issues.extend(f"duplicate canonical {entity_type} key {key}" for key, count in sorted(Counter(keys).items()) if count > 1)
    draft_keys: dict[tuple[str, str], set[str]] = {}
    for draft in drafts:
        for entity_type, field in ENTITY_FIELDS.items():
            draft_keys[(draft["attemptId"], entity_type)] = {entity["key"] for entity in draft["draft"][field]}
    mapping_counts = Counter((m["sourceAttemptId"], m["entityType"], m["sourceKey"]) for m in synthesis["entityMappings"])
    for (attempt, entity_type), keys in sorted(draft_keys.items()):
        for key in sorted(keys):
            count = mapping_counts.get((attempt, entity_type, key), 0)
            if count == 0:
                issues.append(f"unmapped {entity_type} {key} from draft {attempt}")
            elif count > 1:
                issues.append(f"{count} mappings for {entity_type} {key} from draft {attempt}; expected exactly one")
    for mapping in synthesis["entityMappings"]:
        source = (mapping["sourceAttemptId"], mapping["entityType"])
        if source not in draft_keys:
            issues.append(f"mapping references unknown draft {mapping['sourceAttemptId']}")
        elif mapping["sourceKey"] not in draft_keys[source]:
            issues.append(f"mapping references unknown {mapping['entityType']} {mapping['sourceKey']} in draft {mapping['sourceAttemptId']}")
        if mapping["canonicalKey"] not in canonical[mapping["entityType"]]:
            issues.append(f"mapping targets unknown canonical {mapping['entityType']} {mapping['canonicalKey']}")
        if mapping["disposition"] == "DEDUPLICATED" and not (mapping.get("rationale") or "").strip():
            issues.append(f"DEDUPLICATED mapping {mapping['entityType']} {mapping['sourceKey']} from {mapping['sourceAttemptId']} lacks a rationale")
    source_models = {source["attemptId"] for source in synthesis["sourceModels"]}
    draft_ids = {draft["attemptId"] for draft in drafts}
    issues.extend(f"sourceModels omits completed draft {attempt}" for attempt in sorted(draft_ids - source_models))
    issues.extend(f"sourceModels references unknown draft {attempt}" for attempt in sorted(source_models - draft_ids))
    for threat in synthesis["threats"]:
        for field, entity_type in (("actorKeys", "actor"), ("assetKeys", "asset"), ("boundaryKeys", "trust_boundary")):
            issues.extend(
                f"threat {threat['key']} references unknown {entity_type} {key}" for key in threat[field] if key not in canonical[entity_type]
            )
    return sorted(set(issues))


def collect_threat_model(view: RunView, params: Mapping[str, Any]) -> dict[str, Any]:
    synthesis = _require_output(view, params["synthesisNode"], "threat-model-canonical")
    drafts = list(_require_output(view, params["draftsNode"]).get("drafts", []))
    model: dict[str, Any] = {
        "modelId": "tm_" + sha256_hex(view.run_id)[:12],
        "revision": 1,
        "targetId": params.get("targetId"),
        "sourceCommit": _source_commit(view, params),
        **synthesis,
        "threats": [{**threat, "threatId": threat["key"]} for threat in synthesis["threats"]],
    }
    path = view.write_artifact("threat-model.md", rendering.render_threat_model_markdown(model))
    return {"threatModel": model, "markdownPath": str(path), "log": _threat_model_issues(synthesis, drafts)}


def _history_model_issues(synthesis: Mapping[str, Any], candidates: list[dict[str, Any]], attempts: list[dict[str, Any]]) -> list[str]:
    issues: list[str] = []
    item_ids = [item["threatId"] for item in synthesis["items"]]
    issues.extend(f"duplicate historical threatId {tid}" for tid, count in sorted(Counter(item_ids).items()) if count > 1)
    candidate_keys = {(c["sourceAttemptId"], c["key"]) for c in candidates}
    mapping_counts = Counter((m["sourceAttemptId"], m["sourceKey"]) for m in synthesis["mappings"])
    for attempt, key in sorted(candidate_keys):
        count = mapping_counts.get((attempt, key), 0)
        if count == 0:
            issues.append(f"unmapped candidate {key} from attempt {attempt}")
        elif count > 1:
            issues.append(f"{count} mappings for candidate {key} from attempt {attempt}; expected exactly one")
    known_items = set(item_ids)
    for mapping in synthesis["mappings"]:
        if (mapping["sourceAttemptId"], mapping["sourceKey"]) not in candidate_keys:
            issues.append(f"mapping references unknown candidate {mapping['sourceKey']} from attempt {mapping['sourceAttemptId']}")
        if mapping["threatId"] not in known_items:
            issues.append(f"mapping targets unknown historical threat {mapping['threatId']}")
    attempt_ids = {attempt["attemptId"] for attempt in attempts}
    listed = set(synthesis["sourceAttemptIds"])
    issues.extend(f"sourceAttemptIds omits completed attempt {attempt}" for attempt in sorted(attempt_ids - listed))
    issues.extend(f"sourceAttemptIds references unknown attempt {attempt}" for attempt in sorted(listed - attempt_ids))
    return sorted(set(issues))


def collect_history_model(view: RunView, params: Mapping[str, Any]) -> dict[str, Any]:
    synthesis = _require_output(view, params["synthesisNode"], "history-catalog")
    candidates_output = _require_output(view, params["candidatesNode"])
    candidates = list(candidates_output.get("candidates", []))
    attempts = list(candidates_output.get("attempts", []))
    model = {
        "modelId": "hm_" + sha256_hex(view.run_id)[:12],
        "revision": 1,
        "targetId": params.get("targetId"),
        "sourceCommit": _source_commit(view, params),
        "items": sorted(synthesis["items"], key=lambda item: item["threatId"]),
        "sourceAttemptIds": sorted(synthesis["sourceAttemptIds"]),
        "mappings": sorted(synthesis["mappings"], key=lambda m: (m["sourceAttemptId"], m["sourceKey"], m["threatId"])),
    }
    path = view.write_artifact("history-catalog.md", rendering.render_history_markdown(model))
    return {"historyModel": model, "markdownPath": str(path), "log": _history_model_issues(synthesis, candidates, attempts)}


def _accepted_goals(
    plan: Mapping[str, Any],
    threats_by_id: Mapping[str, dict[str, Any]],
    catalog: Mapping[str, dict[str, Any]] | None,
    max_roam: int,
    log: list[str],
) -> list[tuple[dict[str, Any], dict[str, Any] | None]]:
    dispositions: dict[str, dict[str, Any]] = {}
    for disposition in plan["historyDispositions"]:
        historical_id = disposition["historicalId"]
        if catalog is None or historical_id not in catalog:
            log.append(f"disposition for unknown historical threat {historical_id} ignored")
        elif historical_id in dispositions:
            log.append(f"duplicate disposition for historical threat {historical_id}; kept the first")
        else:
            dispositions[historical_id] = disposition
    for historical_id in sorted(catalog or {}):
        if historical_id not in dispositions:
            log.append(f"missing disposition for historical threat {historical_id}")
    accepted: list[tuple[dict[str, Any], dict[str, Any] | None]] = []
    seen_caller_keys: set[str] = set()
    assigned: set[tuple[str, str]] = set()
    roam_count = 0
    for goal in plan["goals"]:
        caller_key, kind, threat_id = goal["callerKey"], goal["kind"], goal.get("threatId")
        if caller_key in seen_caller_keys:
            log.append(f"duplicate goal callerKey {caller_key}; dropped")
            continue
        record: dict[str, Any] | None = None
        if kind == "THREAT_MODEL":
            if threat_id not in threats_by_id:
                log.append(f"dropped THREAT_MODEL goal {caller_key}: unknown threatId {threat_id}")
                continue
            record = threats_by_id[threat_id]
        elif kind == "HISTORICAL":
            if catalog is None or threat_id not in catalog:
                log.append(f"dropped HISTORICAL goal {caller_key}: unknown historical threat {threat_id}")
                continue
            disposition = dispositions.get(threat_id)
            if disposition is None or disposition["disposition"] != "ELIGIBLE":
                log.append(f"dropped HISTORICAL goal {caller_key}: historical threat {threat_id} is not ELIGIBLE")
                continue
            if disposition.get("goalCallerKey") not in (None, caller_key):
                log.append(f"disposition for {threat_id} names goal {disposition['goalCallerKey']} but goal {caller_key} claims it")
            record = catalog[threat_id]
        else:
            if roam_count >= max_roam:
                log.append(f"dropped ROAM goal {caller_key}: maxRoamGoals={max_roam}")
                continue
            roam_count += 1
        if record is not None:
            if (kind, threat_id) in assigned:
                log.append(f"dropped {kind} goal {caller_key}: threat {threat_id} already has a goal")
                continue
            assigned.add((kind, threat_id))
        seen_caller_keys.add(caller_key)
        accepted.append((goal, record))
    for historical_id, disposition in sorted(dispositions.items()):
        if disposition["disposition"] == "ELIGIBLE" and ("HISTORICAL", historical_id) not in assigned:
            log.append(f"ELIGIBLE historical threat {historical_id} has no goal")
    return accepted


def _overlay_values(goal: Mapping[str, Any], record: Mapping[str, Any] | None, model: Mapping[str, Any] | None, context: Any) -> dict[str, str]:
    values = {f"GOAL_{_screaming(key)}": _placeholder_text(value) for key, value in goal.items()}
    if record is not None:
        for key, value in record.items():
            name = _screaming(key)
            values[name] = _placeholder_text(value)
            if not name.startswith("THREAT_"):
                values[f"THREAT_{name}"] = values[name]
    for key, value in goal.items():
        values.setdefault(_screaming(key), _placeholder_text(value))
    if model is not None:
        values["THREAT_MODEL_ID"] = str(model["modelId"])
        values["THREAT_MODEL_REVISION"] = str(model["revision"])
    statement = (record or {}).get("violation") or (record or {}).get("statement") or goal["outcome"]
    values["THREAT_STATEMENT"] = _placeholder_text(statement)
    values["THREAT_CONTEXT"] = json.dumps(context, ensure_ascii=False, sort_keys=True)
    return values


def _render_overlay(template_text: str, values: Mapping[str, str], template_name: str) -> str:
    unresolved = sorted({match.group(1) for match in TEMPLATE_PLACEHOLDER.finditer(template_text)} - set(values))
    if unresolved:
        raise CollectorError(f"template {template_name} has unresolved placeholders {unresolved}; known: {sorted(values)}")
    return TEMPLATE_PLACEHOLDER.sub(lambda match: values[match.group(1)], template_text)


def _threat_context(threat: Mapping[str, Any], model: Mapping[str, Any], markdown_path: str | None) -> dict[str, Any]:
    def linked(field: str, keys_field: str) -> list[dict[str, Any]]:
        wanted = set(threat.get(keys_field, []))
        return sorted((entity for entity in model.get(field, []) if entity["key"] in wanted), key=lambda entity: entity["key"])

    return {
        "modelId": model["modelId"],
        "revision": model["revision"],
        "threat": dict(threat),
        "actors": linked("actors", "actorKeys"),
        "assets": linked("assets", "assetKeys"),
        "trustBoundaries": linked("trustBoundaries", "boundaryKeys"),
        "markdownPath": markdown_path,
    }


def collect_plan_goal_hunts(view: RunView, params: Mapping[str, Any]) -> dict[str, Any]:
    plan = _require_output(view, params["goalPlanNode"], "goal-plan")
    threat_output = _require_output(view, params["threatModelNode"])
    threat_model = threat_output["threatModel"]
    history_output = _require_output(view, params["historyModelNode"]) if params.get("historyModelNode") else None
    history_model = history_output["historyModel"] if history_output else None
    templates_dir = Path(params["templatesDir"])
    max_roam = int(params.get("maxRoamGoals") or 0)
    max_items = int(params["maxItemsPerSlot"])
    source_commit = _source_commit(view, params, threat_model)
    log: list[str] = []
    threats_by_id = {threat.get("threatId", threat["key"]): threat for threat in threat_model["threats"]}
    catalog = {item["threatId"]: item for item in history_model["items"]} if history_model else None
    accepted = _accepted_goals(plan, threats_by_id, catalog, max_roam, log)

    @functools.lru_cache(maxsize=None)
    def template_text(kind: str) -> str:
        path = templates_dir / GOAL_TEMPLATES[kind]
        if not path.is_file():
            raise CollectorError(f"missing goal template {path}")
        return path.read_text(encoding="utf-8")

    planned: list[dict[str, Any]] = []
    for goal, record in accepted:
        kind = goal["kind"]
        if kind == "THREAT_MODEL":
            model, context = threat_model, _threat_context(record or {}, threat_model, threat_output.get("markdownPath"))
        elif kind == "HISTORICAL":
            model = history_model or {}
            context = {"modelId": model.get("modelId"), "revision": model.get("revision"), "threat": dict(record or {}), "markdownPath": (history_output or {}).get("markdownPath")}
        else:
            model, context = None, {"goal": dict(goal)}
        overlay = _render_overlay(template_text(kind), _overlay_values(goal, record, model, context), GOAL_TEMPLATES[kind])
        threat_id = goal.get("threatId") if record is not None else None
        work_item_id = f"{kind}:{model['modelId']}:{model['revision']}:{threat_id}" if model else f"ROAM:{goal['callerKey']}"
        planned.append({"kind": kind, "workItemId": work_item_id, "threatId": threat_id, "goal": dict(goal), "overlay": overlay})

    per_kind = Counter(item["kind"] for item in planned)
    for kind, count in sorted(per_kind.items()):
        if count > max_items:
            log.append(f"deferred {count - max_items} {kind} goals above maxItemsPerSlot={max_items}")
    seen: Counter[str] = Counter()
    capped: list[dict[str, Any]] = []
    for item in planned:
        seen[item["kind"]] += 1
        if seen[item["kind"]] <= max_items:
            capped.append(item)

    def goal_row(item: Mapping[str, Any]) -> dict[str, Any]:
        return {"kind": item["kind"], "workItemId": item["workItemId"], "threatId": item["threatId"], "callerKey": item["goal"]["callerKey"]}

    def build(count: int) -> dict[str, Any]:
        chosen = capped[:count]
        return {
            "lanes": {
                f"{lane}__{slot['slotKey']}": [
                    {
                        "attemptId": attempt_id(kind, item["workItemId"], slot["profileId"], int(slot["replica"])),
                        **_slot_fields(slot),
                        "sourceCommit": source_commit,
                        **item,
                    }
                    for item in chosen
                    if item["kind"] == kind
                ]
                for slot in params["slots"]
                for lane, kind in GOAL_LANES
            },
            "goals": [goal_row(item) for item in chosen],
            "deferredGoals": [goal_row(item) for item in planned if item not in chosen],
            "sourceCommit": source_commit,
            "log": log,
        }

    result, planned_count = _fit_output(build, len(capped))
    if planned_count < len(capped):
        log.append(f"deferred {len(capped) - planned_count} goals over the {OUTPUT_BUDGET_BYTES}-byte output budget")
    return result


def collect_leads(view: RunView, params: Mapping[str, Any]) -> dict[str, Any]:
    rows = _member_rows(view, params["templates"], "hunt-result")
    attempts: list[dict[str, Any]] = []
    leads: list[dict[str, Any]] = []
    for row in rows:
        item = row.item
        base = {
            "attemptId": row.attempt_id,
            "nodeId": row.node_id,
            "templateId": row.template_id,
            "kind": item.get("kind"),
            "workItemId": item.get("workItemId"),
            "profileId": item.get("profileId"),
            "replica": item.get("replica"),
            "slotKey": item.get("slotKey"),
            "sourceCommit": item.get("sourceCommit"),
            "path": item.get("path"),
            "threatId": item.get("threatId"),
        }
        if not row.ok:
            state = row.status.upper() if row.status != COMPLETED else "FAILED"
            attempts.append({**base, "terminalState": state, "summary": None, "leadIds": [], "notes": list(row.errors)})
            continue
        notes: list[str] = []
        seen: set[str] = set()
        attempt_leads: list[dict[str, Any]] = []
        for lead in row.output["leads"]:
            caller_key = lead["callerKey"]
            if caller_key in seen:
                notes.append(f"duplicate lead callerKey {caller_key}; kept the first")
                continue
            seen.add(caller_key)
            attempt_leads.append(
                {
                    "leadId": lead_id(row.attempt_id, caller_key),
                    "attemptId": row.attempt_id,
                    "kind": base["kind"],
                    "workItemId": base["workItemId"],
                    "path": base["path"],
                    "threatId": base["threatId"],
                    "sourceCommit": base["sourceCommit"],
                    "callerKey": caller_key,
                    "claim": lead["claim"],
                    "locations": list(lead["locations"]),
                    "evidence": lead["evidence"],
                    "attackerPreconditions": lead.get("attackerPreconditions"),
                    "impact": lead.get("impact"),
                    "validationPlan": lead.get("validationPlan"),
                }
            )
        state = row.output["result"]
        if state == "BUG_FOUND" and not attempt_leads:
            state = "EXHAUSTED"
            notes.append("BUG_FOUND without leads downgraded to EXHAUSTED")
        attempts.append(
            {
                **base,
                "terminalState": state,
                "summary": row.output["summary"],
                "leadIds": sorted(lead["leadId"] for lead in attempt_leads),
                "notes": notes,
            }
        )
        leads.extend(attempt_leads)
    result = {
        "attempts": sorted(attempts, key=lambda attempt: attempt["attemptId"]),
        "leads": sorted(leads, key=lambda lead: lead["leadId"]),
    }
    view.write_json("leads.json", result)
    return result


def load_known_findings(path: str | Path | None) -> tuple[list[dict[str, Any]], list[str]]:
    """Read the append-only JSONL corpus; malformed lines are reported, not raised."""

    if not path or not Path(path).is_file():
        return [], []
    records: list[dict[str, Any]] = []
    errors: list[str] = []
    for number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            errors.append(f"known findings line {number} is not valid JSON")
            continue
        if isinstance(record, dict):
            records.append(record)
        else:
            errors.append(f"known findings line {number} is not an object")
    return records, errors


def _known_candidates(finding: Mapping[str, Any], leads: list[dict[str, Any]], corpus: list[dict[str, Any]]) -> list[dict[str, Any]]:
    tokens = _tokens(finding["title"], finding["rootCause"], *(location for lead in leads for location in lead["locations"]))
    candidates = []
    for record in corpus:
        shared = tokens & _tokens(record.get("title"), record.get("rootCause"), record.get("locations"))
        if len(shared) >= KNOWN_FINDING_MIN_SHARED_TOKENS:
            candidates.append(
                {
                    "knownFindingId": record.get("findingId"),
                    "runId": record.get("runId"),
                    "title": record.get("title"),
                    "decision": record.get("decision"),
                    "reason": record.get("reason"),
                    "severity": record.get("severity"),
                    "sharedTokens": sorted(shared),
                }
            )
    candidates.sort(key=lambda candidate: (-len(candidate["sharedTokens"]), str(candidate["knownFindingId"]), str(candidate["runId"])))
    return candidates[:KNOWN_FINDING_CANDIDATE_CAP]


def _finding(caller_key: str, title: str, root_cause: str, impact: str, lead_ids: list[str], origin: str) -> dict[str, Any]:
    return {
        "findingId": finding_id(caller_key),
        "callerKey": caller_key,
        "title": title,
        "rootCause": root_cause,
        "impact": impact,
        "leadIds": sorted(lead_ids),
        "origin": origin,
    }


def collect_findings(view: RunView, params: Mapping[str, Any]) -> dict[str, Any]:
    dedup = _require_output(view, params["dedupNode"], "dedup")
    leads_output = _require_output(view, params["leadsNode"])
    leads = {lead["leadId"]: lead for lead in leads_output["leads"]}
    attempts = {attempt["attemptId"]: attempt for attempt in leads_output["attempts"]}
    cap = int(params["cap"])
    corpus, log = load_known_findings(params.get("knownFindingsPath"))
    assigned: set[str] = set()
    caller_keys: set[str] = set()
    findings: list[dict[str, Any]] = []
    for entry in dedup["findings"]:
        caller_key = entry["callerKey"]
        if caller_key in caller_keys:
            log.append(f"duplicate finding callerKey {caller_key}; dropped")
            continue
        lead_ids: list[str] = []
        for lid in entry["leadIds"]:
            if lid not in leads:
                log.append(f"finding {caller_key}: unknown leadId {lid} dropped")
            elif lid in assigned:
                log.append(f"finding {caller_key}: leadId {lid} already assigned; kept the first assignment")
            elif lid not in lead_ids:
                lead_ids.append(lid)
        if not lead_ids:
            log.append(f"finding {caller_key} has no valid leads; dropped")
            continue
        caller_keys.add(caller_key)
        assigned.update(lead_ids)
        findings.append(_finding(caller_key, entry["title"], entry["rootCause"], entry["impact"], lead_ids, "dedup"))
    for lid in sorted(set(leads) - assigned):
        lead = leads[lid]
        log.append(f"lead {lid} was not assigned by dedup; created a singleton finding")
        findings.append(
            _finding(f"singleton:{lid}", _title_from_claim(lead["claim"]), lead["claim"], lead.get("impact") or "Impact not stated by the lead.", [lid], "singleton")
        )
    items = []
    for finding in findings:
        finding_leads = [leads[lid] for lid in finding["leadIds"]]
        discovery = sorted({lead["attemptId"] for lead in finding_leads})
        items.append(
            {
                "findingId": finding["findingId"],
                "finding": finding,
                "leads": finding_leads,
                "discoveryOutcomes": [attempts[aid] for aid in discovery if aid in attempts],
                "knownFindingCandidates": _known_candidates(finding, finding_leads, corpus),
            }
        )
    result = {
        "items": items[:cap],
        "deferredFindingIds": [item["findingId"] for item in items[cap:]],
        "findingCount": len(items),
        "log": log,
    }
    view.write_json("findings.json", result)
    return result


def _gap_context(reason: str, source_commit: str | None) -> dict[str, Any]:
    return {
        "disposition": "INCONCLUSIVE",
        "rationale": f"Context gate gap: {reason}",
        "guidanceReview": {"expectedBehavior": "unknown", "documentationStatus": "UNKNOWN", "bountyStatus": "UNKNOWN", "references": []},
        "knownIssueSearch": {"status": "UNAVAILABLE", "sources": [], "matches": []},
        "targetCommit": source_commit or "unknown",
        "fixCommit": None,
        "validityRequired": False,
        "impactRequired": False,
        "existingEvidenceIds": [],
        "validityMethods": [],
        "impactMethods": [],
    }


def _finding_commit(item: Mapping[str, Any]) -> str | None:
    commits = sorted({lead["sourceCommit"] for lead in item.get("leads", []) if lead.get("sourceCommit")})
    return commits[0] if commits else None


def collect_contexts(view: RunView, params: Mapping[str, Any]) -> dict[str, Any]:
    findings_output = _require_output(view, params["findingsNode"])
    items_by_id = {item["findingId"]: item for item in findings_output["items"]}
    rows = _member_rows(view, [params["gateTemplate"]], "triage-context", validate=context_issues)
    log: list[str] = []
    contexts: dict[str, MemberRow] = {}
    for row in rows:
        fid = row.item.get("findingId")
        if fid not in items_by_id:
            log.append(f"context member {row.node_id} references unknown finding {fid}; ignored")
        elif fid in contexts:
            log.append(f"duplicate context member {row.node_id} for finding {fid}; kept the first")
        else:
            contexts[fid] = row
    findings: list[dict[str, Any]] = []
    validity: dict[str, list[dict[str, Any]]] = {slot["slotKey"]: [] for slot in params["validitySlots"]}
    for fid in sorted(items_by_id):
        item = items_by_id[fid]
        row = contexts.get(fid)
        source_commit = _finding_commit(item)
        if row is None:
            gap: str | None = "no context member"
        elif not row.ok:
            gap = "; ".join(row.errors)
        else:
            gap = None
        context = row.output if gap is None else _gap_context(gap, source_commit)
        if gap is None and source_commit and context["targetCommit"] != source_commit:
            log.append(f"finding {fid}: context targetCommit {context['targetCommit']} differs from source commit {source_commit}")
        scheduled = gap is None and context["disposition"] == "REVIEW" and bool(context["validityRequired"])
        entry = {
            "findingId": fid,
            "finding": item["finding"],
            "leads": item["leads"],
            "discoveryOutcomes": item.get("discoveryOutcomes", []),
            "knownFindingCandidates": item.get("knownFindingCandidates", []),
            "context": context,
            "gap": gap,
            "contextNodeId": row.node_id if row is not None else None,
            "validityScheduled": scheduled,
        }
        findings.append(entry)
        if not scheduled:
            continue
        # Leads are the bulk of a finding and every validity slot copies its item, so the
        # item names the bundle file and carries only the ids; the file holds the records.
        finding_path = view.write_json(f"findings/{fid}.json", {key: entry[key] for key in ("findingId", "finding", "leads", "context", "discoveryOutcomes", "knownFindingCandidates")})
        for slot in params["validitySlots"]:
            validity[slot["slotKey"]].append(
                {
                    "attemptId": attempt_id("VALIDITY", fid, slot["profileId"], int(slot["replica"])),
                    "kind": "VALIDITY",
                    "workItemId": fid,
                    "findingId": fid,
                    **_slot_fields(slot),
                    "sourceCommit": source_commit,
                    "finding": item["finding"],
                    "leadIds": list(item["finding"].get("leadIds", [])),
                    "findingPath": str(finding_path),
                    "context": context,
                }
            )
    return {
        "validity": validity,
        "findings": findings,
        "deferredFindingIds": list(findings_output.get("deferredFindingIds", [])),
        "log": log,
    }


def collect_validity(view: RunView, params: Mapping[str, Any]) -> dict[str, Any]:
    contexts_output = _require_output(view, params["contextsNode"])
    rows = _member_rows(view, params["validityTemplates"], "triage-evidence", validate=lambda evidence: evidence_issues(evidence, "VALIDITY"))
    known = {entry["findingId"] for entry in contexts_output["findings"]}
    attempts: dict[str, list[dict[str, Any]]] = defaultdict(list)
    gaps: dict[str, list[dict[str, Any]]] = defaultdict(list)
    log: list[str] = []
    for row in rows:
        fid = row.item.get("findingId")
        if fid not in known:
            log.append(f"validity member {row.node_id} references unknown finding {fid}; ignored")
        elif row.ok:
            attempts[fid].append(
                {
                    "attemptId": row.attempt_id,
                    "nodeId": row.node_id,
                    "profileId": row.item.get("profileId"),
                    "replica": row.item.get("replica"),
                    "slotKey": row.item.get("slotKey"),
                    "evidence": row.output,
                }
            )
        else:
            gaps[fid].append(row.gap())
    items: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for entry in contexts_output["findings"]:
        fid = entry["findingId"]
        if entry.get("gap"):
            skipped.append(entry)
            continue
        items.append(
            {
                "findingId": fid,
                "finding": entry["finding"],
                "leads": entry["leads"],
                "discoveryOutcomes": entry.get("discoveryOutcomes", []),
                "knownFindingCandidates": entry.get("knownFindingCandidates", []),
                "context": entry["context"],
                "validityAttempts": sorted(attempts[fid], key=lambda attempt: attempt["attemptId"]),
                "gaps": sorted(gaps[fid], key=lambda gap: gap["attemptId"]),
            }
        )
    return {
        "items": items,
        "skipped": skipped,
        "deferredFindingIds": list(contexts_output.get("deferredFindingIds", [])),
        "log": log,
    }


def _finding_summary(entry: Mapping[str, Any]) -> dict[str, Any]:
    finding = entry["finding"]
    leads = entry.get("leads", [])
    return {
        "findingId": entry["findingId"],
        "callerKey": finding.get("callerKey"),
        "title": finding.get("title"),
        "rootCause": finding.get("rootCause"),
        "impact": finding.get("impact"),
        "leadIds": list(finding.get("leadIds", [])),
        "locations": sorted({location for lead in leads for location in lead.get("locations", [])}),
        "sourceCommit": _finding_commit(entry),
    }


def collect_trusted_report(view: RunView, params: Mapping[str, Any]) -> dict[str, Any]:
    validity_output = _require_output(view, params["validityNode"])
    rows = _member_rows(view, [params["impactTemplate"]], "triage-impact", validate=impact_issues)
    impacts: dict[str, dict[str, Any]] = {}
    gaps: dict[str, list[dict[str, Any]]] = defaultdict(list)
    log: list[str] = []
    for row in rows:
        fid = str(row.item.get("findingId"))
        if row.ok and fid in impacts:
            log.append(f"duplicate impact member {row.node_id} for finding {fid}; kept the first")
        elif row.ok:
            impacts[fid] = row.output
        else:
            gaps[fid].append(row.gap())
    dispositions: list[dict[str, Any]] = []
    handoffs: list[dict[str, Any]] = []
    summaries: list[dict[str, Any]] = []
    for item in validity_output["items"]:
        fid = item["findingId"]
        impact = impacts.get(fid)
        decision = asdict(
            derive_decision(item["context"], [attempt["evidence"] for attempt in item["validityAttempts"]], impact, policy=dict(params["policy"]))
        )
        if impact is None:
            decision["blockers"] = [*decision["blockers"], *(f"impact gap: {gap['nodeId']} {'; '.join(gap['reasons'])}" for gap in gaps.get(fid, []))]
        dispositions.append({"findingId": fid, **decision})
        summaries.append(_finding_summary(item))
        if decision["decision"] == "CONFIRMED":
            handoffs.append(
                {
                    "findingId": fid,
                    "finding": item["finding"],
                    "leads": item["leads"],
                    "context": item["context"],
                    "validityAttempts": item["validityAttempts"],
                    "impactDecision": impact,
                    "disposition": decision,
                    "severity": decision["severity"],
                    "discoveryOutcomes": item.get("discoveryOutcomes", []),
                    "knownFindingCandidates": item.get("knownFindingCandidates", []),
                }
            )
    for entry in validity_output.get("skipped", []):
        dispositions.append(
            {"findingId": entry["findingId"], "decision": "INCONCLUSIVE", "reason": "UNPROVEN", "severity": None, "blockers": [f"context gap: {entry.get('gap')}"]}
        )
        summaries.append(_finding_summary(entry))
    dispositions.sort(key=lambda disposition: disposition["findingId"])
    handoffs.sort(key=lambda handoff: handoff["findingId"])
    summaries.sort(key=lambda summary: summary["findingId"])
    report = {
        "findingIds": [disposition["findingId"] for disposition in dispositions if disposition["decision"] == "CONFIRMED"],
        "dispositions": dispositions,
        "deferredFindingIds": list(validity_output.get("deferredFindingIds", [])),
    }
    view.write_json("trusted-report.json", report)
    return {
        "items": handoffs,
        **report,
        "findings": summaries,
        "gaps": sorted((gap for fid_gaps in gaps.values() for gap in fid_gaps), key=lambda gap: gap["nodeId"]),
        "log": log,
    }


def report_issues(
    report: Mapping[str, Any],
    expected_finding_id: str | None,
    source_commit: str | None,
    repository: str | None = None,
) -> list[str]:
    """Structural checks on one report; ``repository`` (``owner/repo``) scopes the permalink rule.

    Permalinks into the target repository must pin ``source_commit`` (a branch name
    or another sha is rejected); links into other repositories (reference clients,
    specifications) may pin any ref. Without ``repository`` every GitHub permalink is
    held to the source commit.
    """

    issues: list[str] = []
    markdown = str(report["markdown"])
    if report["findingId"] != expected_finding_id:
        issues.append(f"findingId {report['findingId']} does not match the assigned finding {expected_finding_id}")
    if not markdown.lstrip("\ufeff \r\n").startswith("# "):
        issues.append("markdown must start with a level-one heading")
    if expected_finding_id and expected_finding_id not in markdown:
        issues.append(f"markdown does not mention the finding id {expected_finding_id}")
    if source_commit:
        foreign = sorted(
            {
                ref
                for repo, ref in _PERMALINK.findall(markdown)
                if ref != source_commit and (repository is None or repo.lower() == repository)
            }
        )
        if foreign:
            scope = f" in {repository}" if repository else ""
            issues.append(f"permalinks{scope} must use source commit {source_commit}; found {foreign}")
    return issues


def collect_reports(view: RunView, params: Mapping[str, Any]) -> dict[str, Any]:
    trusted = _require_output(view, params["trustedNode"])
    handoffs = {handoff["findingId"]: handoff for handoff in trusted["items"]}
    summaries = {summary["findingId"]: summary for summary in trusted.get("findings", [])}
    source_commit = params.get("sourceCommit") or next(
        (summary["sourceCommit"] for summary in summaries.values() if summary.get("sourceCommit")), None
    )
    repository = _repository_slug(params.get("repositoryUrl"))
    log: list[str] = []
    if not source_commit:
        log.append("source commit unknown; permalink check skipped")
    elif repository is None:
        log.append("repository unknown; every GitHub permalink must use the source commit")
    rows = _member_rows(view, [params["reportTemplate"]], "report")
    reports: dict[str, dict[str, Any]] = {}
    rejected: list[dict[str, Any]] = []
    for row in rows:
        expected = row.item.get("findingId")
        reasons = list(row.errors)
        if not reasons:
            reasons = report_issues(row.output, expected, source_commit, repository)
        if not reasons and expected not in handoffs:
            reasons = [f"finding {expected} is not in the trusted report"]
        if not reasons and expected in reports:
            reasons = ["duplicate report member; kept the first"]
        if reasons:
            rejected.append({"findingId": expected, "nodeId": row.node_id, "status": row.status, "reasons": reasons})
            continue
        markdown = str(row.output["markdown"])
        path = view.write_artifact(f"reports/{expected}.md", markdown if markdown.endswith("\n") else markdown + "\n")
        reports[expected] = {"findingId": expected, "nodeId": row.node_id, "path": str(path)}
    rejected_ids = {entry["findingId"] for entry in rejected}
    missing = [fid for fid in trusted["findingIds"] if fid not in reports and fid not in rejected_ids]
    summary = {
        "runId": view.run_id,
        "sourceCommit": source_commit,
        "findingIds": list(trusted["findingIds"]),
        "dispositions": list(trusted["dispositions"]),
        "deferredFindingIds": list(trusted.get("deferredFindingIds", [])),
        "reports": [reports[fid] for fid in sorted(reports)],
        "rejected": sorted(rejected, key=lambda entry: (str(entry["findingId"]), entry["nodeId"])),
        "missing": missing,
        "log": log,
    }
    view.write_json("run-summary.json", summary)
    known_path = params.get("knownFindingsPath")
    if known_path:
        recorded_at = utcnow_iso()
        lines = [
            dumps(
                {
                    "recordedAt": recorded_at,
                    "runId": view.run_id,
                    "targetId": params.get("targetId"),
                    "sourceCommit": source_commit,
                    **summaries.get(disposition["findingId"], {"findingId": disposition["findingId"]}),
                    "decision": disposition["decision"],
                    "reason": disposition["reason"],
                    "severity": disposition["severity"],
                    "blockers": disposition.get("blockers", []),
                    "reportPath": reports.get(disposition["findingId"], {}).get("path"),
                }
            )
            for disposition in trusted["dispositions"]
        ]
        Path(known_path).parent.mkdir(parents=True, exist_ok=True)
        with Path(known_path).open("a", encoding="utf-8") as handle:
            handle.write("".join(f"{line}\n" for line in lines))
        summary = {**summary, "knownFindingsPath": str(known_path), "knownFindingsAppended": len(lines)}
    return summary


# --------------------------------------------------------------------------- entry point

_COLLECTOR_FUNCTIONS: tuple[Callable[[RunView, Mapping[str, Any]], dict[str, Any]], ...] = (
    collect_snapshot,
    collect_plan_file_hunts,
    collect_plan_context_workers,
    collect_threat_drafts,
    collect_history_candidates,
    collect_threat_model,
    collect_history_model,
    collect_plan_goal_hunts,
    collect_leads,
    collect_findings,
    collect_contexts,
    collect_validity,
    collect_trusted_report,
    collect_reports,
)
COLLECTORS: dict[str, Callable[[RunView, Mapping[str, Any]], dict[str, Any]]] = {
    name: function
    for function in _COLLECTOR_FUNCTIONS
    for name in (function.__name__, function.__name__.removeprefix("collect_"))
}


def run(name: str, params: Mapping[str, Any]) -> None:
    """Dispatch to ``collect_<name>`` (``name`` may omit the prefix) and print compact JSON."""

    collector = COLLECTORS.get(name)
    if collector is None:
        raise CollectorError(f"unknown collector {name!r}; expected one of {sorted(COLLECTORS)}")
    text = dumps(collector(RunView.from_environment(), dict(params)))
    size = len(text.encode("utf-8"))
    if size > MAX_OUTPUT_BYTES:
        raise CollectorError(
            f"collector {name} output is {size} bytes, above the {MAX_OUTPUT_BYTES}-byte limit AgentFlow retains "
            "per attempt; a longer line is truncated and unparseable, so the node fails here instead"
        )
    sys.stdout.write(text + "\n")
    sys.stdout.flush()
