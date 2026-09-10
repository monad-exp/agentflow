from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from agentflow.contracts import SCHEMA_ERROR_CAP, validate_json_instance
from examples.bugfinder.v3 import collectors
from examples.bugfinder.v3.collectors import load_schema, schema_errors

SCHEMAS_DIR = Path(__file__).resolve().parents[1] / "examples" / "bugfinder" / "v3" / "schemas"
SCHEMA_NAMES = [
    "rank",
    "hunt-result",
    "threat-model-draft",
    "threat-model-canonical",
    "history-candidates",
    "history-catalog",
    "goal-plan",
    "dedup",
    "triage-context",
    "triage-evidence",
    "triage-impact",
    "report",
]

DOC_CITATION = {"kind": "documentation", "url": "https://docs.monad.xyz/x", "revision": "2026-09-01", "excerpt": "Blocks are final."}
BOUNTY_CITATION = {"kind": "bounty-terms", "url": "https://gist.github.com/x", "revision": "abc123", "excerpt": "Consensus bugs are in scope."}
ISSUE_CITATION = {"kind": "issue", "url": "https://github.com/category-labs/monad/issues/1", "revision": "1", "excerpt": "Same bug."}


def sample_rank() -> dict:
    return {"rankedFiles": [{"path": "src/a.rs", "score": 5, "securityObjective": "consensus safety", "rationale": "votes"}]}


def sample_lead(caller_key: str = "lead-a") -> dict:
    return {
        "callerKey": caller_key,
        "claim": "Unchecked vote quorum lets a minority finalize a block",
        "locations": ["src/a.rs:10-20"],
        "evidence": "quorum() compares against len(validators)/2 without stake weighting",
        "attackerPreconditions": "controls one third of validators",
        "impact": "consensus safety violation",
        "validationPlan": "unit test with skewed stake",
    }


def sample_hunt(result: str = "BUG_FOUND", leads: list[dict] | None = None) -> dict:
    return {"result": result, "summary": "Reviewed quorum logic.", "leads": [sample_lead()] if leads is None else leads}


def sample_actor(key: str = "validator") -> dict:
    return {"key": key, "name": "Validator", "role": "consensus participant", "capabilities": ["vote"], "controlledInputs": ["votes"], "excludedPowers": ["forging signatures"], "sourceRefs": ["src/a.rs:1"]}


def sample_asset(key: str = "finality") -> dict:
    return {"key": key, "name": "Finality", "protectedResource": "committed blocks", "securityProperties": ["safety"], "compromiseConsequences": ["double spend"], "sourceRefs": ["src/a.rs:5"]}


def sample_boundary(key: str = "p2p") -> dict:
    return {"key": key, "name": "P2P", "sides": ["network", "node"], "entryPoints": ["gossip"], "enforcedChecks": ["signature"], "sourceRefs": ["src/net.rs:1"]}


def sample_threat(key: str = "T1", *, actor: str = "validator", asset: str = "finality", boundary: str = "p2p") -> dict:
    return {
        "key": key,
        "title": "Minority quorum finalization",
        "violation": "A minority of stake finalizes a block",
        "securityProperty": "safety",
        "attackSurface": ["src/a.rs:quorum"],
        "preconditions": ["one third of validators"],
        "expectedImpact": "chain split",
        "existingControls": ["stake weighting"],
        "confidence": "medium",
        "openQuestions": ["is stake weighting enforced?"],
        "actorKeys": [actor],
        "assetKeys": [asset],
        "boundaryKeys": [boundary],
        "sourceRefs": ["src/a.rs:10"],
    }


def sample_draft() -> dict:
    return {
        "summary": "Consensus node.",
        "scope": "src/",
        "assumptions": ["honest majority"],
        "exclusions": ["key theft"],
        "actors": [sample_actor()],
        "assets": [sample_asset()],
        "trustBoundaries": [sample_boundary()],
        "threats": [sample_threat()],
    }


def sample_canonical(attempt_ids: tuple[str, ...] = ("THREAT_DRAFT:threat-model:p1:r1",)) -> dict:
    model = sample_draft()
    model["sourceModels"] = [{"attemptId": aid} for aid in attempt_ids]
    model["entityMappings"] = [
        {"sourceAttemptId": aid, "entityType": entity_type, "sourceKey": key, "canonicalKey": key, "disposition": "RETAINED"}
        for aid in attempt_ids
        for entity_type, key in (("actor", "validator"), ("asset", "finality"), ("trust_boundary", "p2p"), ("threat", "T1"))
    ]
    model["disagreements"] = ["worker 2 rated T1 high confidence"]
    return model


def sample_candidate(key: str = "H1") -> dict:
    return {
        "key": key,
        "statement": "Block proposals with duplicate transactions were accepted",
        "attackSurface": "block validation",
        "attackerCapability": "proposer",
        "protectedAsset": "ledger integrity",
        "securityImpact": "double execution",
        "excludedPreconditions": ["compromised keys"],
        "sourceIssueRefs": ["issue-42"],
        "knownFindingRefs": [],
        "confidence": "high",
    }


def sample_candidates() -> dict:
    return {"candidates": [sample_candidate()]}


def sample_catalog(attempt_ids: tuple[str, ...] = ("HISTORY:history:p1:r1",), threat_id: str = "hist-1") -> dict:
    item = sample_candidate()
    item.pop("key")
    return {
        "items": [{"threatId": threat_id, **item}],
        "sourceAttemptIds": list(attempt_ids),
        "mappings": [{"sourceAttemptId": aid, "sourceKey": "H1", "threatId": threat_id, "disposition": "RETAINED"} for aid in attempt_ids],
    }


def sample_goal(caller_key: str = "g1", kind: str = "THREAT_MODEL", threat_id: str | None = "T1") -> dict:
    goal = {
        "callerKey": caller_key,
        "kind": kind,
        "outcome": "minority stake finalizes a block",
        "scope": "src/a.rs",
        "attackerCapabilities": ["one third of validators"],
        "excludedPreconditions": ["key theft"],
        "evidenceBar": "reproducible unit test",
    }
    if threat_id is not None:
        goal["threatId"] = threat_id
    return goal


def sample_goal_plan() -> dict:
    return {
        "goals": [sample_goal(), sample_goal("g2", "HISTORICAL", "hist-1"), sample_goal("g3", "ROAM", None)],
        "historyDispositions": [{"historicalId": "hist-1", "disposition": "ELIGIBLE", "rationale": "variant plausible", "goalCallerKey": "g2"}],
    }


def sample_dedup(lead_ids: list[str]) -> dict:
    return {"findings": [{"callerKey": "quorum", "title": "Minority quorum", "rootCause": "unweighted quorum", "impact": "safety", "leadIds": lead_ids}]}


def sample_guidance(documentation: str = "SUPPORTED", bounty: str = "IN_SCOPE") -> dict:
    return {"expectedBehavior": "quorum is stake weighted", "documentationStatus": documentation, "bountyStatus": bounty, "references": [DOC_CITATION, BOUNTY_CITATION]}


def sample_context(commit: str = "c" * 40) -> dict:
    return {
        "disposition": "REVIEW",
        "rationale": "needs a unit test",
        "guidanceReview": sample_guidance(),
        "knownIssueSearch": {"status": "COMPLETE", "sources": ["github:category-labs/monad"], "matches": []},
        "targetCommit": commit,
        "fixCommit": None,
        "validityRequired": True,
        "impactRequired": True,
        "existingEvidenceIds": [],
        "validityMethods": ["UNIT"],
        "impactMethods": ["SOLONET"],
    }


def sample_assessment() -> dict:
    return {
        "network": "solonet",
        "executionCommit": "c" * 40,
        "consensusCommit": "c" * 40,
        "protocolRevision": "v1",
        "attackerCapabilities": ["one third of validators"],
        "entryPath": ["gossip vote"],
        "defenseChecks": ["quorum()"],
        "honestNodesUnmodified": True,
        "mutationManifestRef": "manifest.json",
        "environmentEquivalent": True,
        "evidenceIds": ["ev-2"],
    }


def sample_evidence(stage: str = "VALIDITY", state: str = "PROVEN") -> dict:
    return {
        "stage": stage,
        "state": state,
        "summary": "Unit test reproduces the minority finalization.",
        "guidanceReview": sample_guidance(),
        "evidenceIds": ["ev-1"] if state != "INCONCLUSIVE" else [],
        "methods": ["UNIT"] if state != "INCONCLUSIVE" else [],
        "productionAssessment": sample_assessment() if stage == "IMPACT" else None,
        "differentialResults": [],
    }


def sample_impact(decision: str = "CONFIRMED") -> dict:
    confirmed = decision == "CONFIRMED"
    return {
        "decision": decision,
        "reason": None if confirmed else "UNPROVEN",
        "mechanism": "SUPPORTED",
        "reachability": "SUPPORTED" if confirmed else "UNKNOWN",
        "impactSupport": "SUPPORTED" if confirmed else "UNKNOWN",
        "guidanceReview": sample_guidance(),
        "evidenceIds": ["ev-1", "ev-2"],
        "rationale": "Reproduced on solonet with unmodified honest nodes.",
        "limitations": [],
        "nonRuntimeJustification": None,
        "impactEvidence": [sample_evidence("IMPACT", "PROVEN")],
        "impact": "CRITICAL" if confirmed else None,
        "likelihood": "HIGH" if confirmed else None,
        "ambiguousCellChoice": None,
        "pocProvided": confirmed,
        "pocEnvironment": "solonet" if confirmed else "none",
        "localFullNodeDemonstrated": confirmed,
        "publicEntryPointDemonstrated": confirmed,
    }


def sample_report(finding_id: str, commit: str = "c" * 40) -> dict:
    return {
        "findingId": finding_id,
        "markdown": f"# Minority quorum finalization\n\nFinding `{finding_id}`.\n\nSee https://github.com/category-labs/monad/blob/{commit}/src/a.rs#L10.\n",
    }


SAMPLES = {
    "rank": sample_rank,
    "hunt-result": sample_hunt,
    "threat-model-draft": sample_draft,
    "threat-model-canonical": sample_canonical,
    "history-candidates": sample_candidates,
    "history-catalog": sample_catalog,
    "goal-plan": sample_goal_plan,
    "dedup": lambda: sample_dedup(["lead_0123456789abcdef"]),
    "triage-context": sample_context,
    "triage-evidence": sample_evidence,
    "triage-impact": sample_impact,
    "report": lambda: sample_report("finding_0123456789abcdef"),
}


def _walk_objects(schema: dict):
    if isinstance(schema, dict):
        if schema.get("type") == "object":
            yield schema
        for value in schema.values():
            yield from _walk_objects(value)
    elif isinstance(schema, list):
        for value in schema:
            yield from _walk_objects(value)


def test_schema_files_match_the_design_list():
    assert sorted(path.name for path in SCHEMAS_DIR.glob("*.json")) == sorted(f"{name}.schema.json" for name in SCHEMA_NAMES)


@pytest.mark.parametrize("name", SCHEMA_NAMES)
def test_schema_is_strict_draft_2020_12(name: str):
    schema = json.loads((SCHEMAS_DIR / f"{name}.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False
    for node in _walk_objects(schema):
        assert node["additionalProperties"] is False
        for key in node["required"]:
            prop = node["properties"][key]
            if prop.get("type") == "string" and "enum" not in prop:
                assert prop.get("minLength") == 1, f"{name}: {key} lacks minLength"
    assert "$ref" not in json.dumps(schema).replace('"$ref": "#/', "")


@pytest.mark.parametrize("name", SCHEMA_NAMES)
def test_sample_instances_validate(name: str):
    assert schema_errors(SAMPLES[name](), name) == []


@pytest.mark.parametrize("name", SCHEMA_NAMES)
def test_additional_top_level_property_is_rejected(name: str):
    instance = {**SAMPLES[name](), "provenance": {}}
    assert any(error.startswith("/: Additional properties") for error in schema_errors(instance, name))


def test_load_schema_accepts_both_suffixes_and_rejects_unknown_names():
    assert load_schema("rank") == load_schema("rank.schema.json") == load_schema("rank.schema")
    with pytest.raises(collectors.CollectorError):
        load_schema("does-not-exist")


def test_schema_errors_are_sorted_pointers_and_capped():
    bad = {"rankedFiles": [{"path": "", "score": 9, "securityObjective": "x", "rationale": "y"}] * 30}
    errors = schema_errors(bad, "rank")
    assert len(errors) == SCHEMA_ERROR_CAP
    assert errors == sorted(errors)
    assert errors[0].startswith("/rankedFiles/0/path: ")
    # The collector wrapper is the orchestrator's validator: same pointers, same escaping, same cap.
    assert errors == validate_json_instance(bad, load_schema("rank"))
    slashed = {"type": "object", "properties": {"a/b": {"type": "integer"}}}
    assert schema_errors({"a/b": "x"}, slashed) == ["/a~1b: 'x' is not of type 'integer'"]


@pytest.mark.parametrize(
    ("name", "mutate", "pointer"),
    [
        ("rank", lambda s: s["rankedFiles"][0].__setitem__("score", 6), "/rankedFiles/0/score"),
        ("hunt-result", lambda s: s.__setitem__("result", "MAYBE"), "/result"),
        ("hunt-result", lambda s: s["leads"][0].__setitem__("locations", []), "/leads/0/locations"),
        ("threat-model-draft", lambda s: s["threats"][0].__setitem__("confidence", "certain"), "/threats/0/confidence"),
        ("threat-model-canonical", lambda s: s["entityMappings"][0].__setitem__("entityType", "boundary"), "/entityMappings/0/entityType"),
        ("threat-model-canonical", lambda s: s["entityMappings"][0].__setitem__("disposition", "REJECTED"), "/entityMappings/0/disposition"),
        ("history-candidates", lambda s: s["candidates"][0].__setitem__("sourceIssueRefs", []), "/candidates/0/sourceIssueRefs"),
        ("history-catalog", lambda s: s["items"][0].pop("threatId"), "/items/0"),
        ("goal-plan", lambda s: s["goals"][0].__setitem__("kind", "FILE"), "/goals/0/kind"),
        ("goal-plan", lambda s: s["historyDispositions"][0].__setitem__("disposition", "MAYBE"), "/historyDispositions/0/disposition"),
        ("dedup", lambda s: s["findings"][0].__setitem__("leadIds", []), "/findings/0/leadIds"),
        ("triage-context", lambda s: s["guidanceReview"]["references"][0].__setitem__("kind", "bugdb"), "/guidanceReview/references/0/kind"),
        ("triage-context", lambda s: s["validityMethods"].append("FUZZ"), "/validityMethods/1"),
        ("triage-context", lambda s: s.__setitem__("fixCommit", 7), "/fixCommit"),
        ("triage-evidence", lambda s: s.__setitem__("stage", "REVIEW"), "/stage"),
        ("triage-evidence", lambda s: s.__setitem__("productionAssessment", {"network": "x"}), "/productionAssessment"),
        ("triage-impact", lambda s: s.__setitem__("decision", "KNOWN"), "/decision"),
        ("triage-impact", lambda s: s.__setitem__("reason", "MAYBE"), "/reason"),
        ("triage-impact", lambda s: s["impactEvidence"][0].__setitem__("stage", "VALIDITY"), "/impactEvidence/0/stage"),
        ("triage-impact", lambda s: s.__setitem__("impact", "INFORMATIONAL"), "/impact"),
        ("triage-impact", lambda s: s.__setitem__("pocEnvironment", "mainnet"), "/pocEnvironment"),
        ("report", lambda s: s.__setitem__("markdown", ""), "/markdown"),
    ],
)
def test_enum_and_shape_violations_are_reported(name: str, mutate, pointer: str):
    instance = copy.deepcopy(SAMPLES[name]())
    mutate(instance)
    errors = schema_errors(instance, name)
    assert errors, f"{name} accepted an invalid instance"
    assert any(error.startswith(pointer + ": ") for error in errors), errors


def test_differential_result_shape_matches_v3():
    evidence = sample_evidence()
    evidence["methods"] = ["DIFFERENTIAL"]
    result = {"client": "geth", "fixtureHash": "f", "prestateHash": "p", "fork": "prague", "version": "1", "command": "run", "artifactRef": "a", "normalizedOutcome": "ok"}
    evidence["differentialResults"] = [result]
    assert schema_errors(evidence, "triage-evidence") == []
    evidence["differentialResults"] = [{**result, "client": "besu"}]
    assert any(error.startswith("/differentialResults/0/client: ") for error in schema_errors(evidence, "triage-evidence"))


def test_optional_fields_accept_null_and_absence():
    lead = sample_lead()
    lead["impact"] = None
    del lead["validationPlan"]
    assert schema_errors(sample_hunt(leads=[lead]), "hunt-result") == []
    plan = sample_goal_plan()
    plan["goals"][2]["threatId"] = None
    assert schema_errors(plan, "goal-plan") == []
    mapping = sample_canonical()["entityMappings"][0]
    canonical = sample_canonical()
    canonical["entityMappings"] = [{**mapping, "rationale": None}]
    assert schema_errors(canonical, "threat-model-canonical") == []
