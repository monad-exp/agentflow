from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any

import pytest

from examples.bugfinder.v3 import policy
from examples.bugfinder.v3.config import load_config
from examples.bugfinder.v3.policy import (
    AMBIGUOUS_CELL,
    IMPACT_LEVELS,
    LIKELIHOOD_LEVELS,
    SEVERITY_LEVELS,
    Decision,
    compute_severity,
    derive_decision,
    poc_required,
    severity_guidance_text,
)

POLICY_MD = Path(__file__).resolve().parents[1] / "examples" / "bugfinder" / "v3" / "policy" / "monad-bounty.md"

# The gist's Risk Classification Matrix, (impact, likelihood) -> severity.
MATRIX = {
    ("CRITICAL", "HIGH"): "CRITICAL",
    ("HIGH", "HIGH"): "HIGH",
    ("MEDIUM", "HIGH"): "MEDIUM",
    ("LOW", "HIGH"): "LOW",
    ("CRITICAL", "MEDIUM"): "HIGH",
    ("HIGH", "MEDIUM"): "HIGH",
    ("MEDIUM", "MEDIUM"): "MEDIUM",
    ("LOW", "MEDIUM"): "LOW",
    ("CRITICAL", "LOW"): "MEDIUM",
    ("MEDIUM", "LOW"): "LOW",
    ("LOW", "LOW"): "INFORMATIONAL",
}


@pytest.fixture(scope="module")
def triage_policy() -> dict[str, Any]:
    return load_config().triagePolicy.model_dump()


def vendored_matrix() -> dict[tuple[str, str], str]:
    """Parse the severity table out of the vendored gist."""
    cells: dict[tuple[str, str], str] = {}
    impacts: list[str] = []
    for line in POLICY_MD.read_text(encoding="utf-8").splitlines():
        columns = [column.strip() for column in line.strip().strip("|").split("|")]
        if columns[0] == "Severity Level":
            impacts = [column.removeprefix("Impact:").strip().upper() for column in columns[1:]]
        elif columns[0].startswith("Likelihood:"):
            likelihood = columns[0].removeprefix("Likelihood:").strip().upper()
            for impact, severity in zip(impacts, columns[1:]):
                cells[(impact, likelihood)] = severity.upper().replace(" ", "")
    return cells


def test_matrix_matches_vendored_gist():
    table = vendored_matrix()
    assert set(table) == set(MATRIX) | {AMBIGUOUS_CELL}
    assert table[AMBIGUOUS_CELL] == "MEDIUM/LOW"
    assert {cell: severity for cell, severity in table.items() if cell != AMBIGUOUS_CELL} == MATRIX


@pytest.mark.parametrize("impact,likelihood", sorted(MATRIX))
def test_compute_severity_every_cell(impact: str, likelihood: str):
    assert compute_severity(impact, likelihood) == MATRIX[(impact, likelihood)]
    assert compute_severity(impact, likelihood, "LOW") == MATRIX[(impact, likelihood)]


def test_compute_severity_covers_whole_grid():
    assert set(MATRIX) | {AMBIGUOUS_CELL} == {(i, l) for i in IMPACT_LEVELS for l in LIKELIHOOD_LEVELS}
    assert set(MATRIX.values()) | {"MEDIUM", "LOW"} == set(SEVERITY_LEVELS)


def test_ambiguous_cell():
    assert compute_severity("HIGH", "LOW", "MEDIUM") == "MEDIUM"
    assert compute_severity("HIGH", "LOW", "LOW") == "LOW"
    with pytest.raises(ValueError, match="MEDIUM / LOW"):
        compute_severity("HIGH", "LOW")
    with pytest.raises(ValueError, match="MEDIUM / LOW"):
        compute_severity("HIGH", "LOW", "HIGH")


def test_compute_severity_rejects_unknown_levels():
    with pytest.raises(ValueError, match="unknown impact 'SEVERE'"):
        compute_severity("SEVERE", "HIGH")
    with pytest.raises(ValueError, match="unknown likelihood 'CERTAIN'"):
        compute_severity("LOW", "CERTAIN")


def test_poc_required(triage_policy: dict[str, Any]):
    levels = tuple(triage_policy["pocRequiredForSeverities"])
    assert levels == ("CRITICAL", "HIGH")
    assert poc_required("CRITICAL", levels)
    assert poc_required("HIGH", levels)
    assert not poc_required("MEDIUM", levels)
    assert not poc_required("INFORMATIONAL", levels)
    assert poc_required("MEDIUM", ("MEDIUM",))
    with pytest.raises(ValueError, match="unknown severity"):
        poc_required("SEVERE", levels)


def test_severity_guidance_text():
    text = severity_guidance_text(POLICY_MD.read_text(encoding="utf-8"))
    assert text.startswith("## Proof of Concept (PoC) Requirements")
    assert "## Severity and Rewards" in text
    assert "### Risk Classification Matrix" in text
    assert "## Issue Severity Extended Guidance" in text
    assert "Medium / Low" in text
    assert "## Introduction" not in text
    assert "Areas of concern" not in text
    assert "trusted roles" not in text
    with pytest.raises(ValueError, match="missing sections"):
        severity_guidance_text("## Introduction\n\nnothing here\n")


def guidance(**over: Any) -> dict[str, Any]:
    base = {
        "expectedBehavior": "Blocks with invalid signatures are rejected.",
        "documentationStatus": "SUPPORTED",
        "bountyStatus": "IN_SCOPE",
        "references": [],
    }
    return {**base, **over}


def context(**over: Any) -> dict[str, Any]:
    base = {
        "disposition": "REVIEW",
        "rationale": "Needs validation.",
        "guidanceReview": guidance(),
        "knownIssueSearch": {"status": "COMPLETE", "sources": ["github:category-labs/monad"], "matches": []},
        "targetCommit": "0123abcd",
        "fixCommit": None,
        "validityRequired": True,
        "impactRequired": True,
        "existingEvidenceIds": [],
        "validityMethods": ["UNIT"],
        "impactMethods": ["SOLONET"],
    }
    return {**base, **over}


def evidence(stage: str, state: str, evidence_ids: list[str], methods: list[str]) -> dict[str, Any]:
    return {
        "stage": stage,
        "state": state,
        "summary": f"{stage} {state}",
        "guidanceReview": guidance(),
        "evidenceIds": evidence_ids,
        "methods": methods,
        "productionAssessment": None,
        "differentialResults": [],
    }


def impact(**over: Any) -> dict[str, Any]:
    base = {
        "decision": "CONFIRMED",
        "reason": None,
        "mechanism": "SUPPORTED",
        "reachability": "SUPPORTED",
        "impactSupport": "SUPPORTED",
        "guidanceReview": guidance(),
        "evidenceIds": ["ev-unit", "ev-solonet"],
        "rationale": "Reproduced on solonet.",
        "limitations": [],
        "nonRuntimeJustification": None,
        "impactEvidence": [evidence("IMPACT", "PROVEN", ["ev-solonet"], ["SOLONET"])],
        "impact": "CRITICAL",
        "likelihood": "HIGH",
        "ambiguousCellChoice": None,
        "pocProvided": True,
        "pocEnvironment": "solonet",
        "localFullNodeDemonstrated": True,
        "publicEntryPointDemonstrated": True,
    }
    return {**base, **over}


VALIDITY = [evidence("VALIDITY", "PROVEN", ["ev-unit"], ["UNIT"])]


def decide(
    ctx: dict[str, Any] | None = None,
    validity: list[dict[str, Any]] | None = None,
    imp: dict[str, Any] | None = None,
    *,
    policy_dict: dict[str, Any] | None = None,
) -> Decision:
    policy_dict = policy_dict or {"pocRequiredForSeverities": ["CRITICAL", "HIGH"]}
    return derive_decision(ctx or context(), VALIDITY if validity is None else validity, imp, policy=policy_dict)


def test_confirmed_happy_path(triage_policy: dict[str, Any]):
    decision = decide(imp=impact(), policy_dict=triage_policy)
    assert decision == Decision("CONFIRMED", None, "CRITICAL", [])


def test_decision_is_frozen():
    decision = decide(imp=impact())
    with pytest.raises(dataclasses.FrozenInstanceError):
        decision.decision = "REJECTED"  # type: ignore[misc]


def test_missing_impact():
    assert decide(imp=None) == Decision("INCONCLUSIVE", "UNPROVEN", None, ["missing impact decision"])


@pytest.mark.parametrize("disposition", ["KNOWN", "INTENDED", "FIXED"])
def test_context_rejections_are_echoed(disposition: str):
    decision = decide(context(disposition=disposition), imp=impact(decision="REJECTED", reason=disposition))
    assert decision == Decision("REJECTED", disposition, "CRITICAL", [])


def test_context_inconclusive_is_echoed():
    ctx = context(disposition="INCONCLUSIVE")
    assert decide(ctx, imp=impact(decision="INCONCLUSIVE", reason="UNPROVEN")) == Decision(
        "INCONCLUSIVE", "UNPROVEN", "CRITICAL", []
    )
    assert decide(ctx, imp=impact(decision="INCONCLUSIVE", reason=None)).reason == "UNPROVEN"


@pytest.mark.parametrize(
    "review",
    [impact(), impact(decision="REJECTED", reason="FALSE"), impact(decision="INCONCLUSIVE", reason="UNPROVEN")],
    ids=["confirmed", "wrong-reason", "inconclusive"],
)
def test_context_disagreement_is_inconclusive(review: dict[str, Any]):
    decision = decide(context(disposition="KNOWN"), imp=review)
    assert (decision.decision, decision.reason) == ("INCONCLUSIVE", "UNPROVEN")
    assert decision.severity == "CRITICAL"
    assert decision.blockers == ["impact decision disputes the context disposition KNOWN"]


def test_unknown_context_disposition():
    decision = decide(context(disposition="MAYBE"), imp=impact())
    assert decision.decision == "INCONCLUSIVE"
    assert decision.blockers == ["unknown context disposition 'MAYBE'"]


@pytest.mark.parametrize(
    "decision,reason",
    [("REJECTED", "FALSE"), ("REJECTED", "INFORMATIONAL"), ("INCONCLUSIVE", "UNPROVEN")],
)
def test_non_confirmed_impact_passes_through(decision: str, reason: str):
    result = decide(imp=impact(decision=decision, reason=reason, impact="LOW", likelihood="LOW"))
    assert result == Decision(decision, reason, "INFORMATIONAL", [])


def test_non_confirmed_impact_without_reason():
    assert decide(imp=impact(decision="INCONCLUSIVE", reason=None)) == Decision(
        "INCONCLUSIVE", "UNPROVEN", "CRITICAL", []
    )
    rejected = decide(imp=impact(decision="REJECTED", reason=None))
    assert (rejected.decision, rejected.reason) == ("INCONCLUSIVE", "UNPROVEN")
    assert rejected.blockers == ["impact decision REJECTED lacks a valid reason"]
    unknown = decide(imp=impact(decision="MAYBE", reason=None))
    assert unknown.blockers == ["unknown impact decision 'MAYBE'"]


def test_severity_reported_without_impact_levels():
    decision = decide(imp=impact(decision="REJECTED", reason="FALSE", impact=None, likelihood=None))
    assert decision == Decision("REJECTED", "FALSE", None, [])


def blockers_for(
    ctx: dict[str, Any] | None = None,
    validity: list[dict[str, Any]] | None = None,
    **over: Any,
) -> list[str]:
    decision = decide(ctx, validity, impact(**over))
    assert (decision.decision, decision.reason) == ("INCONCLUSIVE", "UNPROVEN")
    return decision.blockers


def test_incomplete_known_issue_search():
    ctx = context(knownIssueSearch={"status": "PARTIAL", "sources": [], "matches": []})
    assert blockers_for(ctx) == ["known-issue search coverage is incomplete"]


@pytest.mark.parametrize("field,value", [("documentationStatus", "CONTRADICTED"), ("bountyStatus", "UNKNOWN")])
def test_guidance_not_supporting(field: str, value: str):
    assert blockers_for(guidanceReview=guidance(**{field: value})) == [
        "documentation and bounty terms do not support promotion"
    ]


def test_falsified_validity_evidence():
    falsified = [*VALIDITY, evidence("VALIDITY", "FALSIFIED", ["ev-neg"], ["INTEGRATION"])]
    assert blockers_for(validity=falsified) == ["contradictory evidence must be resolved, not outvoted"]


def test_falsified_impact_evidence():
    evidence_list = [*impact()["impactEvidence"], evidence("IMPACT", "FALSIFIED", ["ev-neg"], ["SOLONET"])]
    assert blockers_for(impactEvidence=evidence_list) == ["contradictory evidence must be resolved, not outvoted"]


def test_validity_required_without_proof():
    inconclusive = [evidence("VALIDITY", "INCONCLUSIVE", [], [])]
    assert blockers_for(validity=inconclusive) == [
        "mechanism validation has not succeeded",
        "planned validity method UNIT has no PROVEN attempt",
        "impact decision cites evidence not established by the selected route",
    ]


def test_impact_required_without_proof():
    assert blockers_for(impactEvidence=[], evidenceIds=["ev-unit"]) == [
        "production reachability and impact have not been established",
        "planned impact method SOLONET has no PROVEN attempt",
    ]


def test_planned_method_unsatisfied():
    ctx = context(validityMethods=["UNIT", "DIFFERENTIAL"])
    assert blockers_for(ctx) == ["planned validity method DIFFERENTIAL has no PROVEN attempt"]


def test_reused_impact_evidence_needs_justification():
    ctx = context(impactRequired=False, impactMethods=[], existingEvidenceIds=["ev-prior"])
    reused = {"impactEvidence": [], "evidenceIds": ["ev-prior", "ev-unit"]}
    accepted = decide(ctx, imp=impact(nonRuntimeJustification="Prior solonet run.", **reused))
    assert accepted == Decision("CONFIRMED", None, "CRITICAL", [])
    assert blockers_for(ctx, nonRuntimeJustification=None, **reused) == [
        "reusing impact evidence requires existing evidence ids and a non-runtime justification"
    ]
    no_existing = context(impactRequired=False, impactMethods=[])
    assert blockers_for(no_existing, impactEvidence=[], evidenceIds=["ev-unit"], nonRuntimeJustification="x") == [
        "reusing impact evidence requires existing evidence ids and a non-runtime justification"
    ]


def test_impact_evidence_ids_must_be_established():
    assert blockers_for(evidenceIds=["ev-unit", "ev-forged"]) == [
        "impact decision cites evidence not established by the selected route"
    ]
    assert blockers_for(evidenceIds=[]) == ["impact decision cites no evidence"]


@pytest.mark.parametrize(
    "severity_over",
    [{"impact": "CRITICAL", "likelihood": "HIGH"}, {"impact": "HIGH", "likelihood": "MEDIUM"}],
)
def test_poc_required_for_high_severities(severity_over: dict[str, str]):
    expected = compute_severity(severity_over["impact"], severity_over["likelihood"])
    message = f"{expected} severity requires a working PoC on devnet or solonet"
    assert blockers_for(pocProvided=False, **severity_over) == [message]
    assert blockers_for(pocEnvironment="none", **severity_over) == [message]
    assert decide(imp=impact(pocEnvironment="devnet", **severity_over)).decision == "CONFIRMED"


def test_poc_optional_for_medium_severity():
    decision = decide(imp=impact(impact="MEDIUM", likelihood="MEDIUM", pocProvided=False, pocEnvironment="none"))
    assert decision == Decision("CONFIRMED", None, "MEDIUM", [])


def test_poc_levels_come_from_policy():
    decision = decide(
        imp=impact(impact="MEDIUM", likelihood="MEDIUM", pocProvided=False, pocEnvironment="none"),
        policy_dict={"pocRequiredForSeverities": ["CRITICAL", "HIGH", "MEDIUM"]},
    )
    assert decision.blockers == ["MEDIUM severity requires a working PoC on devnet or solonet"]


def test_ambiguous_cell_in_decision():
    unresolved = decide(imp=impact(impact="HIGH", likelihood="LOW"))
    assert unresolved.severity is None
    assert unresolved.decision == "INCONCLUSIVE"
    assert unresolved.blockers == [
        "HIGH impact with LOW likelihood is 'MEDIUM / LOW'; ambiguous_choice must be MEDIUM or LOW"
    ]
    resolved = decide(
        imp=impact(
            impact="HIGH", likelihood="LOW", ambiguousCellChoice="LOW", pocProvided=False, pocEnvironment="none"
        )
    )
    assert resolved == Decision("CONFIRMED", None, "LOW", [])


def test_confirmed_requires_impact_and_likelihood():
    assert blockers_for(impact=None, likelihood="HIGH") == ["confirmed decision lacks impact or likelihood"]
    assert blockers_for(impact="LOW", likelihood=None) == ["confirmed decision lacks impact or likelihood"]


def test_resource_exhaustion_needs_local_full_node():
    message = "resource exhaustion claims must be demonstrated against a local full node"
    statistical_ctx = context(validityMethods=["STATISTICAL"])
    statistical_validity = [evidence("VALIDITY", "PROVEN", ["ev-unit"], ["STATISTICAL"])]
    assert blockers_for(statistical_ctx, statistical_validity, localFullNodeDemonstrated=False) == [message]
    for limitation in ("Possible DoS vector via mempool spam", "denial-of-service only on Docker"):
        assert blockers_for(limitations=[limitation], localFullNodeDemonstrated=False) == [message]
    evidence_stat = [evidence("IMPACT", "PROVEN", ["ev-solonet"], ["SOLONET", "STATISTICAL"])]
    assert blockers_for(impactEvidence=evidence_stat, localFullNodeDemonstrated=False) == [message]
    demonstrated = impact(limitations=["Possible DoS vector"], localFullNodeDemonstrated=True)
    assert decide(imp=demonstrated).decision == "CONFIRMED"
    unrelated = impact(limitations=["Requires two validators"], localFullNodeDemonstrated=False)
    assert decide(imp=unrelated).decision == "CONFIRMED"


def test_blockers_accumulate():
    ctx = context(knownIssueSearch={"status": "UNAVAILABLE", "sources": [], "matches": []})
    falsified = [*VALIDITY, evidence("VALIDITY", "FALSIFIED", ["ev-neg"], ["UNIT"])]
    decision = decide(ctx, falsified, impact(pocProvided=False))
    assert decision.decision == "INCONCLUSIVE"
    assert decision.severity == "CRITICAL"
    assert decision.blockers == [
        "known-issue search coverage is incomplete",
        "contradictory evidence must be resolved, not outvoted",
        "CRITICAL severity requires a working PoC on devnet or solonet",
    ]


def test_malformed_impact_is_inconclusive_not_an_error():
    decision = decide(imp={"decision": "CONFIRMED"})
    assert (decision.decision, decision.reason, decision.severity) == ("INCONCLUSIVE", "UNPROVEN", None)
    assert "impact decision cites no evidence" in decision.blockers
    assert "confirmed decision lacks impact or likelihood" in decision.blockers


def test_policy_dict_requires_poc_levels():
    with pytest.raises(KeyError, match="pocRequiredForSeverities"):
        derive_decision(context(), VALIDITY, impact(), policy={})


def test_module_constants():
    assert policy.DECISIONS == ("CONFIRMED", "REJECTED", "INCONCLUSIVE")
    assert policy.REASONS == ("KNOWN", "INTENDED", "FIXED", "INFORMATIONAL", "FALSE", "UNPROVEN")
