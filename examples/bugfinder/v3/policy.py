"""Bounty policy as pure functions: severity matrix, PoC rules, decision derivation.

Encodes ``policy/monad-bounty.md`` (pinned in ``config.yaml``) and ports the
Smithers ``reportDisposition`` onto the three-outcome model
(CONFIRMED | REJECTED | INCONCLUSIVE plus a closed ``reason`` enum).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

IMPACT_LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
LIKELIHOOD_LEVELS = ("HIGH", "MEDIUM", "LOW")
SEVERITY_LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")

DECISIONS = ("CONFIRMED", "REJECTED", "INCONCLUSIVE")
REASONS = ("KNOWN", "INTENDED", "FIXED", "INFORMATIONAL", "FALSE", "UNPROVEN")
POC_ENVIRONMENTS = ("devnet", "solonet")

AMBIGUOUS_CELL = ("HIGH", "LOW")
AMBIGUOUS_CHOICES = ("MEDIUM", "LOW")

# (impact, likelihood) -> severity; the ambiguous "MEDIUM / LOW" cell is absent.
_MATRIX: dict[tuple[str, str], str] = {
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

# Context dispositions that gate 3 must echo, mapped onto (decision, reason).
_ECHOED_CONTEXT = {
    "KNOWN": ("REJECTED", "KNOWN"),
    "INTENDED": ("REJECTED", "INTENDED"),
    "FIXED": ("REJECTED", "FIXED"),
    "INCONCLUSIVE": ("INCONCLUSIVE", None),
}

_RESOURCE_EXHAUSTION = re.compile(
    r"\b(?:d?dos|denial[- ]of[- ]service|resource exhaustion|out[- ]of[- ]memory)\b",
    re.IGNORECASE,
)

_GUIDANCE_SECTIONS = (
    "Proof of Concept (PoC) Requirements",
    "Severity and Rewards",
    "Issue Severity Extended Guidance",
)


@dataclass(frozen=True)
class Decision:
    decision: str
    reason: str | None
    severity: str | None
    blockers: list[str] = field(default_factory=list)


def compute_severity(impact: str, likelihood: str, ambiguous_choice: str | None = None) -> str:
    """Look up the gist matrix.

    ``ambiguous_choice`` resolves the HIGH impact x LOW likelihood cell
    ("MEDIUM / LOW") and is ignored for every other cell.
    """
    if impact not in IMPACT_LEVELS:
        raise ValueError(f"unknown impact {impact!r}; expected one of {IMPACT_LEVELS}")
    if likelihood not in LIKELIHOOD_LEVELS:
        raise ValueError(f"unknown likelihood {likelihood!r}; expected one of {LIKELIHOOD_LEVELS}")
    if (impact, likelihood) == AMBIGUOUS_CELL:
        if ambiguous_choice not in AMBIGUOUS_CHOICES:
            raise ValueError(
                "HIGH impact with LOW likelihood is 'MEDIUM / LOW'; ambiguous_choice must be MEDIUM or LOW"
            )
        return ambiguous_choice
    return _MATRIX[(impact, likelihood)]


def poc_required(severity: str, policy_levels: tuple[str, ...]) -> bool:
    if severity not in SEVERITY_LEVELS:
        raise ValueError(f"unknown severity {severity!r}; expected one of {SEVERITY_LEVELS}")
    return severity in policy_levels


def derive_decision(
    context: dict,
    validity: list[dict],
    impact: dict | None,
    *,
    policy: dict,
) -> Decision:
    """Derive the trusted disposition for one finding.

    ``context`` is the gate 1 output, ``validity`` the gate 2 outputs and ``impact``
    the gate 3 output (``None`` when the member produced nothing). ``policy`` is the
    ``triagePolicy`` block of the config. Severity is reported whenever gate 3
    recorded impact and likelihood, whatever the decision. ``blockers`` list the
    CONFIRMED-path checks that failed; a decision echoed from the context gate or
    passed through from gate 3 carries its ``reason`` instead and has no blockers
    unless the inputs themselves were inconsistent.
    """
    poc_levels = tuple(policy["pocRequiredForSeverities"])
    if impact is None:
        return Decision("INCONCLUSIVE", "UNPROVEN", None, ["missing impact decision"])

    severity, blockers = _severity_of(impact)
    disposition = context.get("disposition")
    if disposition != "REVIEW":
        return _echo_context(disposition, impact, severity, blockers)

    decision = impact.get("decision")
    if decision != "CONFIRMED":
        return _pass_through(decision, impact.get("reason"), severity, blockers)

    proven_validity = [a for a in validity if a.get("state") == "PROVEN"]
    impact_evidence = _list(impact, "impactEvidence")
    proven_impact = [a for a in impact_evidence if a.get("state") == "PROVEN"]
    guidance = impact.get("guidanceReview") or {}
    known = context.get("knownIssueSearch") or {}
    validity_required = bool(context.get("validityRequired"))
    impact_required = bool(context.get("impactRequired"))
    existing_ids = _list(context, "existingEvidenceIds")

    if known.get("status") != "COMPLETE":
        blockers.append("known-issue search coverage is incomplete")
    docs_ok = guidance.get("documentationStatus") == "SUPPORTED"
    bounty_ok = guidance.get("bountyStatus") == "IN_SCOPE"
    if not (docs_ok and bounty_ok):
        blockers.append("documentation and bounty terms do not support promotion")
    if any(a.get("state") == "FALSIFIED" for a in [*validity, *impact_evidence]):
        blockers.append("contradictory evidence must be resolved, not outvoted")
    if validity_required and not proven_validity:
        blockers.append("mechanism validation has not succeeded")
    if impact_required and not proven_impact:
        blockers.append("production reachability and impact have not been established")
    for stage, required, attempts in (
        ("validity", validity_required, proven_validity),
        ("impact", impact_required, proven_impact),
    ):
        if not required:
            continue
        for method in _list(context, f"{stage}Methods"):
            if not any(method in _list(a, "methods") for a in attempts):
                blockers.append(f"planned {stage} method {method} has no PROVEN attempt")
    if not impact_required and (not existing_ids or not impact.get("nonRuntimeJustification")):
        blockers.append("reusing impact evidence requires existing evidence ids and a non-runtime justification")

    established = set(existing_ids)
    for attempt in [*proven_validity, *proven_impact]:
        established.update(_list(attempt, "evidenceIds"))
    cited = _list(impact, "evidenceIds")
    if not cited:
        blockers.append("impact decision cites no evidence")
    elif any(evidence_id not in established for evidence_id in cited):
        blockers.append("impact decision cites evidence not established by the selected route")

    if severity is None:
        if impact.get("impact") is None or impact.get("likelihood") is None:
            blockers.append("confirmed decision lacks impact or likelihood")
    elif poc_required(severity, poc_levels) and not _poc_provided(impact):
        blockers.append(f"{severity} severity requires a working PoC on devnet or solonet")

    if _claims_resource_exhaustion(context, validity, impact) and not impact.get("localFullNodeDemonstrated"):
        blockers.append("resource exhaustion claims must be demonstrated against a local full node")

    if blockers:
        return Decision("INCONCLUSIVE", "UNPROVEN", severity, blockers)
    return Decision("CONFIRMED", None, severity, [])


def severity_guidance_text(policy_md: str) -> str:
    """Return the PoC and severity sections of the vendored bounty policy."""
    sections = _sections(policy_md)
    missing = [title for title in _GUIDANCE_SECTIONS if title not in sections]
    if missing:
        raise ValueError(f"bounty policy is missing sections: {missing}")
    return "\n\n".join(f"## {title}\n\n{sections[title]}" for title in _GUIDANCE_SECTIONS)


def _severity_of(impact: dict) -> tuple[str | None, list[str]]:
    level, likelihood = impact.get("impact"), impact.get("likelihood")
    if level is None or likelihood is None:
        return None, []
    try:
        return compute_severity(level, likelihood, impact.get("ambiguousCellChoice")), []
    except ValueError as exc:
        return None, [str(exc)]


def _echo_context(disposition: Any, impact: dict, severity: str | None, blockers: list[str]) -> Decision:
    expected = _ECHOED_CONTEXT.get(disposition)
    if expected is None:
        return Decision(
            "INCONCLUSIVE", "UNPROVEN", severity, [*blockers, f"unknown context disposition {disposition!r}"]
        )
    decision, reason = expected
    actual_reason = impact.get("reason")
    agrees = impact.get("decision") == decision and (reason is None or actual_reason == reason)
    if not agrees:
        return Decision(
            "INCONCLUSIVE",
            "UNPROVEN",
            severity,
            [*blockers, f"impact decision disputes the context disposition {disposition}"],
        )
    if reason is None:
        reason = actual_reason if actual_reason in REASONS else "UNPROVEN"
    return Decision(decision, reason, severity, blockers)


def _pass_through(decision: Any, reason: Any, severity: str | None, blockers: list[str]) -> Decision:
    if decision not in DECISIONS:
        blockers = [*blockers, f"unknown impact decision {decision!r}"]
    elif reason in REASONS:
        return Decision(decision, reason, severity, blockers)
    elif decision != "INCONCLUSIVE":
        blockers = [*blockers, f"impact decision {decision} lacks a valid reason"]
    return Decision("INCONCLUSIVE", "UNPROVEN", severity, blockers)


def _poc_provided(impact: dict) -> bool:
    return bool(impact.get("pocProvided")) and impact.get("pocEnvironment") in POC_ENVIRONMENTS


def _claims_resource_exhaustion(context: dict, validity: list[dict], impact: dict) -> bool:
    methods = set(_list(context, "validityMethods")) | set(_list(context, "impactMethods"))
    for attempt in [*validity, *_list(impact, "impactEvidence")]:
        methods.update(_list(attempt, "methods"))
    if "STATISTICAL" in methods:
        return True
    return any(_RESOURCE_EXHAUSTION.search(str(text)) for text in _list(impact, "limitations"))


def _list(source: dict, key: str) -> list:
    value = source.get(key)
    return list(value) if isinstance(value, (list, tuple)) else []


def _sections(markdown: str) -> dict[str, str]:
    sections: dict[str, str] = {}
    for chunk in re.split(r"^## ", markdown, flags=re.MULTILINE)[1:]:
        title, _, body = chunk.partition("\n")
        sections[title.strip()] = body.strip()
    return sections
