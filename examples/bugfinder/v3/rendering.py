"""Deterministic Markdown renderers for the v3 threat model and history catalog.

Rendering is a pure function of the collector-produced dict: the same model
always yields byte-identical Markdown, sections come in a fixed order and every
entity list is sorted by its key.
"""

from __future__ import annotations

import json
from typing import Any, Iterable, Sequence


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        return "; ".join(_text(item) for item in value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _cell(value: Any) -> str:
    return _text(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ").strip() or "-"


def _table(headers: Sequence[str], rows: Iterable[Sequence[Any]]) -> list[str]:
    materialized = [[_cell(cell) for cell in row] for row in rows]
    if not materialized:
        return ["_(none)_"]
    return [
        "| " + " | ".join(headers) + " |",
        "|" + "|".join(" --- " for _ in headers) + "|",
        *("| " + " | ".join(row) + " |" for row in materialized),
    ]


def _bullets(items: Iterable[Any]) -> list[str]:
    lines = [f"- {_cell(item)}" for item in items]
    return lines or ["- (none)"]


def _field(label: str, value: Any) -> str:
    return f"- {label}: {_cell(value)}"


def _sorted(entities: Iterable[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    return sorted(entities, key=lambda entity: str(entity.get(key, "")))


def _header(title: str, model: dict[str, Any], source_label: str, source_ids: Iterable[str]) -> list[str]:
    return [
        f"# {title} {model.get('modelId', 'unknown')}",
        "",
        _field("Model", model.get("modelId")),
        _field("Revision", model.get("revision")),
        _field("Target", model.get("targetId") or "unknown"),
        _field("Source commit", model.get("sourceCommit") or "unknown"),
        _field(source_label, sorted(source_ids)),
        "",
    ]


def render_threat_model_markdown(model: dict[str, Any]) -> str:
    """Render a canonical threat model (collect_threat_model output) as Markdown."""

    lines = _header(
        "Threat model",
        model,
        "Source models",
        (source.get("attemptId", "") for source in model.get("sourceModels", [])),
    )
    lines += ["## Summary", "", _text(model.get("summary")) or "_(none)_", "", f"Scope: {_text(model.get('scope')) or '-'}", ""]
    lines += ["### Assumptions", "", *_bullets(model.get("assumptions", [])), ""]
    lines += ["### Exclusions", "", *_bullets(model.get("exclusions", [])), ""]

    lines += ["## Actors", ""]
    lines += _table(
        ["Key", "Name", "Role", "Capabilities", "Controlled inputs", "Excluded powers", "Sources"],
        (
            [a.get("key"), a.get("name"), a.get("role"), a.get("capabilities"), a.get("controlledInputs"), a.get("excludedPowers"), a.get("sourceRefs")]
            for a in _sorted(model.get("actors", []), "key")
        ),
    )
    lines += ["", "## Assets", ""]
    lines += _table(
        ["Key", "Name", "Protected resource", "Security properties", "Compromise consequences", "Sources"],
        (
            [a.get("key"), a.get("name"), a.get("protectedResource"), a.get("securityProperties"), a.get("compromiseConsequences"), a.get("sourceRefs")]
            for a in _sorted(model.get("assets", []), "key")
        ),
    )
    lines += ["", "## Trust boundaries", ""]
    lines += _table(
        ["Key", "Name", "Sides", "Entry points", "Enforced checks", "Sources"],
        (
            [b.get("key"), b.get("name"), b.get("sides"), b.get("entryPoints"), b.get("enforcedChecks"), b.get("sourceRefs")]
            for b in _sorted(model.get("trustBoundaries", []), "key")
        ),
    )

    lines += ["", "## Threats", ""]
    threats = _sorted(model.get("threats", []), "key")
    if not threats:
        lines.append("_(none)_")
    for threat in threats:
        lines += [
            f"### {_cell(threat.get('key'))}: {_cell(threat.get('title'))}",
            "",
            _field("Violation", threat.get("violation")),
            _field("Security property", threat.get("securityProperty")),
            _field("Attack surface", threat.get("attackSurface")),
            _field("Preconditions", threat.get("preconditions")),
            _field("Expected impact", threat.get("expectedImpact")),
            _field("Existing controls", threat.get("existingControls")),
            _field("Confidence", threat.get("confidence")),
            _field("Open questions", threat.get("openQuestions")),
            _field("Actors", threat.get("actorKeys")),
            _field("Assets", threat.get("assetKeys")),
            _field("Boundaries", threat.get("boundaryKeys")),
            _field("Sources", threat.get("sourceRefs")),
            "",
        ]

    lines += ["## Mappings", ""]
    mappings = sorted(
        model.get("entityMappings", []),
        key=lambda m: (str(m.get("sourceAttemptId", "")), str(m.get("entityType", "")), str(m.get("sourceKey", "")), str(m.get("canonicalKey", ""))),
    )
    lines += _table(
        ["Source attempt", "Type", "Source key", "Canonical key", "Disposition", "Rationale"],
        ([m.get("sourceAttemptId"), m.get("entityType"), m.get("sourceKey"), m.get("canonicalKey"), m.get("disposition"), m.get("rationale")] for m in mappings),
    )
    lines += ["", "## Disagreements", "", *_bullets(model.get("disagreements", []))]
    return "\n".join(lines) + "\n"


def render_history_markdown(catalog: dict[str, Any]) -> str:
    """Render a frozen historical risk catalog (collect_history_model output) as Markdown."""

    items = _sorted(catalog.get("items", []), "threatId")
    lines = _header("Historical risk catalog", catalog, "Source attempts", catalog.get("sourceAttemptIds", []))
    lines += [
        "## Summary",
        "",
        f"{len(items)} historical threats from {len(catalog.get('sourceAttemptIds', []))} source attempts.",
        "",
        "## Historical threats",
        "",
    ]
    if not items:
        lines.append("_(none)_")
    for item in items:
        lines += [
            f"### {_cell(item.get('threatId'))}",
            "",
            _field("Statement", item.get("statement")),
            _field("Attack surface", item.get("attackSurface")),
            _field("Attacker capability", item.get("attackerCapability")),
            _field("Protected asset", item.get("protectedAsset")),
            _field("Security impact", item.get("securityImpact")),
            _field("Excluded preconditions", item.get("excludedPreconditions")),
            _field("Source issues", item.get("sourceIssueRefs")),
            _field("Known findings", item.get("knownFindingRefs")),
            _field("Confidence", item.get("confidence")),
            "",
        ]
    lines += ["## Mappings", ""]
    mappings = sorted(
        catalog.get("mappings", []),
        key=lambda m: (str(m.get("sourceAttemptId", "")), str(m.get("sourceKey", "")), str(m.get("threatId", ""))),
    )
    lines += _table(
        ["Source attempt", "Source key", "Threat", "Disposition"],
        ([m.get("sourceAttemptId"), m.get("sourceKey"), m.get("threatId"), m.get("disposition")] for m in mappings),
    )
    return "\n".join(lines) + "\n"
