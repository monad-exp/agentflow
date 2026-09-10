"""Prompt assembly for bugfinder v3 agent nodes (DESIGN.md section 9).

Every agent prompt is plain text: the phase prompt from ``prompts/<phase>.md``,
the JSON Schema the agent must satisfy, the response rules, and for triage and
report phases the vendored bounty guidance plus the ``triagePolicy`` JSON. The
assembled text is rendered by AgentFlow's StrictUndefined Jinja environment, so
it may contain no Jinja syntax except the single orchestrator-produced value
``{{ nodes.snapshot.data.sourceCommit }}`` that this module adds itself.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

from examples.bugfinder.v3.policy import severity_guidance_text

if TYPE_CHECKING:
    from examples.bugfinder.v3.config import BudgetProfile, Target, V3Config

V3_DIR = Path(__file__).resolve().parent
PROMPTS_DIR = V3_DIR / "prompts"
TEMPLATES_DIR = V3_DIR / "templates"
BOUNTY_POLICY_PATH = V3_DIR / "policy" / "monad-bounty.md"

PHASES: tuple[str, ...] = (
    "rank",
    "file-hunt",
    "goal-common",
    "threat",
    "threat-synthesis",
    "historical-risk-classes",
    "historical-synthesis",
    "goal-plan",
    "deduplicate",
    "triager-1-context",
    "triager-2-validity",
    "triager-3-impact",
    "report",
)
TEMPLATES: tuple[str, ...] = ("goal-threat-model", "goal-historical", "goal-roam")

HUNT_PHASES = frozenset({"file-hunt", "goal-common"})
TRIAGE_PHASES = frozenset({"triager-1-context", "triager-2-validity", "triager-3-impact"})
POLICY_PHASES = TRIAGE_PHASES | {"report"}
SOURCE_COMMIT_PHASES = TRIAGE_PHASES | {"report"}

SOURCE_COMMIT_EXPRESSION = "{{ nodes.snapshot.data.sourceCommit }}"
SEARCH_TIMEOUT_PLACEHOLDER = "{{SEARCH_TIMEOUT_MS}}"
FINALIZATION_GRACE_PLACEHOLDER = "{{FINALIZATION_GRACE_MS}}"
HARD_TIMEOUT_PLACEHOLDER = "{{HARD_TIMEOUT_MS}}"
TIMEOUT_PLACEHOLDERS = (SEARCH_TIMEOUT_PLACEHOLDER, FINALIZATION_GRACE_PLACEHOLDER, HARD_TIMEOUT_PLACEHOLDER)
FINALIZATION_GRACE_MS = 5 * 60 * 1000

PHASE_TIMEOUT_FIELDS: dict[str, str] = {
    "rank": "rankMin",
    "file-hunt": "huntMin",
    "goal-common": "huntMin",
    "threat": "contextWorkerMin",
    "historical-risk-classes": "contextWorkerMin",
    "threat-synthesis": "synthesisMin",
    "historical-synthesis": "synthesisMin",
    "goal-plan": "goalPlanMin",
    "deduplicate": "dedupMin",
    "triager-1-context": "gate1Min",
    "triager-2-validity": "gate2Min",
    "triager-3-impact": "gate3Min",
    "report": "reportMin",
}

_JINJA_MARKERS = ("{{", "{%", "{#")
# Goal-template placeholders are substituted by ``collectors.plan_goal_hunts`` with
# ``str.replace``; the same regex lints the templates so renderer and lint never
# disagree about what a placeholder is (no inner whitespace: Jinja would match it too).
TEMPLATE_PLACEHOLDER = re.compile(r"\{\{([A-Z][A-Z0-9_]*)\}\}")

RESPONSE_RULES = """\
## Response rules

- Return exactly one JSON object as your final response. It must validate
  against the schema in the Required output section.
- No prose before or after the object, no Markdown fences, no comments.
- The "AgentFlow structured input (JSON)" block appended below this prompt is
  your assignment; read it before you start. When no such block is appended,
  a "Structured input" section names the trusted collector files to read instead.
- There is no database and there are no tools for recording results. Your
  final JSON response is the only durable output of this task."""


def prompt_path(phase: str) -> Path:
    """Return the prompt file for ``phase`` (a member of ``PHASES``)."""

    if phase not in PHASES:
        raise ValueError(f"unknown bugfinder v3 phase {phase!r}; expected one of {', '.join(PHASES)}")
    return PROMPTS_DIR / f"{phase}.md"


def template_path(name: str) -> Path:
    """Return the goal overlay template for ``name`` (a member of ``TEMPLATES``)."""

    if name not in TEMPLATES:
        raise ValueError(f"unknown bugfinder v3 template {name!r}; expected one of {', '.join(TEMPLATES)}")
    return TEMPLATES_DIR / f"{name}.md"


def template_placeholders(name: str) -> tuple[str, ...]:
    """Distinct ``{{UPPER_CASE}}`` placeholders of a template, in order of first use."""

    text = template_path(name).read_text(encoding="utf-8")
    return tuple(dict.fromkeys(TEMPLATE_PLACEHOLDER.findall(text)))


def find_forbidden_jinja(text: str, *, allowed: tuple[str, ...] = ()) -> list[str]:
    """Return the lines of ``text`` that contain Jinja syntax other than ``allowed`` literals."""

    scrubbed = text
    for literal in allowed:
        scrubbed = scrubbed.replace(literal, "")
    return [line for line in scrubbed.splitlines() if any(marker in line for marker in _JINJA_MARKERS)]


def phase_timeout_minutes(phase: str, budget: BudgetProfile) -> int:
    """The budget timeout (minutes) that applies to ``phase``."""

    field = PHASE_TIMEOUT_FIELDS.get(phase)
    if field is None:
        raise ValueError(f"unknown bugfinder v3 phase {phase!r}")
    return int(getattr(budget.timeouts, field))


def hunt_timeouts_ms(hard_minutes: int) -> dict[str, int]:
    """Hunt windows in milliseconds: search = hard - grace, grace fixed at five minutes."""

    hard = int(hard_minutes) * 60 * 1000
    if hard <= FINALIZATION_GRACE_MS:
        raise ValueError(f"hunt timeout of {hard_minutes} min leaves no search window after a 5 min grace")
    return {"search": hard - FINALIZATION_GRACE_MS, "grace": FINALIZATION_GRACE_MS, "hard": hard}


def _target_section(phase: str, target: Target, source_ref: str) -> str:
    lines = [
        "## Target",
        "",
        f"- Repository URL: {target.repositoryUrl}",
        f"- Source ref: {source_ref}",
    ]
    if phase in SOURCE_COMMIT_PHASES:
        lines.append(f"- Source commit: {SOURCE_COMMIT_EXPRESSION}")
    return "\n".join(lines)


def _required_output_section(schema: dict[str, Any]) -> str:
    return (
        "## Required output\n\n"
        "Your final response must be one JSON object that validates against this\n"
        "JSON Schema (Draft 2020-12):\n\n"
        "```json\n" + json.dumps(schema, indent=2) + "\n```"
    )


def _bounty_policy_section(config: V3Config) -> str:
    guidance = severity_guidance_text(BOUNTY_POLICY_PATH.read_text(encoding="utf-8"))
    policy_json = json.dumps(config.triagePolicy.model_dump(mode="json"), indent=2)
    return (
        "## Bounty policy\n\n"
        "The following sections are quoted verbatim from the vendored Monad bounty\n"
        "terms (`policy/monad-bounty.md`, revision pinned in `config.yaml`). Apply\n"
        "them when judging proof requirements, impact and likelihood; a pinned copy\n"
        "is not necessarily current.\n\n"
        f"{guidance}\n\n"
        "### Triage policy\n\n"
        "```json\n" + policy_json + "\n```"
    )


def _extra_sections(extra: dict[str, str] | None) -> list[str]:
    sections: list[str] = []
    for heading, text in (extra or {}).items():
        if not isinstance(heading, str) or not heading.strip():
            raise ValueError("extra section headings must be non-empty strings")
        if not isinstance(text, str):
            raise TypeError(f"extra section {heading!r} must be a string")
        sections.append(f"## {heading.strip()}\n\n{text.strip()}")
    return sections


def build_prompt(
    phase: str,
    *,
    config: V3Config,
    budget: BudgetProfile,
    target: Target,
    schema: dict[str, Any],
    extra: dict[str, str] | None = None,
    source_ref: str | None = None,
) -> str:
    """Assemble the full prompt text for an agent node of ``phase``.

    ``source_ref`` is the ref the run pinned (the sha ``run.py`` resolved) and
    defaults to ``target.sourceRef``. ``extra`` adds trailing ``## <heading>``
    sections of static text (for example the evidence environment). The result
    contains no Jinja syntax except ``SOURCE_COMMIT_EXPRESSION`` on triage and
    report phases; a ``ValueError`` is raised otherwise so no agent-derived text
    can reach the renderer.
    """

    body = prompt_path(phase).read_text(encoding="utf-8").strip()
    if phase in HUNT_PHASES:
        windows = hunt_timeouts_ms(phase_timeout_minutes(phase, budget))
        body = (
            body.replace(SEARCH_TIMEOUT_PLACEHOLDER, str(windows["search"]))
            .replace(FINALIZATION_GRACE_PLACEHOLDER, str(windows["grace"]))
            .replace(HARD_TIMEOUT_PLACEHOLDER, str(windows["hard"]))
        )
    sections = [body, _target_section(phase, target, source_ref or target.sourceRef), _required_output_section(schema), RESPONSE_RULES]
    if phase in POLICY_PHASES:
        sections.append(_bounty_policy_section(config))
    sections.extend(_extra_sections(extra))
    prompt = "\n\n".join(sections)
    offending = find_forbidden_jinja(prompt, allowed=(SOURCE_COMMIT_EXPRESSION,))
    if offending:
        raise ValueError(f"assembled {phase} prompt contains forbidden Jinja syntax: {offending[:3]}")
    return prompt
