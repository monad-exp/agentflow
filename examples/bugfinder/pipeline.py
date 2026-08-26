"""Single-commit, DB-backed bug-finding workflow from issue #1."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any, Callable

from agentflow import Graph, claude, codex, fanout_from, pi


HERE = Path(__file__).resolve().parent
REPOSITORY = Path(os.environ["BUGFINDER_REPO_PATH"]).expanduser().resolve()
INPUT_REF = os.environ.get("BUGFINDER_INPUT_REF", os.environ.get("BUGFINDER_SOURCE_REF", "HEAD"))
BUGDB_PORT = int(os.environ.get("BUGDB_PORT", "4312"))


def git(*args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(REPOSITORY), *args],
        text=True,
    ).strip()


COMMIT_SHA = git("rev-parse", f"{INPUT_REF}^{{commit}}").lower()
if len(COMMIT_SHA) not in {40, 64} or any(char not in "0123456789abcdef" for char in COMMIT_SHA):
    raise ValueError("BUGFINDER_INPUT_REF must resolve to a full 40- or 64-character commit SHA")
if git("rev-parse", "HEAD").lower() != COMMIT_SHA:
    raise ValueError(f"BUGFINDER_REPO_PATH must be checked out at resolved commit {COMMIT_SHA}")
dirty_paths = git("status", "--porcelain", "--untracked-files=normal")
if dirty_paths:
    raise ValueError("BUGFINDER_REPO_PATH must be a clean worktree pinned to the resolved commit")
REPOSITORY_URL = os.environ.get("BUGFINDER_REPOSITORY_URL")
if not REPOSITORY_URL:
    REPOSITORY_URL = git("config", "--get", "remote.origin.url")

history_file = os.environ.get("BUGFINDER_HISTORY_FILE")
HISTORICAL_CONTEXT = (
    Path(history_file).expanduser().read_text(encoding="utf-8")
    if history_file
    else "No external historical bug corpus was supplied for this run."
)


def prompt(name: str) -> str:
    text = (HERE / "prompts" / f"{name}.md").read_text(encoding="utf-8")
    return (
        text.replace("{commit_sha}", COMMIT_SHA)
        .replace("{repository_url}", REPOSITORY_URL)
        .replace("{historical_context}", HISTORICAL_CONTEXT)
    )


def role_agent(role: str, **kwargs: Any):
    """Choose Codex, Claude Code, or Pi/OpenRouter independently per role."""

    selected = os.environ.get(
        f"BUGFINDER_{role.upper()}_AGENT",
        os.environ.get("BUGFINDER_AGENT", "codex"),
    ).lower()
    builders: dict[str, Callable[..., Any]] = {"codex": codex, "claude": claude, "pi": pi}
    if selected not in builders:
        raise ValueError(f"unsupported {role} agent {selected!r}; choose codex, claude, or pi")
    kwargs.setdefault("connectors", ["bugdb"])
    kwargs.setdefault("concurrency_pool", f"{selected}-provider")
    kwargs.setdefault("durable_goal", {"mode": os.environ.get("BUGFINDER_GOAL_MODE", "supervised")})
    kwargs.setdefault("retries", int(os.environ.get("BUGFINDER_RETRIES", "1")))
    kwargs.setdefault("retry_backoff_seconds", 2)
    kwargs.setdefault("timeout_seconds", int(os.environ.get("BUGFINDER_NODE_TIMEOUT", "1800")))
    if selected == "codex":
        kwargs["model"] = os.environ.get("BUGFINDER_CODEX_MODEL", "gpt-5.6-luna")
    elif selected == "claude" and os.environ.get("BUGFINDER_CLAUDE_MODEL"):
        kwargs["model"] = os.environ["BUGFINDER_CLAUDE_MODEL"]
    elif selected == "pi":
        kwargs["model"] = os.environ.get(
            "BUGFINDER_PI_MODEL",
            "openrouter/anthropic/claude-sonnet-4.6",
        )
        kwargs["provider"] = {
            "name": "openrouter",
            "base_url": "https://openrouter.ai/api/v1",
            "api_key_env": "OPENROUTER_API_KEY",
            "wire_api": "openai-completions",
        }
    return builders[selected](**kwargs)


def requires_tool(name: str) -> list[dict[str, str]]:
    return [{"kind": "connector_tool_called", "connector": "bugdb", "tool": name}]


HUNT_ITEM = {
    "type": "object",
    "additionalProperties": False,
    "required": ["callerKey", "kind", "objective", "paths"],
    "properties": {
        "callerKey": {"type": "string", "minLength": 1, "maxLength": 256},
        "kind": {"enum": ["FILE", "THREAT_MODEL", "ROAM"]},
        "objective": {"type": "string", "minLength": 1},
        "paths": {"type": "array", "items": {"type": "string", "minLength": 1}},
    },
}
LEAD_INPUT = {
    "type": "object",
    "additionalProperties": False,
    "required": ["callerKey", "claim", "locations", "evidence"],
    "properties": {
        "callerKey": {"type": "string", "minLength": 1, "maxLength": 256},
        "claim": {"type": "string", "minLength": 1},
        "locations": {
            "type": "array",
            "minItems": 1,
            "items": {"type": "string", "minLength": 1},
        },
        "evidence": {"type": "string", "minLength": 1},
        "attackerPreconditions": {"type": "string", "minLength": 1},
        "impact": {"type": "string", "minLength": 1},
        "validationPlan": {"type": "string", "minLength": 1},
    },
}
FINDING_ITEM = {
    "type": "object",
    "additionalProperties": False,
    "required": ["callerKey", "title", "rootCause", "impact", "leadIds"],
    "properties": {
        "callerKey": {"type": "string", "minLength": 1, "maxLength": 256},
        "title": {"type": "string", "minLength": 1},
        "rootCause": {"type": "string", "minLength": 1},
        "impact": {"type": "string", "minLength": 1},
        "leadIds": {
            "type": "array",
            "minItems": 1,
            "items": {"type": "string", "minLength": 1},
        },
    },
}
REVIEW_INPUT = {
    "type": "object",
    "additionalProperties": False,
    "required": ["verdict", "assessment"],
    "properties": {
        "verdict": {"enum": ["CONFIRMED", "REJECTED", "INCONCLUSIVE"]},
        "assessment": {"type": "string", "minLength": 1},
    },
}

CONNECTOR_TOOLS = [
    {
        "name": "add_hunts",
        "description": "Insert selected Hunts into the injected run using stable caller keys.",
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["hunts"],
            "properties": {"hunts": {"type": "array", "items": HUNT_ITEM}},
        },
    },
    {"name": "get_hunt", "description": "Read the injected Hunt and Leads.", "input_schema": {"type": "object", "additionalProperties": False}},
    {"name": "add_lead", "description": "Append one immutable Lead to the injected Hunt.", "input_schema": LEAD_INPUT},
    {
        "name": "finish_hunt",
        "description": "Set the injected Hunt result exactly once.",
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["result", "resultSummary"],
            "properties": {
                "result": {"enum": ["BUG_FOUND", "EXHAUSTED", "BLOCKED"]},
                "resultSummary": {"type": "string", "minLength": 1},
            },
        },
    },
    {"name": "list_hunts_and_leads", "description": "Read all Hunts and Leads in the injected run.", "input_schema": {"type": "object", "additionalProperties": False}},
    {
        "name": "create_findings",
        "description": "Create Findings and assign same-run Leads transactionally.",
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["findings"],
            "properties": {"findings": {"type": "array", "items": FINDING_ITEM}},
        },
    },
    {"name": "get_finding", "description": "Read the injected Finding and its complete Lead provenance.", "input_schema": {"type": "object", "additionalProperties": False}},
    {"name": "set_triage", "description": "Set triage once on the injected Finding.", "input_schema": REVIEW_INPUT},
    {"name": "set_rereview", "description": "Set independent re-review once on the injected Finding.", "input_schema": REVIEW_INPUT},
]

with Graph(
    "bugfinder",
    description="Single-commit Mythos-style and threat-model-driven bug finding",
    working_dir=str(REPOSITORY),
    source_snapshot={
        "repositoryUrl": REPOSITORY_URL,
        "inputRef": INPUT_REF,
        "commitSha": COMMIT_SHA,
    },
    concurrency=int(os.environ.get("BUGFINDER_CONCURRENCY", "24")),
    fail_fast=False,
    concurrency_pools={
        "codex-provider": int(os.environ.get("BUGFINDER_CODEX_CONCURRENCY", "12")),
        "claude-provider": int(os.environ.get("BUGFINDER_CLAUDE_CONCURRENCY", "8")),
        "pi-provider": int(os.environ.get("BUGFINDER_PI_CONCURRENCY", "12")),
    },
    connectors=[
        {
            "name": "bugdb",
            "url": f"http://127.0.0.1:{BUGDB_PORT}/mcp",
            "control_url": f"http://127.0.0.1:{BUGDB_PORT}/orchestration",
            "command": "npm",
            "args": ["run", "connector"],
            "cwd": str(HERE),
            "env": {"BUGDB_PORT": str(BUGDB_PORT)},
            "env_from": {"DATABASE_URL": "DATABASE_URL"},
            "tools": CONNECTOR_TOOLS,
        }
    ],
) as graph:
    rank_files = role_agent(
        "rank", task_id="rank_files", prompt=prompt("rank"), success_criteria=requires_tool("add_hunts")
    )
    threat_model = role_agent(
        "threat", task_id="threat_model", prompt=prompt("threat"), success_criteria=requires_tool("add_hunts")
    )
    roam_plan = role_agent(
        "roam", task_id="roam_plan", prompt=prompt("roam"), success_criteria=requires_tool("add_hunts")
    )

    hunt = fanout_from(
        role_agent(
            "hunt", task_id="hunt", prompt=prompt("hunt"), success_criteria=requires_tool("finish_hunt")
        ),
        rank_files,
        connector="bugdb",
        resource="hunts",
        as_="hunt",
        max_items=500,
    )
    threat_model >> hunt
    roam_plan >> hunt

    deduplicate = role_agent(
        "deduplicate",
        task_id="deduplicate",
        prompt=prompt("deduplicate"),
        success_criteria=requires_tool("create_findings"),
    )
    hunt >> deduplicate

    triage = fanout_from(
        role_agent(
            "triage", task_id="triage", prompt=prompt("triage"), success_criteria=requires_tool("set_triage")
        ),
        deduplicate,
        connector="bugdb",
        resource="findings",
        as_="finding",
        max_items=500,
    )
    rereview = fanout_from(
        role_agent(
            "rereview",
            task_id="rereview",
            prompt=prompt("rereview"),
            success_criteria=requires_tool("set_rereview"),
        ),
        triage,
        connector="bugdb",
        resource="findings",
        as_="finding",
        max_items=500,
    )
    fanout_from(
        role_agent(
            "report",
            task_id="report",
            prompt=prompt("report"),
            output_artifact="report.md",
            success_criteria=requires_tool("get_finding"),
        ),
        rereview,
        connector="bugdb",
        resource="findings",
        as_="finding",
        max_items=500,
    )

pipeline = graph
print(pipeline.to_json())
