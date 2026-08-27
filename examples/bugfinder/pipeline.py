"""Single-commit, DB-backed bug-finding workflow from issue #1."""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import subprocess
from typing import Any, Callable, Mapping

from agentflow import Graph, claude, codex, fanout_from, pi, python_node


HERE = Path(__file__).resolve().parent
NO_HISTORY = "No external historical bug corpus was supplied for this run."


def git(repository: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(repository), *args],
        text=True,
    ).strip()


@dataclass(frozen=True)
class BugfinderConfig:
    repository: Path
    repository_url: str
    input_ref: str
    historical_context: str = NO_HISTORY
    environment: Mapping[str, str] = field(default_factory=dict, repr=False)

    @classmethod
    def from_environment(cls, environment: Mapping[str, str] | None = None) -> "BugfinderConfig":
        values = dict(os.environ if environment is None else environment)
        raw_repository = values.get("BUGFINDER_REPO_PATH")
        if not raw_repository:
            raise ValueError("BUGFINDER_REPO_PATH is required")
        repository = Path(raw_repository).expanduser().resolve()
        input_ref = values.get("BUGFINDER_INPUT_REF", values.get("BUGFINDER_SOURCE_REF", "HEAD"))
        repository_url = values.get("BUGFINDER_REPOSITORY_URL") or git(
            repository, "config", "--get", "remote.origin.url"
        )
        history_file = values.get("BUGFINDER_HISTORY_FILE")
        historical_context = (
            Path(history_file).expanduser().read_text(encoding="utf-8")
            if history_file
            else NO_HISTORY
        )
        return cls(
            repository=repository,
            repository_url=repository_url,
            input_ref=input_ref,
            historical_context=historical_context,
            environment=values,
        )

    def setting(self, name: str, default: str) -> str:
        return self.environment.get(name, default)


def prompt(name: str) -> str:
    return (HERE / "prompts" / f"{name}.md").read_text(encoding="utf-8")


def role_agent(config: BugfinderConfig, role: str, **kwargs: Any):
    """Choose Codex, Claude Code, or Pi/OpenRouter independently per role."""

    selected = config.setting(
        f"BUGFINDER_{role.upper()}_AGENT",
        config.setting("BUGFINDER_AGENT", "codex"),
    ).lower()
    builders: dict[str, Callable[..., Any]] = {"codex": codex, "claude": claude, "pi": pi}
    if selected not in builders:
        raise ValueError(f"unsupported {role} agent {selected!r}; choose codex, claude, or pi")
    kwargs.setdefault("connectors", ["bugdb"])
    kwargs.setdefault("concurrency_pool", f"{selected}-provider")
    if role in {"hunt", "deduplicate"}:
        kwargs.setdefault(
            "durable_goal",
            {"mode": config.setting("BUGFINDER_GOAL_MODE", "supervised")},
        )
    retryable = role in {"hunt", "deduplicate", "triage", "rereview"}
    kwargs.setdefault(
        "retries",
        int(config.setting("BUGFINDER_RETRIES", "1")) if retryable else 0,
    )
    kwargs.setdefault("retry_backoff_seconds", 2)
    kwargs.setdefault("timeout_seconds", int(config.setting("BUGFINDER_NODE_TIMEOUT", "1800")))
    kwargs.setdefault("repo_instructions_mode", "ignore")
    if selected == "codex":
        kwargs["model"] = config.setting("BUGFINDER_CODEX_MODEL", "gpt-5.6-luna")
    elif selected == "claude" and config.environment.get("BUGFINDER_CLAUDE_MODEL"):
        kwargs["model"] = config.environment["BUGFINDER_CLAUDE_MODEL"]
    elif selected == "pi":
        kwargs["model"] = config.setting(
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


REPORT_CODE = r'''import json
import os
import urllib.request

urls = json.loads(os.environ["AGENTFLOW_CONNECTOR_URLS"])
all_headers = json.loads(os.environ["AGENTFLOW_CONNECTOR_HEADERS"])
url = urls["bugdb"].removesuffix("/mcp") + "/tools/call"
headers = all_headers["bugdb"]
headers["content-type"] = "application/json"
request = urllib.request.Request(
    url,
    data=json.dumps({"name": "get_finding", "arguments": {}}).encode(),
    headers=headers,
    method="POST",
)
with urllib.request.urlopen(request) as response:
    finding = json.loads(response.read())["result"]

def required_text(value, label):
    if not isinstance(value, str) or not value.strip():
        raise RuntimeError(f"Finding report requires {label}")
    return value.strip()

triage = required_text(finding.get("triageVerdict"), "triage")
rereview = required_text(finding.get("rereviewVerdict"), "re-review")
disposition = required_text(finding.get("disposition"), "derived disposition")
if disposition not in {"CONFIRMED", "REJECTED", "INCONCLUSIVE"}:
    raise RuntimeError("BugDB returned an invalid derived disposition")

leads = finding.get("leads")
if not isinstance(leads, list) or not leads:
    raise RuntimeError("Finding report requires at least one Lead")
evidence = []
validation_plans = []
for index, lead in enumerate(leads, start=1):
    hunt = lead.get("hunt") or {}
    section = [
        f"### Lead {index} ({required_text(hunt.get('kind'), 'Hunt kind')})",
        f"**Claim:** {required_text(lead.get('claim'), 'Lead claim')}",
        f"**Locations:** {', '.join(lead.get('locations') or [])}",
        f"**Evidence:** {required_text(lead.get('evidence'), 'Lead evidence')}",
    ]
    for key, label in (
        ("attackerPreconditions", "Attacker preconditions"),
        ("impact", "Lead impact"),
        ("validationPlan", "Validation"),
    ):
        value = lead.get(key)
        if isinstance(value, str) and value.strip():
            section.append(f"**{label}:** {value.strip()}")
            if key == "validationPlan":
                validation_plans.append(value.strip())
    evidence.append("\n\n".join(section))

report = "\n\n".join([
    f"# {required_text(finding.get('title'), 'title')}",
    f"**Disposition:** {disposition}",
    "## Impact",
    required_text(finding.get("impact"), "impact"),
    "## Root cause",
    required_text(finding.get("rootCause"), "root cause"),
    "## Reviews",
    f"**Triage ({triage}):** {required_text(finding.get('triageAssessment'), 'triage assessment')}",
    f"**Independent re-review ({rereview}):** "
    f"{required_text(finding.get('rereviewAssessment'), 're-review assessment')}",
    "## Evidence",
    "\n\n".join(evidence),
    "## Validation guidance",
    "\n".join(f"- {plan}" for plan in validation_plans)
    or "Reproduce the stated evidence against the pinned source commit.",
    "## Remediation",
    "Address the stated root cause, then repeat the validation guidance above.",
]).strip() + "\n"
print(report, end="")
'''


def bugdb_connector() -> dict[str, Any]:
    return {
        "name": "bugdb",
        "url": "http://127.0.0.1:{port}/mcp",
        "control_url": "http://127.0.0.1:{port}/orchestration",
        "command": "npm",
        "args": ["run", "connector"],
        "cwd": str(HERE),
        "env": {"BUGDB_PORT": "{port}"},
        "env_from": {"DATABASE_URL": "DATABASE_URL"},
    }


def build_pipeline(config: BugfinderConfig) -> Graph:
    with Graph(
        "bugfinder",
        description="Single-commit Mythos-style and threat-model-driven bug finding",
        working_dir=str(config.repository),
        source_snapshot={
            "repositoryUrl": config.repository_url,
            "inputRef": config.input_ref,
        },
        concurrency=int(config.setting("BUGFINDER_CONCURRENCY", "24")),
        deadline_seconds=int(config.setting("BUGFINDER_DEADLINE_SECONDS", "14400")),
        fail_fast=False,
        concurrency_pools={
            "codex-provider": int(config.setting("BUGFINDER_CODEX_CONCURRENCY", "12")),
            "claude-provider": int(config.setting("BUGFINDER_CLAUDE_CONCURRENCY", "8")),
            "pi-provider": int(config.setting("BUGFINDER_PI_CONCURRENCY", "12")),
        },
        connectors=[bugdb_connector()],
    ) as graph:
        rank_files = role_agent(
            config,
            "rank",
            task_id="rank_files",
            prompt=prompt("rank"),
            connector_tools={"bugdb": ["add_hunts"]},
            success_criteria=requires_tool("add_hunts"),
        )
        threat_model = role_agent(
            config,
            "threat",
            task_id="threat_model",
            prompt=prompt("threat"),
            input={
                "repositoryUrl": config.repository_url,
                "historicalContext": config.historical_context,
            },
            connector_tools={"bugdb": ["add_hunts"]},
            success_criteria=requires_tool("add_hunts"),
        )
        roam_plan = role_agent(
            config,
            "roam",
            task_id="roam_plan",
            prompt=prompt("roam"),
            connector_tools={"bugdb": ["add_hunts"]},
            success_criteria=requires_tool("add_hunts"),
        )

        hunt = fanout_from(
            role_agent(
                config,
                "hunt",
                task_id="hunt",
                prompt=prompt("hunt"),
                connector_tools={"bugdb": ["get_hunt", "add_lead", "finish_hunt"]},
                success_criteria=requires_tool("finish_hunt"),
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
            config,
            "deduplicate",
            task_id="deduplicate",
            prompt=prompt("deduplicate"),
            connector_tools={"bugdb": ["list_hunts_and_leads", "create_findings"]},
            success_criteria=requires_tool("create_findings"),
        )
        hunt >> deduplicate

        triage = fanout_from(
            role_agent(
                config,
                "triage",
                task_id="triage",
                prompt=prompt("triage"),
                connector_tools={"bugdb": ["get_finding", "set_triage"]},
                success_criteria=requires_tool("set_triage"),
            ),
            deduplicate,
            connector="bugdb",
            resource="findings",
            as_="finding",
            max_items=500,
        )
        rereview = fanout_from(
            role_agent(
                config,
                "rereview",
                task_id="rereview",
                prompt=prompt("rereview"),
                connector_tools={"bugdb": ["get_finding", "set_rereview"]},
                success_criteria=requires_tool("set_rereview"),
            ),
            triage,
            connector="bugdb",
            resource="findings",
            as_="finding",
            max_items=500,
        )
        fanout_from(
            python_node(
                task_id="report",
                code=REPORT_CODE,
                connectors=["bugdb"],
                connector_tools={"bugdb": ["get_finding"]},
                repo_instructions_mode="ignore",
                capture="trace",
                output_artifact="report.md",
                success_criteria=[{"kind": "output_regex", "value": r"\S"}],
            ),
            rereview,
            connector="bugdb",
            resource="findings",
            as_="finding",
            max_items=500,
        )
    return graph


if __name__ == "__main__":
    print(build_pipeline(BugfinderConfig.from_environment()).to_json())
