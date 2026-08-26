"""One-node live smoke: subscription-authenticated Codex appends one run-scoped Hunt."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from agentflow import Graph, codex, fanout_from


HERE = Path(__file__).resolve().parent
REPOSITORY = Path(os.environ["BUGFINDER_REPO_PATH"]).expanduser().resolve()
INPUT_REF = os.environ.get("BUGFINDER_INPUT_REF", os.environ.get("BUGFINDER_SOURCE_REF", "HEAD"))
COMMIT_SHA = subprocess.check_output(
    ["git", "-C", str(REPOSITORY), "rev-parse", f"{INPUT_REF}^{{commit}}"],
    text=True,
).strip()
REPOSITORY_URL = os.environ.get("BUGFINDER_REPOSITORY_URL", "https://github.com/monad-exp/agentflow.git")
BUGDB_PORT = int(os.environ.get("BUGDB_PORT", "4312"))

with Graph(
    "bugfinder-live-smoke",
    working_dir=str(REPOSITORY),
    source_snapshot={
        "repositoryUrl": REPOSITORY_URL,
        "inputRef": INPUT_REF,
        "commitSha": COMMIT_SHA,
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
            "tools": [
                {
                    "name": "add_hunts",
                    "description": "Insert selected Hunts into the AgentFlow-injected run.",
                    "input_schema": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["hunts"],
                        "properties": {
                            "hunts": {
                                "type": "array",
                                "minItems": 1,
                                "maxItems": 1,
                                "items": {
                                    "type": "object",
                                    "additionalProperties": False,
                                    "required": ["callerKey", "kind", "objective", "paths"],
                                    "properties": {
                                        "callerKey": {"type": "string"},
                                        "kind": {"const": "FILE"},
                                        "objective": {"type": "string"},
                                        "paths": {
                                            "type": "array",
                                            "minItems": 1,
                                            "maxItems": 1,
                                            "items": {"type": "string"},
                                        },
                                    },
                                },
                            }
                        },
                    },
                },
                {
                    "name": "get_hunt",
                    "description": "Read the Hunt injected into this hunter.",
                    "input_schema": {"type": "object", "additionalProperties": False},
                },
                {
                    "name": "finish_hunt",
                    "description": "Set the injected Hunt result once.",
                    "input_schema": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["result", "resultSummary"],
                        "properties": {
                            "result": {"enum": ["BUG_FOUND", "EXHAUSTED", "BLOCKED"]},
                            "resultSummary": {"type": "string"},
                        },
                    },
                },
            ],
        }
    ],
) as graph:
    plan = codex(
        task_id="write_hunt",
        model=os.environ.get("BUGFINDER_CODEX_MODEL", "gpt-5.6-luna"),
        connectors=["bugdb"],
        retries=1,
        success_criteria=[
            {"kind": "connector_tool_called", "connector": "bugdb", "tool": "add_hunts"}
        ],
        prompt=f"""This is a connector smoke test at pinned commit {COMMIT_SHA}.
Call bugdb.add_hunts exactly once with one Hunt:
- callerKey: live-codex-smoke-v2
- kind: FILE
- objective: Verify a subscription-authenticated Codex MCP write to BugDB.
- paths: [README.md]

Do not modify files or call another tool. Return only `smoke complete`.
""",
    )
    fanout_from(
        codex(
            task_id="finish_hunt",
            model=os.environ.get("BUGFINDER_CODEX_MODEL", "gpt-5.6-luna"),
            connectors=["bugdb"],
            retries=1,
            durable_goal={"mode": "supervised"},
            success_criteria=[
                {"kind": "connector_tool_called", "connector": "bugdb", "tool": "finish_hunt"}
            ],
            prompt="""Use exactly these two BugDB tools and no others. First call bugdb.get_hunt with no arguments and verify the injected FILE Hunt is anchored to README.md. Then you MUST call bugdb.finish_hunt with result EXHAUSTED and resultSummary `Live scoped fan-out and write-once result verification completed.` The task is incomplete until finish_hunt succeeds. Do not modify files. Only after both calls succeed, return `hunt smoke complete`.""",
        ),
        plan,
        connector="bugdb",
        resource="hunts",
        as_="hunt",
        max_items=1,
    )

pipeline = graph
print(pipeline.to_json())
