from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

from agentflow.agents.util import PythonAdapter
from agentflow.orchestrator import Orchestrator
from agentflow.prepared import ExecutionPaths
from agentflow.runners.base import LaunchPlan
from agentflow.specs import NodeSpec
from agentflow.store import RunStore


def test_python_node_receives_declared_connector_binding_in_ephemeral_env(tmp_path: Path):
    node = NodeSpec.model_validate(
        {
            "id": "report",
            "agent": "python",
            "prompt": "pass",
            "connector_bindings": [
                {
                    "name": "bugdb",
                    "url": "http://127.0.0.1:43210/mcp",
                    "headers": {"authorization": "Bearer secret"},
                }
            ],
        }
    )
    paths = ExecutionPaths(
        host_workdir=tmp_path,
        host_runtime_dir=tmp_path / "runtime",
        target_workdir=str(tmp_path),
        target_runtime_dir=str(tmp_path / "runtime"),
        app_root=tmp_path,
    )

    prepared = PythonAdapter().prepare(node, node.prompt, paths)

    assert json.loads(prepared.env["AGENTFLOW_CONNECTOR_URLS"]) == {
        "bugdb": "http://127.0.0.1:43210/mcp"
    }
    assert json.loads(prepared.env["AGENTFLOW_CONNECTOR_HEADERS"]) == {
        "bugdb": {"authorization": "Bearer secret"}
    }
    assert prepared.command[:3] == ["python3", "-I", "-c"]
    assert "Bearer secret" not in " ".join(prepared.command)

    launch = Orchestrator(store=RunStore(tmp_path / "runs"))._launch_artifact_payload(
        1,
        LaunchPlan(command=prepared.command, env=prepared.env, cwd=prepared.cwd),
    )
    assert launch["env"]["AGENTFLOW_CONNECTOR_HEADERS"] == "<redacted>"


def test_python_connector_node_cannot_import_from_untrusted_worktree(tmp_path: Path):
    marker = tmp_path / "imported-untrusted-json"
    (tmp_path / "json.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).touch()\n",
        encoding="utf-8",
    )
    node = NodeSpec.model_validate(
        {
            "id": "report",
            "agent": "python",
            "prompt": "import json; print(json.dumps({'safe': True}))",
            "connector_bindings": [
                {"name": "bugdb", "url": "http://127.0.0.1:43210/mcp"}
            ],
        }
    )
    paths = ExecutionPaths(
        host_workdir=tmp_path,
        host_runtime_dir=tmp_path / "runtime",
        target_workdir=str(tmp_path),
        target_runtime_dir=str(tmp_path / "runtime"),
        app_root=tmp_path,
    )

    prepared = PythonAdapter().prepare(node, node.prompt, paths)
    completed = subprocess.run(
        prepared.command,
        cwd=prepared.cwd,
        env=prepared.env,
        capture_output=True,
        text=True,
        check=True,
    )

    assert json.loads(completed.stdout) == {"safe": True}
    assert not marker.exists()


def _paths(tmp_path: Path) -> ExecutionPaths:
    return ExecutionPaths(
        host_workdir=tmp_path,
        host_runtime_dir=tmp_path / "runtime",
        target_workdir=str(tmp_path),
        target_runtime_dir=str(tmp_path / "runtime"),
        app_root=tmp_path,
    )


def test_python_node_defaults_to_python3_in_the_working_dir(tmp_path: Path):
    node = NodeSpec.model_validate({"id": "collect", "agent": "python", "prompt": "print(1)"})

    prepared = PythonAdapter().prepare(node, node.prompt, _paths(tmp_path))

    assert prepared.command == ["python3", "-c", "print(1)"]
    assert prepared.cwd == str(tmp_path)


def test_python_node_honours_declared_executable_and_keeps_isolation_flag(tmp_path: Path):
    node = NodeSpec.model_validate(
        {
            "id": "collect",
            "agent": "python",
            "prompt": "print(1)",
            "executable": sys.executable,
            "connector_bindings": [{"name": "bugdb", "url": "http://127.0.0.1:43210/mcp"}],
        }
    )

    prepared = PythonAdapter().prepare(node, node.prompt, _paths(tmp_path))

    assert prepared.command == [sys.executable, "-I", "-c", "print(1)"]
