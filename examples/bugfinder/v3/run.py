"""Launcher: python -m examples.bugfinder.v3.run --target monad [--budget medium] [--print]."""

from __future__ import annotations

import argparse
import asyncio
import os
from pathlib import Path
import subprocess
import sys
from typing import Mapping, Sequence

from agentflow.dsl import Graph
from agentflow.orchestrator import Orchestrator
from agentflow.specs import RunRecord, RunStatus
from agentflow.store import RunStore
from examples.bugfinder.v3.config import Target, V3Config, load_config, select_target
from examples.bugfinder.v3.pipeline import build_pipeline, checkout_path


DEFAULT_RUNS_DIR = ".agentflow/runs"
SOURCE_REF = "refs/bugfinder/source"


def git(repository: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def ensure_checkout(repository_url: str, source_ref: str, path: Path) -> str:
    """Clone or fetch `repository_url` into `path`, detach HEAD at `source_ref`, return the commit sha."""

    if not (path / ".git").exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", "--no-checkout", repository_url, str(path)], check=True)
    git(path, "fetch", "--force", "origin", f"+{source_ref}:{SOURCE_REF}")
    sha = git(path, "rev-parse", "--verify", f"{SOURCE_REF}^{{commit}}")
    git(path, "checkout", "--detach", "--force", sha)
    return sha


def resolve_source(target: Target, environment: Mapping[str, str] | None = None) -> tuple[Path, str]:
    """Worktree path and pinned sha; an explicit BUGFINDER_REPO_PATH is used as-is at its HEAD."""

    values = os.environ if environment is None else environment
    path = checkout_path(target.id, values).resolve()
    if values.get("BUGFINDER_REPO_PATH"):
        return path, git(path, "rev-parse", "--verify", "HEAD^{commit}")
    return path, ensure_checkout(target.repositoryUrl, target.sourceRef, path)


def prepare(config: V3Config, target_id: str, budget: str | None) -> Graph:
    target = select_target(config, target_id)
    _, sha = resolve_source(target)
    return build_pipeline(config, target.id, budget=budget, source_ref=sha)


def run_graph(graph: Graph, runs_dir: str) -> RunRecord:
    store = RunStore(runs_dir)
    orchestrator = Orchestrator(store=store, max_concurrent_runs=1)

    async def _run() -> RunRecord:
        record = await orchestrator.submit(graph.to_spec())
        return await orchestrator.wait(record.id, timeout=None)

    return asyncio.run(_run())


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m examples.bugfinder.v3.run",
        description="Run the bugfinder v3 workflow against one or more configured targets.",
    )
    parser.add_argument("--target", dest="targets", action="append", required=True, metavar="ID")
    parser.add_argument("--budget", metavar="low|medium|high", help="budget profile (default: config.budget)")
    parser.add_argument("--config", type=Path, help="config.yaml path (default: the shipped v3 config)")
    parser.add_argument("--print", dest="print_only", action="store_true", help="print the pipeline JSON")
    parser.add_argument("--runs-dir", default=DEFAULT_RUNS_DIR, help="AgentFlow run store directory")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    config = load_config(args.config)
    exit_code = 0
    for target_id in args.targets:
        graph = prepare(config, target_id, args.budget)
        if args.print_only:
            print(graph.to_json())
            continue
        record = run_graph(graph, args.runs_dir)
        print(f"bugfinder-v3 target={target_id} run={record.id} status={record.status.value}")
        if record.status != RunStatus.COMPLETED:
            exit_code = 1
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
