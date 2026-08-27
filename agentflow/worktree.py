"""Git worktree management for isolated agent execution."""

from __future__ import annotations

import subprocess
from pathlib import Path


def repository_root(path: Path) -> Path:
    """Return the root of the Git repository containing ``path``."""

    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=str(path),
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        raise RuntimeError(f"source working directory is not a Git repository: {result.stderr.strip()}")
    return Path(result.stdout.strip()).resolve()


def resolve_commit(repo_dir: Path, input_ref: str) -> str:
    """Resolve a Git ref to one full commit ID."""

    result = subprocess.run(
        ["git", "rev-parse", "--verify", "--end-of-options", f"{input_ref}^{{commit}}"],
        cwd=str(repo_dir),
        capture_output=True,
        text=True,
        timeout=10,
    )
    commit_sha = result.stdout.strip().lower()
    if result.returncode != 0 or len(commit_sha) not in {40, 64} or any(
        char not in "0123456789abcdef" for char in commit_sha
    ):
        detail = result.stderr.strip() or f"ref {input_ref!r} is not a commit"
        raise RuntimeError(f"could not resolve source input: {detail}")
    return commit_sha


def create_pinned_worktree(repo_dir: Path, run_id: str, commit_sha: str) -> Path:
    """Create the detached source worktree shared by one run."""

    worktree_dir = repo_dir / ".agentflow" / "worktrees" / run_id / "source"
    worktree_dir.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        ["git", "worktree", "add", "--detach", str(worktree_dir), commit_sha],
        cwd=str(repo_dir),
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(f"failed to create pinned source worktree: {result.stderr.strip()}")
    return worktree_dir


def create_worktree(repo_dir: Path, node_id: str, run_id: str) -> Path:
    """Create a git worktree for a node. Returns the worktree path."""
    safe_id = node_id.replace("/", "_")
    worktree_dir = repo_dir / ".agentflow" / "worktrees" / run_id / safe_id
    worktree_dir.parent.mkdir(parents=True, exist_ok=True)

    branch_name = f"agentflow/{run_id[:8]}/{safe_id}"

    result = subprocess.run(
        ["git", "worktree", "add", "-b", branch_name, str(worktree_dir)],
        cwd=str(repo_dir),
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        result = subprocess.run(
            ["git", "worktree", "add", str(worktree_dir), "HEAD"],
            cwd=str(repo_dir),
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Failed to create worktree for {node_id}: {result.stderr.strip()}")

    return worktree_dir


def get_worktree_diff(worktree_dir: Path) -> str:
    """Get the full diff of changes made in a worktree (tracked + untracked)."""
    # Stage everything so diff captures new files too
    subprocess.run(
        ["git", "add", "-A"],
        cwd=str(worktree_dir),
        capture_output=True,
        timeout=10,
    )
    result = subprocess.run(
        ["git", "diff", "--cached", "HEAD"],
        cwd=str(worktree_dir),
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.stdout if result.returncode == 0 else ""


def remove_worktree(repo_dir: Path, worktree_dir: Path) -> None:
    """Remove a git worktree."""
    subprocess.run(
        ["git", "worktree", "remove", "--force", str(worktree_dir)],
        cwd=str(repo_dir),
        capture_output=True,
        text=True,
        timeout=30,
    )


def is_git_repo(path: Path) -> bool:
    """Check if path is inside a git repository."""
    result = subprocess.run(
        ["git", "rev-parse", "--git-dir"],
        cwd=str(path),
        capture_output=True,
        text=True,
        timeout=5,
    )
    return result.returncode == 0
