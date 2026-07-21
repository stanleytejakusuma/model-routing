"""Fail-closed Git worktree state binding for capital approval intents.

The hash is built with a temporary Git index, so `git add -A` sees tracked and
untracked worktree state without changing the caller's real index.

Accepted residuals:
* Remote-sync convergence is not verified in v1: this local tree binding assumes
  Syncthing has converged and that no remote-side edits occurred.
* There is a short check-to-exec window between hash verification and command
  execution. Repo locking is intentionally not used for a solo operator.
"""
from __future__ import annotations

import os
import re
import subprocess
import tempfile
from pathlib import Path


GIT_TIMEOUT_SECONDS = 10
TREE_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class StateHashError(RuntimeError):
    """The worktree could not be represented as a deterministic Git tree."""


def is_git_repository(repo_path: Path | str) -> bool:
    """Return whether *repo_path* is inside a worktree; execution errors raise."""
    repo = Path(repo_path).expanduser().resolve(strict=False)
    result = _git(repo, ["rev-parse", "--is-inside-work-tree"], _git_env())
    if result.returncode != 0:
        return False
    return result.stdout.strip() == "true"


def tree_sha_for_repo(repo_path: Path | str) -> str:
    """Return the 40-hex Git tree SHA for the entire current worktree state.

    A separate scratch index is deliberately used for both Git commands. This
    means tracked edits, additions, deletions, and untracked files affect the
    returned tree without staging anything in the user's real index.
    """
    repo = Path(repo_path).expanduser().resolve(strict=False)
    if not is_git_repository(repo):
        raise StateHashError(f"not a git repository: {repo}")

    with tempfile.TemporaryDirectory(prefix="model-routing-statehash-") as tempdir:
        scratch_index = Path(tempdir) / "index"
        env = _scratch_git_env(scratch_index)
        _check_git(repo, ["add", "-A"], env)
        tree_sha = _check_git(repo, ["write-tree"], env).stdout.strip()

    if not TREE_SHA_RE.fullmatch(tree_sha):
        raise StateHashError("git write-tree returned an invalid 40-hex tree SHA")
    return tree_sha


def _scratch_git_env(scratch_index: Path) -> dict[str, str]:
    env = _git_env()
    env["GIT_INDEX_FILE"] = str(scratch_index)
    return env


def _git_env() -> dict[str, str]:
    env = dict(os.environ)
    for key in (
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_DIR",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_WORK_TREE",
    ):
        env.pop(key, None)
    return env


def _git(repo: Path, args: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise StateHashError(f"git {' '.join(args)} failed: {exc.__class__.__name__}") from exc


def _check_git(repo: Path, args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    result = _git(repo, args, env)
    if result.returncode != 0:
        raise StateHashError(f"git {' '.join(args)} failed with exit {result.returncode}")
    return result
