#!/usr/bin/env python3
"""Isolation test for pretooluse_hook.py. Drives the hook as a subprocess with
controlled env/stdin and asserts exit codes + side effects. Run BEFORE installing
the hook into any Claude Code settings."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
HOOK = REPO / "scripts" / "pretooluse_hook.py"
SRC = REPO / "src"
REGISTRY = REPO / "config" / "capital-registry.example.json"

sys.path.insert(0, str(SRC))
from model_routing.approval import ApprovalDecision, build_approval_package, gatekeeper_sign_authorized  # noqa: E402
from model_routing.classifier import classify_tool_call  # noqa: E402
from model_routing.registry import CapitalRegistry  # noqa: E402
from model_routing.statehash import tree_sha_for_repo  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat  # noqa: E402

CAPITAL_EVENT = {"tool_name": "Bash",
                 "tool_input": {"command": "systemctl restart signer.service"},
                 "cwd": "/home/operator/repos/trading-engine", "host": "local"}
NONCAPITAL_EVENT = {"tool_name": "Bash", "tool_input": {"command": "git log --oneline"},
                    "cwd": "/home/operator/repos/research", "host": "local"}


def run_hook(event, mode, env_extra):
    env = dict(os.environ)
    env.update({"MODEL_ROUTING_MODE": mode, "MODEL_ROUTING_SRC": str(SRC),
                "MODEL_ROUTING_REGISTRY": str(REGISTRY), "MODEL_ROUTING_SHADOW_VERBOSE": "1"})
    env.update(env_extra)
    stdin = event if isinstance(event, str) else json.dumps(event)
    p = subprocess.run([sys.executable, str(HOOK)], input=stdin, env=env,
                       capture_output=True, text=True, timeout=30)
    return p.returncode, p.stdout, p.stderr


def make_intent(pending_dir: Path, priv: Path, user: str, event: dict, *, state_binding="auto") -> Path:
    reg = CapitalRegistry.from_file(REGISTRY)
    c = classify_tool_call(event["tool_name"], event["tool_input"], Path(event["cwd"]), reg, host="local")
    if state_binding == "auto":
        tree_sha = tree_sha_for_repo(Path(c.cwd))
        state_repo = str(Path(c.cwd).resolve())
    else:
        tree_sha = "none"
        state_repo = ""
    pkg = build_approval_package(c, policy_version="hook-test",
                                 tree_sha=tree_sha, state_repo=state_repo,
                                 opus_reviewer=lambda r: ApprovalDecision(True, "test-opus", "v1", int(time.time())))
    out = gatekeeper_sign_authorized(pkg, private_key_path=priv, human_confirmer=lambda r, a: True,
                                     operator=user, gatekeeper_user=user)
    assert out.ok, out.reason
    path = pending_dir / f"{pkg.request.request_id}.json"
    path.write_text(json.dumps(out.signed_intent))
    return path


def make_git_repo(root: Path, name: str) -> Path:
    repo = root / name
    repo.mkdir()
    for args in (("init",), ("config", "user.email", "hook-test@example.invalid"),
                 ("config", "user.name", "Hook Test")):
        subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True, timeout=10)
    (repo / "tracked.txt").write_text("original\n")
    subprocess.run(["git", "-C", str(repo), "add", "tracked.txt"], check=True, capture_output=True, text=True, timeout=10)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "initial"], check=True, capture_output=True, text=True, timeout=10)
    return repo


def capital_event_for(repo: Path) -> dict:
    return {**CAPITAL_EVENT, "cwd": str(repo)}


def main() -> int:
    tmp = Path(tempfile.mkdtemp())
    log = tmp / "hook.log"
    pending = tmp / "pending"
    pending.mkdir()
    priv = tmp / "k-priv.pem"
    pub = tmp / "k-pub.pem"
    key = Ed25519PrivateKey.generate()
    priv.write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    pub.write_bytes(key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
    priv.chmod(0o600)
    user = __import__("pwd").getpwuid(os.getuid()).pw_name
    base_env = {"MODEL_ROUTING_LOG": str(log), "MODEL_ROUTING_PENDING_DIR": str(pending),
                "MODEL_ROUTING_INTENT_PUBLIC_KEY": str(pub)}
    fails = []
    base_repo = make_git_repo(tmp, "base")
    capital_event = capital_event_for(base_repo)

    # 1. shadow + capital -> allow(0), SHADOW note, logged
    rc, so, se = run_hook(capital_event, "shadow", base_env)
    if not (rc == 0 and "SHADOW" in se):
        fails.append(f"shadow-capital rc={rc} se={se!r}")

    # 2. shadow + non-capital -> allow(0)
    rc, so, se = run_hook(NONCAPITAL_EVENT, "shadow", base_env)
    if rc != 0:
        fails.append(f"shadow-noncapital rc={rc}")

    # 3. fail-open on bad stdin -> allow(0)
    rc, so, se = run_hook("this is not json", "enforce", base_env)
    if rc != 0:
        fails.append(f"fail-open-badjson rc={rc}")

    # 4. enforce + capital + no intent -> block(2)
    rc, so, se = run_hook(capital_event, "enforce", base_env)
    if rc != 2:
        fails.append(f"enforce-nointent rc={rc} (want 2)")

    # 5. enforce + capital + valid intent -> allow(0) + consume
    make_intent(pending, priv, user, capital_event)
    n_before = len(list(pending.glob("*.json")))
    rc, so, se = run_hook(capital_event, "enforce", base_env)
    n_after = len(list(pending.glob("*.json")))
    if not (rc == 0 and n_before == 1 and n_after == 0):
        fails.append(f"enforce-validintent rc={rc} before={n_before} after={n_after}")

    # 6. enforce again (intent consumed) -> block(2)
    rc, so, se = run_hook(capital_event, "enforce", base_env)
    if rc != 2:
        fails.append(f"enforce-consumed-reblock rc={rc} (want 2)")

    # 7. enforce + non-capital -> allow(0) even with no intent
    rc, so, se = run_hook(NONCAPITAL_EVENT, "enforce", base_env)
    if rc != 0:
        fails.append(f"enforce-noncapital rc={rc}")

    # 8. approval -> changed-and-committed repo -> block + invalidate.
    commit_repo = make_git_repo(tmp, "commit-drift")
    commit_event = capital_event_for(commit_repo)
    intent_path = make_intent(pending, priv, user, commit_event)
    (commit_repo / "tracked.txt").write_text("committed drift\n")
    subprocess.run(["git", "-C", str(commit_repo), "add", "tracked.txt"], check=True, capture_output=True, text=True, timeout=10)
    subprocess.run(["git", "-C", str(commit_repo), "commit", "-m", "drift"], check=True, capture_output=True, text=True, timeout=10)
    rc, so, se = run_hook(commit_event, "enforce", base_env)
    if not (rc == 2 and not intent_path.exists() and intent_path.with_name(f"{intent_path.name}.invalidated").exists()):
        fails.append(f"state-commit-drift rc={rc} intent={intent_path.exists()}")

    # 9. approval -> unstaged tracked edit -> block + invalidate.
    edit_repo = make_git_repo(tmp, "unstaged-drift")
    edit_event = capital_event_for(edit_repo)
    intent_path = make_intent(pending, priv, user, edit_event)
    (edit_repo / "tracked.txt").write_text("unstaged drift\n")
    rc, so, se = run_hook(edit_event, "enforce", base_env)
    if not (rc == 2 and intent_path.with_name(f"{intent_path.name}.invalidated").exists()):
        fails.append(f"state-unstaged-drift rc={rc}")

    # 10. approval -> new untracked file -> block + invalidate.
    add_repo = make_git_repo(tmp, "untracked-add")
    add_event = capital_event_for(add_repo)
    intent_path = make_intent(pending, priv, user, add_event)
    (add_repo / "new-untracked.txt").write_text("drift\n")
    rc, so, se = run_hook(add_event, "enforce", base_env)
    if not (rc == 2 and intent_path.with_name(f"{intent_path.name}.invalidated").exists()):
        fails.append(f"state-untracked-add rc={rc}")

    # 11. approval with an untracked file -> delete it -> block + invalidate.
    delete_repo = make_git_repo(tmp, "untracked-delete")
    reviewed_untracked = delete_repo / "reviewed-untracked.txt"
    reviewed_untracked.write_text("reviewed\n")
    delete_event = capital_event_for(delete_repo)
    intent_path = make_intent(pending, priv, user, delete_event)
    reviewed_untracked.unlink()
    rc, so, se = run_hook(delete_event, "enforce", base_env)
    if not (rc == 2 and intent_path.with_name(f"{intent_path.name}.invalidated").exists()):
        fails.append(f"state-untracked-delete rc={rc}")

    # 12. drift then exact revert restores the reviewed tree and is allowed.
    revert_repo = make_git_repo(tmp, "drift-revert")
    revert_event = capital_event_for(revert_repo)
    intent_path = make_intent(pending, priv, user, revert_event)
    tracked = revert_repo / "tracked.txt"
    tracked.write_text("drift\n")
    tracked.write_text("original\n")
    rc, so, se = run_hook(revert_event, "enforce", base_env)
    if not (rc == 0 and not intent_path.exists()):
        fails.append(f"state-drift-revert rc={rc}")

    # 13. a repo-free secret read keeps its explicit `none` binding and is allowed.
    repo_free_event = {"tool_name": "Bash", "tool_input": {"command": "cat /home/operator/.config/trading/signer-key"},
                       "cwd": str(tmp / "repo-free"), "host": "local"}
    intent_path = make_intent(pending, priv, user, repo_free_event, state_binding="none")
    rc, so, se = run_hook(repo_free_event, "enforce", base_env)
    if not (rc == 0 and not intent_path.exists()):
        fails.append(f"state-repo-free-none rc={rc}")

    # 14. a `none` downgrade for a restart in a git repo is refused + invalidated.
    downgrade_repo = make_git_repo(tmp, "none-downgrade")
    downgrade_event = capital_event_for(downgrade_repo)
    intent_path = make_intent(pending, priv, user, downgrade_event, state_binding="none")
    rc, so, se = run_hook(downgrade_event, "enforce", base_env)
    if not (rc == 2 and intent_path.with_name(f"{intent_path.name}.invalidated").exists()):
        fails.append(f"state-none-downgrade rc={rc}")

    # 15. a classify-time exception (here: unreadable registry) must fail CLOSED
    # in enforce so a crafted crash cannot slip the gate, and stay log-only in shadow.
    bad_reg_env = {**base_env, "MODEL_ROUTING_REGISTRY": str(tmp / "no-such-registry.json")}
    rc, so, se = run_hook(capital_event, "enforce", bad_reg_env)
    if rc != 2:
        fails.append(f"classify-error-enforce-failclosed rc={rc} (want 2)")
    rc, so, se = run_hook(capital_event, "shadow", bad_reg_env)
    if rc != 0:
        fails.append(f"classify-error-shadow-allow rc={rc} (want 0)")

    if fails:
        print("HOOK-ISOLATION: FAIL")
        for f in fails:
            print("  -", f)
        return 1
    print("HOOK-ISOLATION: PASS (15/15: shadow-allow, noncapital-allow, fail-open, "
          "enforce-block, no-drift-allow+consume, reblock-after-consume, enforce-noncapital-allow, "
          "commit-drift, unstaged-drift, untracked-add, untracked-delete, drift-revert, "
          "repo-free-none, none-downgrade, classify-error-failclosed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
