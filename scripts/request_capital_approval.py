#!/usr/bin/env python3
"""Workstation-side capital-approval channel. When enforce mode blocks a capital
action, this walks it through the full gate and drops a signed intent the hook
consumes:

  classify -> INDEPENDENT LLM capital review -> human CONFIRM
  -> one-shot ssh to the gatekeeper host (holds the key) -> pending intent.

The key never leaves the gatekeeper host; signing needs BOTH the review approval
carried in the package AND the --confirm the operator authorizes here.
Fail-closed throughout.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

MR = Path(os.path.expanduser("~/.model-routing"))
sys.path.insert(0, str(MR / "src"))

from model_routing.approval import build_approval_package  # noqa: E402
from model_routing.classifier import classify_tool_call  # noqa: E402
from model_routing.lifecycle import ApprovalDecision, ApprovalRequest  # noqa: E402
from model_routing.registry import CapitalRegistry  # noqa: E402

REGISTRY = MR / "capital-registry.json"
PENDING = MR / "pending"
GATEKEEPER_HOST = os.environ.get("MODEL_ROUTING_GATEKEEPER_HOST", "gatekeeper")
# sudo -u mr-gatekeeper cannot read /dev/stdin (pipe fd owned by the agent user),
# so land the package in a gatekeeper-readable temp file, sign, then remove it.
GATEKEEPER_SIGN = ("f=$(mktemp); cat > $f; chmod 644 $f; "
                   "sudo -u mr-gatekeeper python3 /opt/model-routing/scripts/gatekeeper_sign.py --package $f --confirm; "
                   "rc=$?; rm -f $f; exit $rc")
OPUS_TIMEOUT_SECONDS = 600
REPO_CONTEXT_LIMIT_BYTES = 16 * 1024
OPUS_VERDICT = re.compile(r"^VERDICT: (APPROVE|REJECT)$")
REPO_BOUND_ACTION_RE = re.compile(r"\b(?:deploy(?:ment)?|migrat(?:e|ion))\b", re.IGNORECASE)


class StateBindingError(RuntimeError):
    """A capital action cannot be bound to the reviewed repository state."""


def is_git_repository(repo_path: Path) -> bool:
    # Keep the import local so the deployed script keeps using its mirrored source
    # tree, while unit tests can exercise capture policy without deployment state.
    from model_routing.statehash import is_git_repository as check_git_repository

    return check_git_repository(repo_path)


def tree_sha_for_repo(repo_path: Path) -> str:
    from model_routing.statehash import tree_sha_for_repo as hash_worktree

    return hash_worktree(repo_path)


def bind_approval_state(classification, registry: CapitalRegistry) -> tuple[str, str]:
    """Compute the signed state binding or refuse before review/signing."""
    if _requires_service_repo_binding(classification):
        service_name = _service_name_for_classification(classification, registry)
        repo = registry.repo_for_service(service_name)
        if repo is None:
            raise StateBindingError(
                f"no repo binding for capital service {service_name} — add it to the registry"
            )
        return _hash_and_record_repo(Path(repo))

    cwd = Path(classification.cwd).expanduser().resolve(strict=False)
    try:
        if not is_git_repository(cwd):
            return "none", ""
        return _hash_and_record_repo(cwd)
    except Exception as exc:
        raise StateBindingError(f"state hash failed for {cwd}: {exc.__class__.__name__}") from exc


def _requires_service_repo_binding(classification) -> bool:
    return (
        getattr(classification, "capital_reason", "") == "capital-service-mutation"
        or bool(REPO_BOUND_ACTION_RE.search(str(getattr(classification, "exact_action", ""))))
    )


def _service_name_for_classification(classification, registry: CapitalRegistry) -> str:
    target = str(getattr(classification, "target", "")).strip()
    exact_action = str(getattr(classification, "exact_action", "")).lower()
    for service in getattr(registry, "services", []):
        name = str(service.get("name", "")).strip()
        if name and name.lower() in exact_action:
            return name
    return target


def _hash_and_record_repo(repo_path: Path) -> tuple[str, str]:
    repo = repo_path.expanduser().resolve(strict=False)
    try:
        return tree_sha_for_repo(repo), str(repo)
    except Exception as exc:
        raise StateBindingError(f"state hash failed for {repo}: {exc.__class__.__name__}") from exc


def repo_state_context(cwd: str) -> str:
    """Fetch a bounded Git snapshot for the reviewer without trusting caller prose."""
    try:
        repo_cwd = str(Path(cwd).expanduser().resolve())
    except (OSError, RuntimeError) as e:
        return f"repo state unavailable: cwd resolution failed: {type(e).__name__}"

    try:
        check = subprocess.run(
            ["git", "-C", repo_cwd, "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except Exception as e:
        return f"repo state unavailable: git check failed: {type(e).__name__}"

    if check.returncode != 0 or check.stdout.strip() != "true":
        return "not a git repository"

    try:
        status = subprocess.run(
            ["git", "-C", repo_cwd, "status", "--porcelain"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if status.returncode != 0:
            return f"repo state unavailable: git status failed (exit {status.returncode})"
        diff = subprocess.run(
            ["git", "-C", repo_cwd, "diff", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if diff.returncode != 0:
            return f"repo state unavailable: git diff failed (exit {diff.returncode})"
    except Exception as e:
        return f"repo state unavailable: git fetch failed: {type(e).__name__}"

    state = (
        "git status --porcelain:\n"
        f"{status.stdout or '(clean)'}\n"
        "git diff HEAD:\n"
        f"{diff.stdout or '(no diff)'}"
    )
    if len(state.encode("utf-8")) <= REPO_CONTEXT_LIMIT_BYTES:
        return state

    marker = "\n[truncated]"
    budget = REPO_CONTEXT_LIMIT_BYTES - len(marker.encode("utf-8"))
    return state.encode("utf-8")[:budget].decode("utf-8", errors="ignore") + marker


def opus_capital_reviewer(request: ApprovalRequest) -> ApprovalDecision:
    """Independent Opus review. Any script error or ambiguous verdict rejects."""
    reviewed_repo = getattr(request, "state_repo", "") or request.cwd
    prompt = (
        "You are an INDEPENDENT capital-safety reviewer. A model-routing gate has "
        "flagged the following action as capital-affecting and needs your verdict "
        "BEFORE it can be cryptographically authorized. Judge ONLY this action.\n\n"
        f"  action_type : {request.action_type}\n"
        f"  exact_action: {request.exact_action}\n"
        f"  target      : {request.target}\n"
        f"  risk_class  : {request.risk_class}\n"
        f"  cwd/repo    : {request.cwd} / {reviewed_repo}\n"
        f"  host        : {request.host}\n\n"
        "REPO STATE (fetched independently)\n"
        f"{repo_state_context(reviewed_repo)}\n\n"
        "Respond on the FIRST line with exactly 'VERDICT: APPROVE' or 'VERDICT: "
        "REJECT', then a one-paragraph reason. REJECT if the action is destructive, moves "
        "funds, exfiltrates a key/secret, targets a live exchange, is malformed, or "
        "if you are at all unsure. Approve only a clearly-safe, sane operational action."
    )
    try:
        p = subprocess.run(
            ["claude", "-p", "--model", "claude-opus-4-8", prompt],
            capture_output=True,
            text=True,
            timeout=OPUS_TIMEOUT_SECONDS,
        )
    except Exception:
        return ApprovalDecision(False, "claude-cli-opus-capital", "claude-opus-4-8", int(time.time()),
                                defects=("opus-review-error",))

    out = p.stdout or ""
    if p.returncode != 0:
        return ApprovalDecision(False, "claude-cli-opus-capital", "claude-opus-4-8", int(time.time()),
                                defects=(f"opus-review-exit-{p.returncode}",))
    if not out.strip():
        return ApprovalDecision(False, "claude-cli-opus-capital", "claude-opus-4-8", int(time.time()),
                                defects=("opus-review-empty",))

    lines = out.splitlines()
    verdict = OPUS_VERDICT.fullmatch(lines[0]) if lines else None
    if not verdict or any(line.strip().upper().startswith("VERDICT:") for line in lines[1:]):
        return ApprovalDecision(False, "claude-cli-opus-capital", "claude-opus-4-8", int(time.time()),
                                defects=("opus-review-ambiguous",))

    approved = verdict.group(1).upper() == "APPROVE"
    return ApprovalDecision(
        approved=approved,
        verifier_identity="claude-cli-opus-capital",
        verifier_version="claude-opus-4-8",
        approved_at=int(time.time()),
        defects=() if approved else ("opus-review-rejected",),
    )


def approve_stub(request: ApprovalRequest) -> ApprovalDecision:
    return ApprovalDecision(True, "approve-stub", "test", int(time.time()))


def reject_stub(request: ApprovalRequest) -> ApprovalDecision:
    return ApprovalDecision(False, "reject-stub", "test", int(time.time()), defects=("stub-reject",))


def pre_blessed_reviewer(request: ApprovalRequest) -> ApprovalDecision:
    """Owner pre-blessed: auto-approve the REVIEW step only. The human confirm at the
    gatekeeper and the Ed25519-signed intent are still required."""
    return ApprovalDecision(True, "owner-pre-blessed", "registry", int(time.time()), defects=())


REVIEWERS = {"opus-capital": opus_capital_reviewer, "approve-stub": approve_stub, "reject-stub": reject_stub}


def sign_on_gatekeeper(package) -> dict:
    """One-shot ssh: pipe the package to the gatekeeper (holds the key) which signs
    with --confirm and returns the signed intent on stdout."""
    wire = json.dumps({
        "request": dataclasses.asdict(package.request),
        "approval": dataclasses.asdict(package.approval),
    })
    p = subprocess.run(["ssh", "-o", "ConnectTimeout=10", GATEKEEPER_HOST, GATEKEEPER_SIGN],
                       input=wire, capture_output=True, text=True, timeout=40)
    if p.returncode != 0:
        raise RuntimeError(f"gatekeeper-sign failed rc={p.returncode}: {p.stderr.strip()}")
    return json.loads(p.stdout.strip())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tool", required=True, help="Bash|Edit|Write|NotebookEdit")
    ap.add_argument("--command", help="for Bash")
    ap.add_argument("--file", help="for Edit/Write/NotebookEdit")
    ap.add_argument("--cwd", required=True)
    ap.add_argument("--host", default="local")
    ap.add_argument("--reviewer", choices=list(REVIEWERS), default="opus-capital")
    ap.add_argument("--confirm-token", default=None, help="skip interactive prompt (testing)")
    args = ap.parse_args()

    tool_input = {}
    if args.command:
        tool_input["command"] = args.command
    if args.file:
        tool_input["file_path"] = args.file

    reg = CapitalRegistry.from_file(REGISTRY)
    c = classify_tool_call(args.tool, tool_input, Path(args.cwd), reg, host=args.host)
    if not c.is_capital or c.is_read_only:
        print(f"Not a capital mutation ({c.read_only_reason or c.capital_reason}); no approval needed.")
        return 0

    try:
        tree_sha, state_repo = bind_approval_state(c, reg)
    except StateBindingError as exc:
        print(f"REFUSED — {exc}")
        return 5

    print(f"CAPITAL ACTION: {c.exact_action}\n  target={c.target} risk={c.risk_class} "
          f"reason={c.capital_reason}\n  cwd={c.cwd} repo={c.repo_id} host={c.host}")
    if reg.is_pre_blessed(c.exact_action):
        print("PRE-BLESSED owner-approved command — skipping capital review (owner confirm still required).")
        pkg = build_approval_package(
            c, policy_version="workstation-request", opus_reviewer=pre_blessed_reviewer,
            tree_sha=tree_sha, state_repo=state_repo,
        )
    else:
        print(f"Running independent review ({args.reviewer})...")
        pkg = build_approval_package(
            c, policy_version="workstation-request", opus_reviewer=REVIEWERS[args.reviewer],
            tree_sha=tree_sha, state_repo=state_repo,
        )
    if not pkg.approved:
        print("REVIEW REJECTED — not authorized:")
        for d in pkg.approval.defects:
            print("  -", d)
        return 3
    print(f"Review APPROVED by {pkg.approval.verifier_identity}.")

    token = args.confirm_token
    if token is None:
        token = input("Type CONFIRM to authorize this capital action: ").strip()
    if token != "CONFIRM":
        print("Not confirmed; aborting.")
        return 4

    print("Requesting signature from the gatekeeper host...")
    signed = sign_on_gatekeeper(pkg)
    PENDING.mkdir(parents=True, exist_ok=True)
    out_path = PENDING / f"{pkg.request.request_id}.json"
    out_path.write_text(json.dumps(signed))
    print(f"AUTHORIZED. Signed intent written to {out_path}\nRetry the action; the hook will consume it (single-use).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
