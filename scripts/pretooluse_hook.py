#!/usr/bin/env python3
"""Model-routing capital-safety PreToolUse hook (Claude Code).

Modes (env MODEL_ROUTING_MODE, default "shadow"):
  shadow  : classify + LOG capital mutations, NEVER block. Fully reversible.
  enforce : block a capital mutation unless a valid Opus-signed intent is pending
            for THIS exact action (single-use, consumed on match).

Fail posture (deliberate): any INTERNAL error (bad stdin, missing config, load
failure) is logged and FAILS OPEN — a hook bug must never wedge every tool call
in every session. The load-bearing gates are (a) the human-confirm at signing
and (b) the authoritative gatekeeper-side verifier for gatekeeper-routed actions;
this local hook is the fast best-effort layer. Only a cleanly-classified capital
mutation with no valid pending intent is blocked, and only in enforce mode.

Install with a matcher scoped to mutation-capable tools (Bash|Edit|Write|
NotebookEdit) so read-only tools take zero overhead.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path

HOME = Path(os.path.expanduser("~"))
MODE = os.environ.get("MODEL_ROUTING_MODE", "shadow").strip().lower()
REGISTRY = os.environ.get("MODEL_ROUTING_REGISTRY", str(HOME / ".model-routing/capital-registry.json"))
PUBKEY = os.environ.get("MODEL_ROUTING_INTENT_PUBLIC_KEY", str(HOME / ".model-routing/intent-public.pem"))
PENDING = Path(os.environ.get("MODEL_ROUTING_PENDING_DIR", str(HOME / ".model-routing/pending")))
LOGFILE = Path(os.environ.get("MODEL_ROUTING_LOG", str(HOME / ".model-routing/hook.log")))
SRC = os.environ.get("MODEL_ROUTING_SRC", str(HOME / ".model-routing/src"))

if SRC and SRC not in sys.path:
    sys.path.insert(0, SRC)


def log(obj: dict) -> None:
    try:
        LOGFILE.parent.mkdir(parents=True, exist_ok=True)
        obj["ts"] = int(time.time())
        obj["mode"] = MODE
        with LOGFILE.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(obj) + "\n")
    except Exception:
        pass  # logging must never break the hook


def allow(reason: str) -> int:
    # exit 0 = allow. No stdout needed for allow; Claude Code proceeds.
    return 0


def block(reason: str, detail: dict | None = None) -> int:
    # enforce-mode block: exit 2 + stderr is the universal, version-robust signal.
    msg = f"[model-routing] capital mutation blocked: {reason}. " \
          "Obtain a reviewed, human-confirmed, signed intent (gatekeeper host) and retry. " \
          "If you are only writing prose that mentions a capital command (for example, a doc or spec), " \
          "use the Edit/Write tool instead of a Bash heredoc; this gate scans Bash command content."
    sys.stderr.write(msg + "\n")
    # Also emit modern hookSpecificOutput for hosts that read it.
    try:
        out = {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                      "permissionDecision": "deny",
                                      "permissionDecisionReason": msg}}
        sys.stdout.write(json.dumps(out) + "\n")
    except Exception:
        pass
    return 2


def _expected(c) -> dict:
    return {
        "action_type": c.action_type,
        "exact_action": c.exact_action,
        "cwd": c.cwd,
        "repo_id": c.repo_id or "unknown",
        "host": c.host,
        "target": c.target,
        "risk_class": c.risk_class,
    }


def _find_valid_intent(c) -> tuple[Path, dict] | None:
    """enforce mode: scan pending dir for a signed intent matching THIS action.
    Non-consuming peek; the matched file is deleted by the caller (single-use)."""
    from model_routing.intents import verify_peek  # local import; keeps shadow path light
    if not PENDING.is_dir():
        return None
    exp = _expected(c)
    now = int(time.time())
    for f in sorted(PENDING.glob("*.json")):
        try:
            intent = json.loads(f.read_text(encoding="utf-8"))
            res = verify_peek(intent, Path(PUBKEY), exp, now=now)
            if res.ok:
                payload = intent.get("payload")
                if isinstance(payload, dict):
                    return f, payload
        except Exception:
            continue
    return None


def _state_binding_has_drift(c, payload: dict) -> bool:
    """Return true when a signed intent no longer represents its reviewed state."""
    from model_routing.statehash import StateHashError, is_git_repository, tree_sha_for_repo

    tree_sha = str(payload.get("tree_sha", ""))
    if tree_sha in {"", "none"}:
        if not _requires_repo_state_binding(c):
            return False
        recorded_cwd = Path(str(payload.get("cwd", ""))).expanduser().resolve(strict=False)
        try:
            return is_git_repository(recorded_cwd)
        except StateHashError:
            return True

    state_repo = str(payload.get("state_repo", "")).strip()
    if not state_repo or not re.fullmatch(r"[0-9a-f]{40}", tree_sha):
        return True
    try:
        return tree_sha_for_repo(Path(state_repo)) != tree_sha
    except StateHashError:
        return True


def _requires_repo_state_binding(c) -> bool:
    if getattr(c, "capital_reason", "") == "capital-service-mutation":
        return True
    return bool(re.search(r"\b(?:deploy(?:ment)?|migrat(?:e|ion))\b", c.exact_action, re.IGNORECASE))


def _invalidate_intent(path: Path) -> Path:
    invalidated = path.with_name(f"{path.name}.invalidated")
    path.replace(invalidated)
    return invalidated


def main() -> int:
    # --- read event (fail open) ---
    try:
        event = json.load(sys.stdin)
    except Exception as e:
        log({"event": "stdin-parse-error", "err": str(e)})
        return allow("stdin-unreadable")

    tool_name = str(event.get("tool_name", ""))
    payload = event.get("tool_input", {}) or {}
    cwd = Path(str(event.get("cwd") or payload.get("cwd") or "."))

    # --- classify (fail open) ---
    try:
        from model_routing.classifier import classify_tool_call
        from model_routing.registry import CapitalRegistry
        registry = CapitalRegistry.from_file(Path(REGISTRY))
        c = classify_tool_call(tool_name, payload, cwd, registry, host=str(event.get("host", "local")))
    except Exception as e:
        log({"event": "classify-error", "tool": tool_name, "err": str(e)})
        # Cannot prove this call is non-capital. A crafted input that crashes the
        # classifier must not slip the gate, so enforce mode fails CLOSED here.
        # Shadow mode keeps its never-block contract (log-only).
        if MODE == "enforce":
            return block("classify-failed-fail-closed")
        return allow("classify-failed-shadow")

    if c.is_read_only or not c.is_capital:
        return allow("not-capital-mutation")

    # --- capital mutation ---
    base = {"event": "capital-mutation", "tool": tool_name,
            "action_type": c.action_type, "exact_action": c.exact_action,
            "target": c.target, "risk_class": c.risk_class,
            "capital_reason": getattr(c, "capital_reason", ""), "cwd": str(cwd)}

    if MODE != "enforce":
        log({**base, "decision": "shadow-allow"})
        if os.environ.get("MODEL_ROUTING_SHADOW_VERBOSE") == "1":
            sys.stderr.write(f"[model-routing SHADOW] capital mutation observed: {c.exact_action} "
                             f"(target={c.target}, risk={c.risk_class}). Would require signed intent when armed.\n")
        return allow("shadow")

    # enforce
    try:
        match = _find_valid_intent(c)
    except Exception as e:
        # enforce + can't evaluate intent: fail CLOSED for capital (this is the
        # one place we choose safety over availability, and only for capital).
        log({**base, "decision": "enforce-error-block", "err": str(e)})
        return block(f"intent-check-error:{e}", base)

    if match is None:
        log({**base, "decision": "enforce-block", "reason": "no-valid-intent"})
        return block("no-valid-pending-intent", base)

    intent_file, payload = match
    try:
        has_drift = _state_binding_has_drift(c, payload)
    except Exception as e:
        # Any unexpected state-check failure is also fail-closed for capital.
        has_drift = True
        log({**base, "event": "state-binding-error", "err": str(e)})
    if has_drift:
        try:
            invalidated = _invalidate_intent(intent_file)
            invalidated_name = invalidated.name
        except Exception as e:
            invalidated_name = None
            log({**base, "event": "state-intent-invalidation-error", "err": str(e)})
        log({
            **base,
            "decision": "enforce-block",
            "reason": "state-drift-since-review",
            "intent_file": intent_file.name,
            "invalidated_file": invalidated_name,
        })
        return block("state-drift-since-review", base)

    # consume (single-use) then allow
    try:
        intent_file.unlink()
    except Exception:
        pass
    log({**base, "decision": "enforce-allow", "intent_file": intent_file.name})
    return allow("valid-intent-consumed")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception as e:  # absolute backstop: never wedge the session
        log({"event": "hook-fatal", "err": str(e)})
        raise SystemExit(0)
