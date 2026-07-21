#!/usr/bin/env python3
"""End-to-end signing self-test, run ON the gatekeeper host AS the gatekeeper
user with the REAL deployed key. Proves the gatekeeper can classify -> package
-> sign -> verify a capital action, and that a replay of the consumed nonce is
refused. Log-only; performs no capital action.

Paths default to the deployed layout and can be overridden via env:
  MODEL_ROUTING_PRIVATE_KEY, MODEL_ROUTING_PUBLIC_KEY,
  MODEL_ROUTING_REGISTRY, MODEL_ROUTING_GATEKEEPER_USER
"""
from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from model_routing.approval import ApprovalDecision, build_approval_package, gatekeeper_sign_authorized  # noqa: E402
from model_routing.classifier import classify_tool_call  # noqa: E402
from model_routing.intents import NonceStore, verify_intent  # noqa: E402
from model_routing.registry import CapitalRegistry  # noqa: E402

PRIV = Path(os.environ.get("MODEL_ROUTING_PRIVATE_KEY", "/etc/model-routing/keys/intent-private.pem"))
PUB = Path(os.environ.get("MODEL_ROUTING_PUBLIC_KEY", "/etc/model-routing/keys/intent-public.pem"))
REG = Path(os.environ.get(
    "MODEL_ROUTING_REGISTRY",
    str(Path(__file__).resolve().parents[1] / "config" / "capital-registry.example.json"),
))
GK = os.environ.get("MODEL_ROUTING_GATEKEEPER_USER", "mr-gatekeeper")


def main() -> int:
    reg = CapitalRegistry.from_file(REG)
    c = classify_tool_call(
        "Bash",
        {"command": "systemctl restart signer.service"},
        Path("/home/operator/repos/trading-engine"),
        reg,
    )
    print(f"classify: is_capital={c.is_capital} is_read_only={c.is_read_only} target={c.target}")
    assert c.is_capital and not c.is_read_only, "expected capital mutation"

    pkg = build_approval_package(
        c,
        policy_version="gatekeeper-selftest",
        opus_reviewer=lambda req: ApprovalDecision(True, "selftest-reviewer", "v1", int(time.time())),
    )
    out = gatekeeper_sign_authorized(
        pkg,
        private_key_path=PRIV,
        human_confirmer=lambda r, a: True,
        operator="selftest-operator",
        gatekeeper_user=GK,
    )
    print(f"sign: ok={out.ok} reason={out.reason}")
    assert out.ok, out.reason

    exp = {
        "action_type": c.action_type,
        "exact_action": c.exact_action,
        "cwd": c.cwd,
        "repo_id": c.repo_id or "unknown",
        "host": c.host,
        "target": c.target,
        "risk_class": c.risk_class,
    }
    ns = NonceStore(Path(tempfile.mkdtemp()) / "nonces")
    v = verify_intent(out.signed_intent, PUB, ns, exp, now=int(time.time()), gatekeeper_user=GK)
    print(f"verify: ok={v.ok} reason={v.reason}")
    assert v.ok, v.reason

    # Nonce is now consumed: a replay must fail.
    v2 = verify_intent(out.signed_intent, PUB, ns, exp, now=int(time.time()), gatekeeper_user=GK)
    print(f"replay: ok={v2.ok} reason={v2.reason} (expect ok=False nonce-replay)")
    assert not v2.ok and v2.reason == "nonce-replay", "replay should be refused"

    print("GATEKEEPER-SIGNING-SELFTEST: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
