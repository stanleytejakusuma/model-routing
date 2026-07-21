#!/usr/bin/env python3
from __future__ import annotations


def main() -> int:
    steps = [
        (
            "Gatekeeper signer",
            "WOULD copy scripts/gatekeeper_sign.py to a reviewed gatekeeper-host-only path owned by the gatekeeper user.",
        ),
        (
            "Key custody",
            "WOULD verify the Ed25519 private key exists outside the agent-writable workspace with mode 0600 and non-agent ownership.",
        ),
        (
            "Nonce stores",
            "WOULD create separate approval and action nonce-store directories owned by the gatekeeper or broker user.",
        ),
        (
            "Local PreToolUse",
            "WOULD copy scripts/pretooluse_hook.py to a non-agent-owned hook path and point the agent-harness config at it.",
        ),
        (
            "Local hook config",
            "WOULD set MODEL_ROUTING_REGISTRY and MODEL_ROUTING_INTENT_PUBLIC_KEY to reviewed read-only paths.",
        ),
        (
            "Tamper resistance",
            "WOULD chown hook script/config to a non-agent owner and remove group/world write bits.",
        ),
        (
            "Verification",
            "WOULD run unit tests, scripts/shadow_runner.py, scripts/redteam_harness.py, and scripts/test_hook_isolation.py before any arming decision.",
        ),
    ]

    print("DRY RUN ONLY: no install, no ssh, no service changes, no chmod/chown, no hook activation")
    for index, (label, command) in enumerate(steps, start=1):
        print(f"{index}. {label}: {command}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
