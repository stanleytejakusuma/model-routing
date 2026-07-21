#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

from model_routing.registry import CapitalRegistry
from runner_support import InertKeyMaterial, replay_case


def main() -> int:
    project_root = Path(__file__).resolve().parents[1]
    corpus_path = project_root / "corpus" / "shadow_actions.json"
    cases = json.loads(corpus_path.read_text(encoding="utf-8"))
    keys = InertKeyMaterial()
    try:
        registry = CapitalRegistry.from_file(project_root / "config" / "capital-registry.example.json")
        decisions = [replay_case(case, registry, keys) for case in cases]
    finally:
        keys.cleanup()

    allowed = sum(1 for decision in decisions if decision.allowed)
    blocked = sum(1 for decision in decisions if decision.blocked)
    print("SHADOW MODE: log-only; no command execution; no network; no host mutation")
    print(f"cases={len(decisions)} would_allow={allowed} would_block={blocked}")
    for decision in decisions:
        verdict = "ALLOW" if decision.allowed else "BLOCK"
        print(
            f"{verdict} {decision.case_id} "
            f"stage={decision.stage} reason={decision.reason} risk={decision.risk_class} "
            f"capital={decision.capital_reason} read_only={decision.read_only_reason}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
