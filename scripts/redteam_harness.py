#!/usr/bin/env python3
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from model_routing.redteam import RecallCase, calculate_recall
from model_routing.registry import CapitalRegistry
from runner_support import InertKeyMaterial, replay_case


HEREDOC_FIXTURE_CWD = "__model_routing_heredoc_fixture__"


def _prepare_heredoc_fixture_cases(cases: list[dict]) -> tuple[tempfile.TemporaryDirectory, list[dict]]:
    """Materialize the symlink sink needed by the inherited heredoc red-team case."""
    fixture = tempfile.TemporaryDirectory(prefix="model-routing-heredoc-redteam-")
    cwd = Path(fixture.name)
    target = cwd / "inert_exec"
    target.write_text("inert\n", encoding="utf-8")
    (cwd / "link_to_exec").symlink_to(target.name)
    prepared = [
        {**case, "cwd": fixture.name} if case.get("cwd") == HEREDOC_FIXTURE_CWD else case
        for case in cases
    ]
    return fixture, prepared


def main() -> int:
    project_root = Path(__file__).resolve().parents[1]
    corpus_path = project_root / "corpus" / "redteam_cases.json"
    cases = json.loads(corpus_path.read_text(encoding="utf-8"))
    heredoc_fixture, cases = _prepare_heredoc_fixture_cases(cases)
    keys = InertKeyMaterial()
    try:
        registry = CapitalRegistry.from_file(project_root / "config" / "capital-registry.example.json")
        decisions = [replay_case(case, registry, keys) for case in cases]
    finally:
        keys.cleanup()
        heredoc_fixture.cleanup()

    result = calculate_recall(
        RecallCase(
            case_id=str(case["case_id"]),
            should_block=bool(case["should_block"]),
            blocked=decision.blocked,
        )
        for case, decision in zip(cases, decisions)
    )
    print("REDTEAM MODE: log-only; example registry; no command execution")
    print(
        "cases={cases} known_bad={known_bad} detected_bad={detected_bad} "
        "known_good={known_good} allowed_good={allowed_good} recall={recall:.3f} "
        "precision={precision:.3f} false_negative={false_negative} false_positive={false_positive}".format(
            cases=len(decisions),
            known_bad=result.known_bad,
            detected_bad=result.detected_bad,
            known_good=result.known_good,
            allowed_good=result.allowed_good,
            recall=result.recall,
            precision=result.precision,
            false_negative=result.false_negative,
            false_positive=result.false_positive,
        )
    )
    if result.misses:
        print("MISSES " + ",".join(result.misses))
    else:
        print("MISSES none")
    for decision in decisions:
        verdict = "BLOCK" if decision.blocked else "ALLOW"
        print(f"{verdict} {decision.case_id} stage={decision.stage} reason={decision.reason}")
    return 0 if result.false_negative == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
