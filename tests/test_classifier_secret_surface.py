#!/usr/bin/env python3
"""Regression test for the capital-safety classifier's secret-surface behavior.

Freezes variant "A" (applied 2026-07-10): reads of published PUBLIC keys and
vault-prefixed ops scripts are NO LONGER gated, while real secret-file reads and
real capital mutations still block. Stdlib only; no third-party deps, no pytest
required.

Self-locating: works in the deployed tree (~/.model-routing/, registry at
<root>/capital-registry.json) and in the source repo (registry at
<root>/config/capital-registry.example.json). Run:

    python3 tests/test_classifier_secret_surface.py

The command strings below are INERT DATA — every case is only *classified*
(classify_tool_call), never executed.
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "src"))


def _registry_path() -> Path:
    for cand in (_ROOT / "capital-registry.json", _ROOT / "config" / "capital-registry.example.json"):
        if cand.exists():
            return cand
    raise SystemExit(f"capital registry not found under {_ROOT}")


from model_routing.classifier import classify_tool_call  # noqa: E402
from model_routing.registry import CapitalRegistry  # noqa: E402

REGISTRY_PATH = _registry_path()
CODEBASE = "/home/operator/repos"
ENGINE = "/home/operator/repos/trading-engine"

# MUST-ALLOW — false-positives that variant A fixed. Read-only, mutate nothing.
ALLOW_CASES = [
    ("plain cat",          "cat notes.txt",             CODEBASE),
    ("git log",            "git log --oneline -5",      ENGINE),
    ("git status",         "git status",                ENGINE),
    ("source grep",        "grep -rn foo src",          CODEBASE),
    ("public .pem",        "cat intent-public.pem",     CODEBASE),
    ("id_*.pub",           "cat id_ed25519.pub",        CODEBASE),
    ("*-public.pem",       "cat server-public.pem",     CODEBASE),
    ("vault- .sh script",  "cat vault-up.sh",           CODEBASE),
    ("vault- .sh script b","bash vault-cutover.sh",     CODEBASE),
]

# SECURITY INVARIANT — these must never flip to allow; a failure here means the capital gate regressed.
BLOCK_CASES = [
    ("private .pem",         "cat server.pem",                                   "/x"),
    ("registered key path",  "cat /home/operator/.config/trading/signer-key",    "/x"),
    (".age bundle",          "cat vault-trading.age",                            "/x"),
    ("benign+secret mix",    "tar czf b vault-up.sh vault-trading.age",          "/x"),
    ("bare vault- secret",   "cat vault-secrets",                                "/x"),
    ("scp registered path",  "scp x prod-host-1:/opt/prod-signer/foo",           "/x"),
    ("systemctl signer",     "systemctl restart signer.service",                 "/x"),
    ("path-attached signer", "cat ./keys/signer-key",                            "/x"),
]

# VARIANT-A word heuristic (NOT a security invariant): a bare secret-word source
# grep blocks under variant A. Variant B (path-attached-words) would ALLOW it — if
# B is ever adopted, flip this expectation.
A_WORD_HEURISTIC_CASES = [
    ("secret-word grep",   "grep -rn private_key src",  CODEBASE),
]


def _load_registry() -> CapitalRegistry:
    return CapitalRegistry.from_file(REGISTRY_PATH)


def _blocked(cmd: str, cwd: str, reg: CapitalRegistry) -> bool:
    """Block iff the classifier calls it a capital mutation that is not read-only
    (mirrors pretooluse_hook.main's enforce decision). Classifies only."""
    c = classify_tool_call("Bash", {"command": cmd}, Path(cwd), reg)
    return not (c.is_read_only or not c.is_capital)


# --- pytest-discoverable checks (pytest optional) ------------------------------
def test_must_allow_no_false_positives():
    reg = _load_registry()
    for name, cmd, cwd in ALLOW_CASES:
        assert _blocked(cmd, cwd, reg) is False, f"false-positive regressed: {name} :: {cmd}"


def test_security_invariant_must_block():
    reg = _load_registry()
    for name, cmd, cwd in BLOCK_CASES:
        assert _blocked(cmd, cwd, reg) is True, f"CAPITAL GATE REGRESSED: {name} no longer blocks :: {cmd}"


def test_variant_a_secret_word_grep_blocks():
    reg = _load_registry()
    for name, cmd, cwd in A_WORD_HEURISTIC_CASES:
        assert _blocked(cmd, cwd, reg) is True, f"variant-A word heuristic changed: {name} :: {cmd}"


# --- standalone runner ---------------------------------------------------------
def _run(label: str, cases, expected_block: bool, reg, results: list) -> None:
    for name, cmd, cwd in cases:
        got = _blocked(cmd, cwd, reg)
        ok = got == expected_block
        results.append(ok)
        print(f"  [{'PASS' if ok else 'FAIL'}] {label:6} expect={'BLOCK' if expected_block else 'allow':5} "
              f"got={'BLOCK' if got else 'allow':5} :: {name}")


def main() -> int:
    reg = _load_registry()
    print(f"registry: {REGISTRY_PATH}")
    results: list[bool] = []
    print("MUST-ALLOW (false-positives fixed by variant A):")
    _run("allow", ALLOW_CASES, False, reg, results)
    print("MUST-BLOCK (SECURITY INVARIANT — real secrets / mutations):")
    _run("block", BLOCK_CASES, True, reg, results)
    print("VARIANT-A word heuristic (documents current choice, not an invariant):")
    _run("A-only", A_WORD_HEURISTIC_CASES, True, reg, results)
    passed, total = sum(results), len(results)
    print(f"\n{passed}/{total} passed")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
