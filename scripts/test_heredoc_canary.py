#!/usr/bin/env python3
"""Execute only allowed heredoc authoring cases behind inert service-manager shims."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "corpus" / "heredoc_fp_cases.json"


def _write_canary_shim(path: Path) -> None:
    path.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' \"$0 $*\" >> \"$MODEL_ROUTING_CANARY_LOG\"\n",
        encoding="utf-8",
    )
    path.chmod(0o700)


def main() -> int:
    cases = json.loads(CORPUS.read_text(encoding="utf-8"))["must_allow"]
    if any("<SVC>" in case["cmd"] for case in cases):
        print("HEREDOC-CANARY: FAIL (unreplaced service placeholder)")
        return 1

    with tempfile.TemporaryDirectory(prefix="model-routing-heredoc-") as temp_dir:
        sandbox = Path(temp_dir)
        shim_dir = sandbox / "bin"
        shim_dir.mkdir()
        canary_log = sandbox / "service-manager-canary.log"
        for command in ("systemctl", "docker"):
            _write_canary_shim(shim_dir / command)

        # Fixtures referenced by blocked cases remain inert if this corpus grows.
        target = sandbox / "inert_exec"
        target.write_text("inert\n", encoding="utf-8")
        (sandbox / "link_to_exec").symlink_to(target.name)
        os.mkfifo(sandbox / "fifo_sink")

        env = dict(os.environ)
        env["PATH"] = f"{shim_dir}{os.pathsep}{env.get('PATH', '')}"
        env["MODEL_ROUTING_CANARY_LOG"] = str(canary_log)
        for case in cases:
            completed = subprocess.run(
                ["bash", "-c", case["cmd"]],
                cwd=sandbox,
                env=env,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if completed.returncode != 0:
                print(f"HEREDOC-CANARY: FAIL ({case['id']} exited {completed.returncode})")
                return 1

        if canary_log.exists() and canary_log.read_text(encoding="utf-8"):
            print("HEREDOC-CANARY: FAIL (service-manager canary invoked)")
            return 1

    print(f"HEREDOC-CANARY: PASS ({len(cases)}/{len(cases)}; canary log empty)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
