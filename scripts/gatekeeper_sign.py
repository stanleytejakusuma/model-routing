#!/usr/bin/env python3
"""Gatekeeper-host signer. Runs as `mr-gatekeeper` (the only identity that
can read the Ed25519 private key). Signs a capital-action intent ONLY when BOTH:
  * the Opus review in the package approved, AND
  * a human authorization is present (the --confirm flag, which the operator adds
    deliberately AFTER reviewing the action printed to stderr).

A confident-wrong agent that gets blocked does not naturally reproduce
`sudo -u mr-gatekeeper ... --confirm`, so this is the human gate for that threat
model. (An adversarial agent with sudo is out of scope here — covered by the
existing broker + out-of-band confirm as a follow-on.)

Usage (operator, after reviewing the blocked action):
  sudo -u mr-gatekeeper python3 gatekeeper_sign.py --package /path/pkg.json --confirm
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from model_routing.approval import ApprovalPackage, gatekeeper_sign_authorized  # noqa: E402
from model_routing.lifecycle import ApprovalDecision, ApprovalRequest  # noqa: E402


def _load_package(path: Path) -> ApprovalPackage:
    data = json.loads(path.read_text(encoding="utf-8"))
    req_data = dict(data["request"])
    req_data["verifier_requirements"] = tuple(req_data.get("verifier_requirements", ()))
    appr_data = dict(data["approval"])
    appr_data["defects"] = tuple(appr_data.get("defects", ()))
    return ApprovalPackage(request=ApprovalRequest(**req_data), approval=ApprovalDecision(**appr_data))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--package", required=True)
    ap.add_argument("--confirm", action="store_true", help="human authorization; add ONLY after reviewing the action")
    ap.add_argument("--private-key", default="/etc/model-routing/keys/intent-private.pem")
    ap.add_argument("--gatekeeper-user", default="mr-gatekeeper")
    ap.add_argument("--operator", default="operator")
    args = ap.parse_args()

    package = _load_package(Path(args.package))
    r = package.request
    a = package.approval

    sys.stderr.write("=== CAPITAL ACTION AWAITING SIGNATURE ===\n")
    sys.stderr.write(f"  action  : {r.action_type} :: {r.exact_action}\n")
    sys.stderr.write(f"  target  : {r.target}  (host {r.host}, risk {r.risk_class})\n")
    sys.stderr.write(f"  cwd     : {r.cwd}  repo {r.repo_id}\n")
    sys.stderr.write(f"  rollback: {r.rollback_path}\n")
    sys.stderr.write(f"  opus    : approved={a.approved} by {a.verifier_identity}/{a.verifier_version}\n")
    sys.stderr.write(f"  human   : {'CONFIRMED (--confirm)' if args.confirm else 'NOT CONFIRMED'}\n")

    outcome = gatekeeper_sign_authorized(
        package,
        private_key_path=Path(args.private_key),
        human_confirmer=lambda req, appr: args.confirm,
        operator=args.operator,
        gatekeeper_user=args.gatekeeper_user,
    )
    if not outcome.ok:
        sys.stderr.write(f"REFUSED: {outcome.reason}\n")
        return 2
    sys.stdout.write(json.dumps(outcome.signed_intent) + "\n")
    sys.stderr.write("SIGNED.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
