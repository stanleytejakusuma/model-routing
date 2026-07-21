from __future__ import annotations

import os
import pwd
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from model_routing.intents import NonceStore
from model_routing.lifecycle import (
    ApprovalDecision,
    attach_signed_intent,
    authoritative_broker_check,
    build_approval_request,
    build_signing_request,
    detect_capital_action,
    gatekeeper_sign_action,
    local_pretooluse_check,
)
from model_routing.registry import CapitalRegistry


FIXED_NOW = 1_700_000_000


@dataclass(frozen=True)
class RunnerDecision:
    case_id: str
    allowed: bool
    blocked: bool
    stage: str
    reason: str
    risk_class: str
    capital_reason: str
    read_only_reason: str


class InertKeyMaterial:
    def __init__(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.private_key_path = self.root / "keys" / "intent-private.pem"
        self.public_key_path = self.root / "keys" / "intent-public.pem"
        self.nonce_store = NonceStore(self.root / "nonces")
        self.gatekeeper_user = pwd.getpwuid(os.getuid()).pw_name
        self._write_keypair()

    def cleanup(self) -> None:
        self.tempdir.cleanup()

    def _write_keypair(self) -> None:
        self.private_key_path.parent.mkdir(parents=True, exist_ok=True)
        private_key = Ed25519PrivateKey.generate()
        self.private_key_path.write_bytes(
            private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption(),
            )
        )
        self.public_key_path.write_bytes(
            private_key.public_key().public_bytes(
                encoding=Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo,
            )
        )
        self.private_key_path.chmod(0o600)
        self.public_key_path.chmod(0o600)


def placeholder_registry(root: str) -> CapitalRegistry:
    return CapitalRegistry(
        {
            "policy_version": "placeholder-policy",
            "defaults": {"unknown_is_capital": True},
            "repos": [
                {
                    "id": "placeholder-capital",
                    "capital": True,
                    "paths": [f"/tmp/model-routing-{root}/placeholder-capital"],
                    "remotes": [],
                },
                {
                    "id": "placeholder-safe",
                    "capital": False,
                    "paths": [f"/tmp/model-routing-{root}/safe-repo", f"/tmp/model-routing-{root}/output"],
                    "remotes": [],
                },
            ],
            "services": [
                {"name": "placeholder-signer.service", "capital": True},
                {"name": "placeholder-safe.service", "capital": False},
            ],
            "vault_bundles": [{"name": "placeholder-capital", "capital": True}],
            "addresses": [
                {
                    "id": "placeholder-capital-address",
                    "value": "0x1111111111111111111111111111111111111111",
                    "capital": True,
                }
            ],
        }
    )


def replay_case(case: dict[str, Any], registry: CapitalRegistry, keys: InertKeyMaterial) -> RunnerDecision:
    detected = detect_capital_action(
        str(case["tool_name"]),
        dict(case.get("tool_input", {})),
        Path(str(case["cwd"])),
        registry,
        host=str(case.get("host", "local-placeholder.invalid")),
    )
    classification = detected.classification
    if not detected.requires_approval:
        return RunnerDecision(
            case_id=str(case["case_id"]),
            allowed=True,
            blocked=False,
            stage="classify",
            reason="not-capital-mutation",
            risk_class=classification.risk_class,
            capital_reason=classification.capital_reason,
            read_only_reason=classification.read_only_reason,
        )

    if not bool(case.get("opus_approved", False)):
        return RunnerDecision(
            case_id=str(case["case_id"]),
            allowed=False,
            blocked=True,
            stage="opus-approval",
            reason="would-request-opus-approval",
            risk_class=classification.risk_class,
            capital_reason=classification.capital_reason,
            read_only_reason=classification.read_only_reason,
        )

    approval_request = build_approval_request(
        classification,
        rollback_path="inert placeholder rollback; no live action exists",
        policy_version="placeholder-policy",
        tree_sha=f"tree-{case['case_id']}",
        parent_sha=f"parent-{case['case_id']}",
        now=FIXED_NOW,
        nonce=f"approval-request-{case['case_id']}",
    )
    signing_request = build_signing_request(
        approval_request,
        ApprovalDecision(
            approved=True,
            verifier_identity="opus-verifier-placeholder",
            verifier_version="opus-placeholder",
            approved_at=FIXED_NOW + 1,
        ),
        nonce=f"action-intent-{case['case_id']}",
        expires_at=FIXED_NOW + 300,
    )
    signed_intent = gatekeeper_sign_action(signing_request, keys.private_key_path, gatekeeper_user=keys.gatekeeper_user)
    event = attach_signed_intent(detected.event, signed_intent)
    local = local_pretooluse_check(
        event,
        registry,
        keys.public_key_path,
        now=FIXED_NOW + 2,
        gatekeeper_user=keys.gatekeeper_user,
    )
    if not local.ok:
        return _blocked_from_gate(str(case["case_id"]), local, "local-peek")
    authoritative = authoritative_broker_check(
        event,
        registry,
        keys.public_key_path,
        keys.nonce_store,
        now=FIXED_NOW + 2,
        gatekeeper_user=keys.gatekeeper_user,
    )
    if not authoritative.ok:
        return _blocked_from_gate(str(case["case_id"]), authoritative, "authoritative-consume")
    return RunnerDecision(
        case_id=str(case["case_id"]),
        allowed=True,
        blocked=False,
        stage="authoritative-consume",
        reason="signed-intent-valid",
        risk_class=classification.risk_class,
        capital_reason=classification.capital_reason,
        read_only_reason=classification.read_only_reason,
    )


def _blocked_from_gate(case_id: str, gate, fallback_stage: str) -> RunnerDecision:
    classification = gate.classification
    return RunnerDecision(
        case_id=case_id,
        allowed=False,
        blocked=True,
        stage=gate.stage or fallback_stage,
        reason=gate.reason,
        risk_class=classification.risk_class if classification else "unknown",
        capital_reason=classification.capital_reason if classification else "unknown",
        read_only_reason=classification.read_only_reason if classification else "unknown",
    )
