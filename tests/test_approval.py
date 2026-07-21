import os
import pwd
import tempfile
import time
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from model_routing.approval import (
    ApprovalDecision,
    build_approval_package,
    gatekeeper_sign_authorized,
    placeholder_opus_reviewer,
)
from model_routing.classifier import classify_tool_call
from model_routing.intents import NonceStore, verify_intent, verify_peek
from model_routing.registry import CapitalRegistry

REPO = Path(__file__).resolve().parents[1]


def approving_reviewer(request):
    return ApprovalDecision(True, "test-opus", "v1", int(time.time()))


def expected_from(c):
    return {
        "action_type": c.action_type,
        "exact_action": c.exact_action,
        "cwd": c.cwd,
        "repo_id": c.repo_id or "unknown",
        "host": c.host,
        "target": c.target,
        "risk_class": c.risk_class,
    }


class ApprovalLoopTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.priv = root / "gk-private.pem"
        self.pub = root / "gk-public.pem"
        key = Ed25519PrivateKey.generate()
        self.priv.write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
        self.pub.write_bytes(key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
        self.priv.chmod(0o600)
        self.pub.chmod(0o600)
        self.user = pwd.getpwuid(os.getuid()).pw_name
        self.nonces = NonceStore(root / "nonces")
        reg = CapitalRegistry.from_file(REPO / "config" / "capital-registry.example.json")
        self.classification = classify_tool_call(
            "Bash",
            {"command": "systemctl restart signer.service"},
            Path("/home/operator/repos/trading-engine"),
            reg,
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_action_is_capital_and_requires_approval(self):
        self.assertTrue(self.classification.is_capital)
        self.assertFalse(self.classification.is_read_only)

    def test_opus_rejection_blocks_signing(self):
        pkg = build_approval_package(self.classification, policy_version="test", opus_reviewer=placeholder_opus_reviewer)
        self.assertFalse(pkg.approved)
        out = gatekeeper_sign_authorized(
            pkg, private_key_path=self.priv, human_confirmer=lambda r, a: True, operator=self.user, gatekeeper_user=self.user
        )
        self.assertFalse(out.ok)
        self.assertEqual(out.reason, "opus-rejected")
        self.assertIsNone(out.signed_intent)

    def test_no_human_confirmation_no_signature(self):
        pkg = build_approval_package(self.classification, policy_version="test", opus_reviewer=approving_reviewer)
        self.assertTrue(pkg.approved)
        out = gatekeeper_sign_authorized(
            pkg, private_key_path=self.priv, human_confirmer=lambda r, a: False, operator=self.user, gatekeeper_user=self.user
        )
        self.assertFalse(out.ok)
        self.assertEqual(out.reason, "human-declined")
        self.assertIsNone(out.signed_intent)

    def test_full_approval_yields_intent_passing_both_gates(self):
        pkg = build_approval_package(self.classification, policy_version="test", opus_reviewer=approving_reviewer)
        out = gatekeeper_sign_authorized(
            pkg, private_key_path=self.priv, human_confirmer=lambda r, a: True, operator=self.user, gatekeeper_user=self.user
        )
        self.assertTrue(out.ok, out.reason)
        self.assertIsNotNone(out.signed_intent)
        self.assertEqual(out.human_token.request_id, pkg.request.request_id)
        exp = expected_from(self.classification)
        now = int(time.time())
        peek = verify_peek(out.signed_intent, self.pub, exp, now=now, gatekeeper_user=self.user)
        self.assertTrue(peek.ok, peek.reason)
        consume = verify_intent(out.signed_intent, self.pub, self.nonces, exp, now=now, gatekeeper_user=self.user)
        self.assertTrue(consume.ok, consume.reason)

    def test_pre_blessed_skips_review_but_stays_capital_and_needs_confirm(self):
        reg = CapitalRegistry.from_file(REPO / "config" / "capital-registry.example.json")
        cmd = "systemctl restart signer.service"
        # Still classified capital -> the hook still blocks it without a signed intent.
        c = classify_tool_call("Bash", {"command": cmd}, __import__("pathlib").Path("/home/operator/repos/trading-engine"), reg)
        self.assertTrue(c.is_capital)
        self.assertFalse(c.is_read_only)
        # Exact match only — a near-miss or a different service is NOT pre-blessed.
        self.assertTrue(reg.is_pre_blessed(cmd))
        self.assertFalse(reg.is_pre_blessed(cmd + " --now"))
        self.assertFalse(reg.is_pre_blessed("systemctl restart order-keeper.service"))
        # Pre-blessed reviewer auto-approves (skips Opus) ...
        pre_blessed = lambda req: ApprovalDecision(True, "owner-pre-blessed", "registry", int(time.time()))
        pkg = build_approval_package(c, policy_version="test", opus_reviewer=pre_blessed)
        self.assertTrue(pkg.approved)
        # ... but a signature STILL requires the human confirm.
        denied = gatekeeper_sign_authorized(
            pkg, private_key_path=self.priv, human_confirmer=lambda r, a: False, operator=self.user, gatekeeper_user=self.user
        )
        self.assertFalse(denied.ok)
        self.assertEqual(denied.reason, "human-declined")
        ok = gatekeeper_sign_authorized(
            pkg, private_key_path=self.priv, human_confirmer=lambda r, a: True, operator=self.user, gatekeeper_user=self.user
        )
        self.assertTrue(ok.ok, ok.reason)


if __name__ == "__main__":
    unittest.main()
