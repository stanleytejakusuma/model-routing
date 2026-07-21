import os
import pwd
import tempfile
import time
import unittest
from pathlib import Path

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


PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_REGISTRY_PATH = PROJECT_ROOT / "config" / "capital-registry.example.json"


class LifecycleTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.gatekeeper_user = pwd.getpwuid(os.getuid()).pw_name
        self.private_key_path = self.root / "keys" / "intent-private.pem"
        self.public_key_path = self.root / "keys" / "intent-public.pem"
        self._write_keypair(self.private_key_path, self.public_key_path)
        self.registry = CapitalRegistry(
            {
                "policy_version": "test-policy",
                "defaults": {"unknown_is_capital": True},
                "repos": [
                    {
                        "id": "placeholder-capital",
                        "capital": True,
                        "paths": [str(self.root / "placeholder-capital")],
                        "remotes": [],
                    },
                    {
                        "id": "placeholder-safe",
                        "capital": False,
                        "paths": [str(self.root / "safe-repo")],
                        "remotes": [],
                    },
                ],
                "services": [{"name": "placeholder-signer.service", "capital": True}],
                "vault_bundles": [],
                "addresses": [],
            }
        )
        self.capital_cwd = self.root / "placeholder-capital"
        self.capital_cwd.mkdir()
        self.nonce_store = NonceStore(self.root / "nonces")

    def tearDown(self):
        self.tempdir.cleanup()

    def _write_keypair(self, private_key_path, public_key_path):
        private_key_path.parent.mkdir(parents=True, exist_ok=True)
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        private_key_path.write_bytes(
            private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption(),
            )
        )
        public_key_path.write_bytes(
            public_key.public_bytes(
                encoding=Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo,
            )
        )
        private_key_path.chmod(0o600)
        public_key_path.chmod(0o600)

    def _approved_signed_event(self, command="systemctl restart placeholder-signer.service"):
        detected = detect_capital_action(
            "Bash",
            {"command": command},
            self.capital_cwd,
            self.registry,
            host="placeholder-host.invalid",
        )
        approval_request = build_approval_request(
            detected.classification,
            rollback_path="dry-run only; no retry without human approval",
            policy_version="test-policy",
            tree_sha="tree-placeholder",
            parent_sha="parent-placeholder",
            now=1_700_000_000,
            nonce="approval-request-nonce",
        )
        signing_request = build_signing_request(
            approval_request,
            ApprovalDecision(
                approved=True,
                verifier_identity="opus-verifier-placeholder",
                verifier_version="opus-placeholder",
                approved_at=1_700_000_010,
            ),
            nonce="action-intent-nonce",
            expires_at=1_700_000_300,
        )
        signed = gatekeeper_sign_action(signing_request, self.private_key_path, gatekeeper_user=self.gatekeeper_user)
        return attach_signed_intent(detected.event, signed)

    def test_approved_capital_action_passes_local_peek_then_authoritative_consume(self):
        event = self._approved_signed_event()

        local = local_pretooluse_check(
            event,
            self.registry,
            self.public_key_path,
            now=1_700_000_020,
            gatekeeper_user=self.gatekeeper_user,
        )
        first_authoritative = authoritative_broker_check(
            event,
            self.registry,
            self.public_key_path,
            self.nonce_store,
            now=1_700_000_020,
            gatekeeper_user=self.gatekeeper_user,
        )
        replay_authoritative = authoritative_broker_check(
            event,
            self.registry,
            self.public_key_path,
            self.nonce_store,
            now=1_700_000_020,
            gatekeeper_user=self.gatekeeper_user,
        )

        self.assertTrue(local.ok)
        self.assertEqual(local.stage, "local-peek")
        self.assertTrue(first_authoritative.ok)
        self.assertEqual(first_authoritative.stage, "authoritative-consume")
        self.assertFalse(replay_authoritative.ok)
        self.assertEqual(replay_authoritative.reason, "invalid-capital-intent:nonce-replay")

    def test_missing_signed_intent_blocks_capital_mutation(self):
        detected = detect_capital_action(
            "Bash",
            {"command": "systemctl restart placeholder-signer.service"},
            self.capital_cwd,
            self.registry,
            host="placeholder-host.invalid",
        )

        decision = local_pretooluse_check(detected.event, self.registry, self.public_key_path, now=1_700_000_020)

        self.assertFalse(decision.ok)
        self.assertEqual(decision.stage, "local-peek")
        self.assertEqual(decision.reason, "missing-capital-intent")

    def test_unapproved_opus_decision_never_builds_signing_request(self):
        detected = detect_capital_action(
            "Bash",
            {"command": "systemctl restart placeholder-signer.service"},
            self.capital_cwd,
            self.registry,
            host="placeholder-host.invalid",
        )
        approval_request = build_approval_request(
            detected.classification,
            rollback_path="dry-run only",
            policy_version="test-policy",
            tree_sha="tree-placeholder",
            parent_sha="parent-placeholder",
            now=int(time.time()),
            nonce="approval-request-nonce",
        )

        with self.assertRaisesRegex(PermissionError, "opus-approval-rejected"):
            build_signing_request(
                approval_request,
                ApprovalDecision(
                    approved=False,
                    verifier_identity="opus-verifier-placeholder",
                    verifier_version="opus-placeholder",
                    approved_at=int(time.time()),
                    defects=("rollback path insufficient",),
                ),
            )

    def test_signed_intent_bound_to_original_command_rejects_changed_action(self):
        event = self._approved_signed_event()
        changed = dict(event)
        changed["tool_input"] = {"command": "systemctl stop placeholder-signer.service"}

        decision = local_pretooluse_check(
            changed,
            self.registry,
            self.public_key_path,
            now=1_700_000_020,
            gatekeeper_user=self.gatekeeper_user,
        )

        self.assertFalse(decision.ok)
        self.assertEqual(decision.reason, "invalid-capital-intent:binding-mismatch:exact_action")


class ExampleRegistryPolicyTest(unittest.TestCase):
    def setUp(self):
        self.registry = CapitalRegistry.from_file(EXAMPLE_REGISTRY_PATH)

    def _local_decision(self, command, cwd, host="local"):
        detected = detect_capital_action(
            "Bash",
            {"command": command},
            Path(cwd),
            self.registry,
            host=host,
        )
        decision = local_pretooluse_check(
            detected.event,
            self.registry,
            public_key_path=Path("/tmp/model-routing-test-public-key.pem"),
            now=1_700_000_020,
        )
        return detected, decision

    def test_reading_capital_signer_key_file_from_non_capital_cwd_blocks(self):
        detected, decision = self._local_decision(
            "cat /home/operator/.config/trading/signer-key",
            "/home/operator/repos/research",
        )

        self.assertTrue(detected.classification.is_capital)
        self.assertTrue(detected.requires_approval)
        self.assertFalse(decision.ok)
        self.assertEqual(decision.reason, "missing-capital-intent")

    def test_capital_service_status_read_is_still_allowed(self):
        detected, decision = self._local_decision(
            "systemctl status signer.service",
            "/home/operator/repos/research",
        )

        self.assertFalse(detected.classification.is_capital)
        self.assertFalse(detected.requires_approval)
        self.assertTrue(decision.ok)
        self.assertEqual(decision.reason, "not-capital-mutation")

    def test_registered_non_capital_repo_local_mutation_is_allowed(self):
        detected, decision = self._local_decision(
            "python3 build.py",
            "/home/operator/repos/research",
        )

        self.assertFalse(detected.classification.is_capital)
        self.assertFalse(detected.requires_approval)
        self.assertTrue(decision.ok)

    def test_unknown_repo_local_dev_is_allowed(self):
        # Triggers-only: a dev command in an unregistered repo is authoring, not a
        # trigger -> non-capital -> allowed.
        detected, decision = self._local_decision(
            "python3 build.py",
            "/home/operator/repos/unregistered-repo",
        )

        self.assertFalse(detected.classification.is_capital)
        self.assertFalse(detected.requires_approval)
        self.assertTrue(decision.ok)

    def test_capital_service_mutation_from_non_capital_cwd_blocks(self):
        detected, decision = self._local_decision(
            "systemctl restart signer.service",
            "/home/operator/repos/research",
        )

        self.assertTrue(detected.classification.is_capital)
        self.assertEqual(detected.classification.capital_reason, "capital-service-mutation")
        self.assertTrue(detected.requires_approval)
        self.assertFalse(decision.ok)

    def test_generic_command_on_capital_host_is_not_gated(self):
        # Triggers-only: a generic dev command that merely targets a capital host is
        # NOT a trigger by itself; only enumerated triggers gate, and those are
        # detected in the command string regardless of host.
        detected, decision = self._local_decision(
            "python3 build.py",
            "/home/operator/repos/research",
            host="prod-host-2",
        )

        self.assertFalse(detected.classification.is_capital)
        self.assertFalse(detected.requires_approval)
        self.assertTrue(decision.ok)

    def test_live_exchange_api_mutation_from_non_capital_cwd_blocks(self):
        detected, decision = self._local_decision(
            "curl -X POST https://api.exchange.example/api/v3/order",
            "/home/operator/repos/research",
        )

        self.assertFalse(detected.classification.is_read_only)
        self.assertTrue(detected.classification.is_capital)
        self.assertEqual(detected.classification.capital_reason, "capital-cex-order")
        self.assertTrue(detected.requires_approval)
        self.assertFalse(decision.ok)
        self.assertEqual(decision.reason, "missing-capital-intent")

    def test_read_only_market_data_host_from_non_capital_cwd_is_allowed(self):
        detected, decision = self._local_decision(
            "curl https://data.exchange.example/data/spot/daily/klines/BTCUSDT/1m/file.zip",
            "/home/operator/repos/research",
        )

        self.assertFalse(detected.classification.is_read_only)
        self.assertFalse(detected.classification.is_capital)
        self.assertFalse(detected.requires_approval)
        self.assertTrue(decision.ok)
        self.assertEqual(decision.reason, "not-capital-mutation")

    def test_unregistered_network_host_from_non_capital_cwd_is_allowed(self):
        detected, decision = self._local_decision(
            "curl https://example.com/some/public/page",
            "/home/operator/repos/research",
        )

        self.assertFalse(detected.classification.is_read_only)
        self.assertFalse(detected.classification.is_capital)
        self.assertFalse(detected.requires_approval)
        self.assertTrue(decision.ok)
        self.assertEqual(decision.reason, "not-capital-mutation")


if __name__ == "__main__":
    unittest.main()
