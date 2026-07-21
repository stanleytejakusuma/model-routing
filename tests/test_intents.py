import os
import pwd
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from model_routing.intents import IntentRecord, NonceStore, sign_intent, verify_intent, verify_peek


class IntentRecordTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.gatekeeper_user = pwd.getpwuid(os.getuid()).pw_name
        self.private_key_path = self.root / "keys" / "intent-private.pem"
        self.public_key_path = self.root / "keys" / "intent-public.pem"
        self._write_keypair(self.private_key_path, self.public_key_path)
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

    def sample_intent(self, nonce="nonce-1"):
        return IntentRecord(
            action_type="shell",
            exact_action="systemctl --user restart signer.service",
            cwd="/home/operator/repos/trading-engine",
            repo_id="trading-engine",
            host="prod-host-2",
            target="signer.service",
            risk_class="capital-high",
            rollback_path="systemctl --user status signer.service; do not retry without human",
            verifier_identity="opus-verifier",
            verifier_version="opus-4.8",
            policy_version="2026-07-01.v2",
            tree_sha="abc123",
            parent_sha="def456",
            timestamp=int(time.time()),
            nonce=nonce,
            expires_at=int(time.time()) + 300,
        )

    def test_signed_intent_matches_exact_bound_action_once(self):
        signed = sign_intent(self.sample_intent(), self.private_key_path, gatekeeper_user=self.gatekeeper_user)

        result = verify_intent(
            signed,
            self.public_key_path,
            self.nonce_store,
            expected={
                "exact_action": "systemctl --user restart signer.service",
                "cwd": "/home/operator/repos/trading-engine",
                "repo_id": "trading-engine",
                "host": "prod-host-2",
                "target": "signer.service",
                "tree_sha": "abc123",
            },
            now=int(time.time()),
            gatekeeper_user=self.gatekeeper_user,
        )

        self.assertTrue(result.ok)
        replay = verify_intent(
            signed,
            self.public_key_path,
            self.nonce_store,
            expected={"exact_action": "systemctl --user restart signer.service"},
            now=int(time.time()),
            gatekeeper_user=self.gatekeeper_user,
        )
        self.assertFalse(replay.ok)
        self.assertEqual(replay.reason, "nonce-replay")

    def test_verify_peek_does_not_consume_nonce(self):
        signed = sign_intent(self.sample_intent(nonce="peek-nonce"), self.private_key_path, gatekeeper_user=self.gatekeeper_user)

        peek = verify_peek(
            signed,
            self.public_key_path,
            expected={"exact_action": "systemctl --user restart signer.service"},
            now=int(time.time()),
            gatekeeper_user=self.gatekeeper_user,
        )
        consumed = verify_intent(
            signed,
            self.public_key_path,
            self.nonce_store,
            expected={"exact_action": "systemctl --user restart signer.service"},
            now=int(time.time()),
            gatekeeper_user=self.gatekeeper_user,
        )

        self.assertTrue(peek.ok)
        self.assertTrue(consumed.ok)

    def test_changed_command_invalidates_signature_binding(self):
        signed = sign_intent(self.sample_intent(), self.private_key_path, gatekeeper_user=self.gatekeeper_user)

        result = verify_intent(
            signed,
            self.public_key_path,
            self.nonce_store,
            expected={"exact_action": "systemctl --user stop signer.service"},
            now=int(time.time()),
            gatekeeper_user=self.gatekeeper_user,
        )

        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "binding-mismatch:exact_action")

    def test_verification_cannot_be_forged_without_private_key(self):
        attacker_private = self.root / "keys" / "attacker-private.pem"
        attacker_public = self.root / "keys" / "attacker-public.pem"
        self._write_keypair(attacker_private, attacker_public)
        signed_by_attacker = sign_intent(
            self.sample_intent(nonce="attacker-forgery"),
            attacker_private,
            gatekeeper_user=self.gatekeeper_user,
        )

        result = verify_intent(
            signed_by_attacker,
            self.public_key_path,
            self.nonce_store,
            expected={"exact_action": "systemctl --user restart signer.service"},
            now=int(time.time()),
            gatekeeper_user=self.gatekeeper_user,
        )

        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "bad-signature")

    def test_concurrent_nonce_double_spend_is_blocked(self):
        signed = sign_intent(
            self.sample_intent(nonce="raced-nonce"),
            self.private_key_path,
            gatekeeper_user=self.gatekeeper_user,
        )
        barrier = Barrier(8)

        def verify_once():
            barrier.wait()
            return verify_intent(
                signed,
                self.public_key_path,
                self.nonce_store,
                expected={"exact_action": "systemctl --user restart signer.service"},
                now=int(time.time()),
                gatekeeper_user=self.gatekeeper_user,
            )

        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(lambda _: verify_once(), range(8)))

        self.assertEqual([result.ok for result in results].count(True), 1)
        self.assertEqual([result.reason for result in results].count("nonce-replay"), 7)

    def test_private_key_permissions_enforced_public_key_not_gated(self):
        # Private-key custody (0600) IS enforced at signing.
        self.private_key_path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "key-custody:mode-not-600"):
            sign_intent(self.sample_intent(), self.private_key_path, gatekeeper_user=self.gatekeeper_user)

        self.private_key_path.chmod(0o600)
        signed = sign_intent(
            self.sample_intent(nonce="public-perm-check"),
            self.private_key_path,
            gatekeeper_user=self.gatekeeper_user,
        )
        # Public key is NOT custody-gated: it must be readable by the local hook
        # and the gatekeeper-side broker, so verification succeeds even at 0644.
        self.public_key_path.chmod(0o644)

        result = verify_intent(
            signed,
            self.public_key_path,
            self.nonce_store,
            expected={"exact_action": "systemctl --user restart signer.service"},
            now=int(time.time()),
            gatekeeper_user=self.gatekeeper_user,
        )

        self.assertTrue(result.ok, result.reason)

    def test_signing_enforces_owner_public_key_verify_does_not(self):
        alternate_user = next((entry.pw_name for entry in pwd.getpwall() if entry.pw_uid != os.getuid()), None)
        if alternate_user is None:
            self.skipTest("no alternate local user available for owner-mismatch test")

        # Signing refuses when the private key is not owned by the gatekeeper.
        with self.assertRaisesRegex(ValueError, "key-custody:owner-mismatch"):
            sign_intent(self.sample_intent(), self.private_key_path, gatekeeper_user=alternate_user)

        # Verification is NOT public-key-owner-gated: a reader that is not the
        # gatekeeper (e.g. the local hook running as the agent user) still verifies.
        signed = sign_intent(
            self.sample_intent(nonce="owner-mismatch-check"),
            self.private_key_path,
            gatekeeper_user=self.gatekeeper_user,
        )
        result = verify_intent(
            signed,
            self.public_key_path,
            self.nonce_store,
            expected={"exact_action": "systemctl --user restart signer.service"},
            now=int(time.time()),
            gatekeeper_user=alternate_user,
        )

        self.assertTrue(result.ok, result.reason)


if __name__ == "__main__":
    unittest.main()
