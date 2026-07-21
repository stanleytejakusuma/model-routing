import json
import tempfile
import unittest
from pathlib import Path

from model_routing.classifier import classify_tool_call
from model_routing.registry import CapitalRegistry


class ClassifierTest(unittest.TestCase):
    def write_registry(self, payload):
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        with handle:
            json.dump(payload, handle)
        return Path(handle.name)

    def non_capital_registry(self):
        return CapitalRegistry.from_file(
            self.write_registry(
                {
                    "policy_version": "test",
                    "defaults": {"unknown_is_capital": False},
                    "repos": [
                        {
                            "id": "paper-repo",
                            "capital": False,
                            "paths": ["/safe/repo"],
                            "remotes": [],
                        }
                    ],
                    "services": [],
                    "vault_bundles": [],
                    "addresses": [],
                    "capital_hosts": [],
                    "vault_surfaces": [
                        {"suffix": ".age", "capital": True},
                        {"prefix": "vault-", "capital": True},
                    ],
                }
            )
        )

    def test_unknown_bash_command_is_non_capital_triggers_only(self):
        # Triggers-only: an unknown command matching no trigger is non-capital, even
        # when the registry still declares unknown_is_capital=True (the classifier no
        # longer escalates on 'unknown' — it gates only enumerated triggers).
        registry = CapitalRegistry.from_file(
            self.write_registry(
                {
                    "policy_version": "test",
                    "defaults": {"unknown_is_capital": True},
                    "repos": [],
                    "services": [],
                    "vault_bundles": [],
                    "addresses": [],
                    "capital_hosts": [],
                    "vault_surfaces": [],
                }
            )
        )

        result = classify_tool_call(
            tool_name="Bash",
            payload={"command": "custom-diagnostic --dry-run maybe"},
            cwd=Path("/unregistered/repo"),
            registry=registry,
        )

        self.assertFalse(result.is_read_only)
        self.assertFalse(result.is_capital)
        self.assertEqual(result.read_only_reason, "not-in-read-only-allowlist")
        self.assertEqual(result.capital_reason, "non-capital")

    def test_newline_joined_read_only_prefix_is_mutating_non_capital_in_registered_non_capital_repo(self):
        result = classify_tool_call(
            tool_name="Bash",
            payload={"command": "git log\nssh deploy@host systemctl restart unknown.service"},
            cwd=Path("/safe/repo"),
            registry=self.non_capital_registry(),
        )

        self.assertFalse(result.is_read_only)
        self.assertFalse(result.is_capital)
        self.assertEqual(result.read_only_reason, "shell-control-not-allowlisted")

    def test_single_ampersand_joined_read_only_prefix_is_mutating_non_capital_in_registered_non_capital_repo(self):
        result = classify_tool_call(
            tool_name="Bash",
            payload={"command": "git log & ssh deploy@host systemctl restart unknown.service"},
            cwd=Path("/safe/repo"),
            registry=self.non_capital_registry(),
        )

        self.assertFalse(result.is_read_only)
        self.assertFalse(result.is_capital)
        self.assertEqual(result.read_only_reason, "shell-control-not-allowlisted")

    def test_unknown_mutating_service_is_non_capital_from_registered_non_capital_cwd(self):
        result = classify_tool_call(
            tool_name="Bash",
            payload={"command": "systemctl restart unknown-worker.service"},
            cwd=Path("/safe/repo"),
            registry=self.non_capital_registry(),
        )

        self.assertFalse(result.is_read_only)
        self.assertFalse(result.is_capital)
        self.assertEqual(result.capital_reason, "non-capital")

    def test_unknown_mutating_ssh_target_is_non_capital_from_registered_non_capital_cwd(self):
        result = classify_tool_call(
            tool_name="Bash",
            payload={"command": "ssh deploy@new-host touch /tmp/marker"},
            cwd=Path("/safe/repo"),
            registry=self.non_capital_registry(),
        )

        self.assertFalse(result.is_read_only)
        self.assertFalse(result.is_capital)
        self.assertEqual(result.capital_reason, "non-capital")

    def test_journalctl_is_not_read_only_allowlisted(self):
        result = classify_tool_call(
            tool_name="Bash",
            payload={"command": "journalctl -u app.service --vacuum-time=1d"},
            cwd=Path("/safe/repo"),
            registry=self.non_capital_registry(),
        )

        self.assertFalse(result.is_read_only)
        self.assertEqual(result.read_only_reason, "not-in-read-only-allowlist")

    def test_mutation_inside_registered_non_capital_repo_is_non_capital(self):
        result = classify_tool_call(
            tool_name="Bash",
            payload={"command": "touch marker.txt"},
            cwd=Path("/safe/repo"),
            registry=self.non_capital_registry(),
        )

        self.assertFalse(result.is_read_only)
        self.assertFalse(result.is_capital)
        self.assertEqual(result.capital_reason, "non-capital")

    def test_capital_host_does_not_gate_a_read_triggers_only(self):
        registry = CapitalRegistry.from_file(
            self.write_registry(
                {
                    "policy_version": "test",
                    "defaults": {"unknown_is_capital": True},
                    "repos": [
                        {
                            "id": "paper-repo",
                            "capital": False,
                            "paths": ["/safe/repo"],
                            "remotes": [],
                        }
                    ],
                    "services": [],
                    "vault_bundles": [],
                    "addresses": [],
                    "capital_hosts": ["prod-host-1", "prod-host-2"],
                    "vault_surfaces": [],
                }
            )
        )

        result = classify_tool_call(
            tool_name="Bash",
            payload={"command": "systemctl status metrics-gateway.service"},
            cwd=Path("/safe/repo"),
            registry=registry,
            host="prod-host-2",
        )

        self.assertTrue(result.is_read_only)
        self.assertFalse(result.is_capital)
        self.assertEqual(result.capital_reason, "non-capital")

    def test_age_file_surface_is_capital_even_in_non_capital_repo(self):
        result = classify_tool_call(
            tool_name="Bash",
            payload={"command": "cat /safe/repo/vaults/local-test.age"},
            cwd=Path("/safe/repo"),
            registry=self.non_capital_registry(),
        )

        self.assertFalse(result.is_read_only)
        self.assertTrue(result.is_capital)
        self.assertEqual(result.capital_reason, "capital-secret-surface")
        self.assertEqual(result.risk_class, "capital-secret")

    def test_vault_prefixed_name_is_capital_even_in_non_capital_repo(self):
        result = classify_tool_call(
            tool_name="Bash",
            payload={"command": "ls vault-trading"},
            cwd=Path("/safe/repo"),
            registry=self.non_capital_registry(),
        )

        self.assertFalse(result.is_read_only)
        self.assertTrue(result.is_capital)
        self.assertEqual(result.capital_reason, "capital-secret-surface")

    def test_address_env_reference_without_transfer_is_non_capital(self):
        registry = CapitalRegistry.from_file(
            self.write_registry(
                {
                    "policy_version": "test",
                    "defaults": {"unknown_is_capital": True},
                    "repos": [
                        {
                            "id": "paper-repo",
                            "capital": False,
                            "paths": ["/safe/repo"],
                            "remotes": [],
                        }
                    ],
                    "services": [],
                    "vault_bundles": [],
                    "addresses": [{"id": "safe", "env": "TRADING_SAFE_ADDRESS", "capital": True}],
                    "capital_hosts": [],
                    "vault_surfaces": [],
                }
            )
        )

        # Searching docs for the env NAME is authoring/read — no transfer intent.
        result = classify_tool_call(
            tool_name="Bash",
            payload={"command": "rg TRADING_SAFE_ADDRESS /safe/repo/docs"},
            cwd=Path("/safe/repo"),
            registry=registry,
        )

        self.assertTrue(result.is_read_only)
        self.assertFalse(result.is_capital)
        self.assertEqual(result.capital_reason, "non-capital")

    def test_address_env_with_transfer_intent_is_capital(self):
        registry = CapitalRegistry.from_file(
            self.write_registry(
                {
                    "policy_version": "test",
                    "defaults": {"unknown_is_capital": False},
                    "repos": [{"id": "paper-repo", "capital": False, "paths": ["/safe/repo"], "remotes": []}],
                    "services": [],
                    "vault_bundles": [],
                    "addresses": [{"id": "safe", "env": "TRADING_SAFE_ADDRESS", "capital": True}],
                    "capital_hosts": [],
                    "vault_surfaces": [],
                }
            )
        )

        # A transfer verb + a capital address reference IS a trigger.
        result = classify_tool_call(
            tool_name="Bash",
            payload={"command": "cast send $TRADING_SAFE_ADDRESS --value 1ether"},
            cwd=Path("/safe/repo"),
            registry=registry,
        )

        self.assertFalse(result.is_read_only)
        self.assertTrue(result.is_capital)
        self.assertEqual(result.capital_reason, "capital-address-op")


if __name__ == "__main__":
    unittest.main()
