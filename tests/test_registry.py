import json
import tempfile
import unittest
from pathlib import Path

from model_routing.registry import CapitalRegistry


EXAMPLE_REGISTRY = Path(__file__).resolve().parents[1] / "config" / "capital-registry.example.json"


def _normalized(path: str) -> Path:
    return Path(str(Path(path).expanduser().resolve(strict=False)))


class CapitalRegistryTest(unittest.TestCase):
    def write_registry(self, payload):
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        with handle:
            json.dump(payload, handle)
        return Path(handle.name)

    def test_example_registry_marks_known_capital_repos(self):
        registry = CapitalRegistry.from_file(EXAMPLE_REGISTRY)

        self.assertTrue(registry.classify_path(Path("/home/operator/repos/trading-engine")).is_capital)
        self.assertTrue(registry.classify_path(Path("/home/operator/repos/trading-engine/packages/signer")).is_capital)
        self.assertTrue(registry.classify_path(Path("/home/operator/repos/trading-engine/packages/keeper")).is_capital)

    def test_example_registry_marks_known_non_capital_repos(self):
        registry = CapitalRegistry.from_file(EXAMPLE_REGISTRY)

        self.assertFalse(registry.classify_path(Path("/home/operator/repos/research")).is_capital)
        self.assertFalse(registry.classify_path(Path("/home/operator/repos/market-data")).is_capital)
        self.assertFalse(registry.classify_path(Path("/home/operator/repos/tools")).is_capital)

    def test_example_registry_knows_capital_hosts_and_address_env_names(self):
        registry = CapitalRegistry.from_file(EXAMPLE_REGISTRY)

        self.assertTrue(registry.is_capital_host("prod-host-1"))
        self.assertTrue(registry.is_capital_host("prod-host-2"))
        self.assertTrue(registry.is_capital_address_env_name("TRADING_SAFE_ADDRESS"))
        self.assertTrue(registry.is_capital_address_env_name("TRADING_VAULT_ADDRESS"))

    def test_example_registry_binds_capital_services_to_their_source_repos(self):
        registry = CapitalRegistry.from_file(EXAMPLE_REGISTRY)
        engine = _normalized("/home/operator/repos/trading-engine")
        engine_services = (
            "signer.service",
            "order-keeper.service",
            "cosigner-keeper.service",
            "live-trader",
            "order-router",
        )
        for service in engine_services:
            with self.subTest(service=service):
                self.assertEqual(registry.repo_for_service(service), engine)

        self.assertIsNone(registry.repo_for_service("vault_agent.service"))
        self.assertIsNone(registry.repo_for_service("dashboard.service"))

    def test_example_registry_knows_capital_network_targets(self):
        registry = CapitalRegistry.from_file(EXAMPLE_REGISTRY)

        self.assertTrue(registry.is_capital_network_target("api.exchange.example"))
        self.assertTrue(registry.is_capital_network_target("futures.exchange.example"))
        self.assertFalse(registry.is_capital_network_target("data.exchange.example"))
        self.assertFalse(registry.is_capital_network_target("github.com"))

    def test_example_registry_does_not_hardcode_raw_addresses(self):
        payload = json.loads(EXAMPLE_REGISTRY.read_text(encoding="utf-8"))

        for entry in payload["addresses"]:
            self.assertNotIn("value", entry)
            self.assertIn("env", entry)

    def test_unknown_defaults_to_capital(self):
        registry_path = self.write_registry(
            {
                "policy_version": "test",
                "defaults": {"unknown_is_capital": True},
                "repos": [],
                "services": [],
                "vault_bundles": [],
                "addresses": [],
                "capital_hosts": [],
            }
        )

        registry = CapitalRegistry.from_file(registry_path)
        result = registry.classify_path(Path("/unregistered/repo"))

        self.assertTrue(result.is_capital)
        self.assertEqual(result.reason, "unknown-default-capital")


if __name__ == "__main__":
    unittest.main()
