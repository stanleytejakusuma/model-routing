import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_ROOT = PROJECT_ROOT / "scripts"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

import redteam_harness  # noqa: E402


class RedteamHarnessTest(unittest.TestCase):
    def test_harness_loads_example_registry(self):
        registry = object()
        replayed_registries = []

        def fake_replay_case(case, case_registry, keys):
            replayed_registries.append(case_registry)
            return SimpleNamespace(
                case_id=str(case["case_id"]),
                blocked=bool(case["should_block"]),
                stage="test",
                reason="test",
            )

        with (
            patch.object(redteam_harness, "CapitalRegistry", create=True) as registry_cls,
            patch.object(redteam_harness, "InertKeyMaterial") as keys_cls,
            patch.object(redteam_harness, "replay_case", side_effect=fake_replay_case),
            patch("builtins.print"),
        ):
            registry_cls.from_file = Mock(return_value=registry)
            keys_cls.return_value.cleanup = Mock()

            exit_code = redteam_harness.main()

        self.assertEqual(exit_code, 0)
        registry_cls.from_file.assert_called_once_with(PROJECT_ROOT / "config" / "capital-registry.example.json")
        self.assertTrue(replayed_registries)
        self.assertTrue(all(case_registry is registry for case_registry in replayed_registries))


if __name__ == "__main__":
    unittest.main()
