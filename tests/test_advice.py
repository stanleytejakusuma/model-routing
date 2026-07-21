import unittest
from pathlib import Path

from model_routing.advice import scan_advice
from model_routing.registry import CapitalRegistry


class AdviceScannerTest(unittest.TestCase):
    def test_capital_advice_shapes_emit_unverified_label(self):
        registry = CapitalRegistry.from_file(
            Path(__file__).resolve().parents[1] / "config" / "capital-registry.example.json"
        )

        result = scan_advice(
            "Send 1250 USDC to 0x1111111111111111111111111111111111111111 with calldata 0x"
            + ("ab" * 40),
            cwd=Path("/home/operator/repos/trading-engine"),
            registry=registry,
        )

        self.assertTrue(result.detected)
        self.assertEqual(result.label, "UNVERIFIED advice")
        self.assertIn("evm-address", result.kinds)
        self.assertIn("tx-payload", result.kinds)
        self.assertIn("amount", result.kinds)
        self.assertEqual(result.payload["status"], "UNVERIFIED")


if __name__ == "__main__":
    unittest.main()
