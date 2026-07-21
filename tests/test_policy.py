import tempfile
import time
import unittest
from pathlib import Path

from model_routing.breakglass import BreakGlassRecord, validate_breakglass
from model_routing.kill_switch import KillSwitchState
from model_routing.mutation import MutationRequest, evaluate_mutation


class PolicyTest(unittest.TestCase):
    def test_non_capital_can_use_env_kill_switch_but_capital_cannot(self):
        state = KillSwitchState.from_env({"DISABLE_MODEL_ROUTING": "1"})

        self.assertTrue(state.non_capital_routing_disabled)
        self.assertFalse(state.capital_gate_disabled)

    def test_capital_mutation_requires_intent(self):
        request = MutationRequest(
            action_type="shell",
            exact_action="rsync ./build prod-host-2:/opt/trading-engine",
            cwd="/home/operator/repos/trading-engine",
            repo_id="trading-engine",
            host="prod-host-2",
            target="/opt/trading-engine",
            is_capital=True,
            is_read_only=False,
            risk_class="capital-high",
        )

        decision = evaluate_mutation(request, signed_intent=None, breakglass=None)

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "missing-capital-intent")

    def test_read_only_capital_probe_passes_without_intent(self):
        request = MutationRequest(
            action_type="shell",
            exact_action="systemctl --user status signer.service",
            cwd="/home/operator/repos/trading-engine",
            repo_id="trading-engine",
            host="prod-host-2",
            target="signer.service",
            is_capital=True,
            is_read_only=True,
            risk_class="capital-read",
        )

        decision = evaluate_mutation(request, signed_intent=None, breakglass=None)

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, "read-only")

    def test_breakglass_must_be_unexpired_and_human_confirmed(self):
        record = BreakGlassRecord(
            reason="emergency signer kill path wedged",
            human="operator",
            created_at=int(time.time()) - 10,
            expires_at=int(time.time()) + 60,
            target="signer.service",
            audit_log_path="/var/log/model-routing/breakglass.log",
        )

        result = validate_breakglass(record, target="signer.service", now=int(time.time()))

        self.assertTrue(result.ok)


if __name__ == "__main__":
    unittest.main()
