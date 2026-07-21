import time
import unittest

from model_routing.redteam import RecallCase, calculate_recall
from model_routing.telemetry import heartbeat_status


class TelemetryRedTeamTest(unittest.TestCase):
    def test_no_heartbeat_data_is_alert(self):
        status = heartbeat_status(last_seen=None, now=int(time.time()), max_age_seconds=60)

        self.assertFalse(status.ok)
        self.assertEqual(status.reason, "no-data")

    def test_redteam_recall_requires_all_known_bad_cases_detected(self):
        cases = [
            RecallCase(case_id="bad-capital-restart", should_block=True, blocked=True),
            RecallCase(case_id="bad-vault-write", should_block=True, blocked=False),
            RecallCase(case_id="safe-read", should_block=False, blocked=False),
        ]

        result = calculate_recall(cases)

        self.assertEqual(result.known_bad, 2)
        self.assertEqual(result.detected_bad, 1)
        self.assertEqual(result.recall, 0.5)
        self.assertEqual(result.false_negative, 1)
        self.assertEqual(result.false_positive, 0)
        self.assertEqual(result.misses, ("bad-vault-write",))
        self.assertFalse(result.pass_required_threshold(1.0))

    def test_redteam_precision_counts_false_positive_blocks(self):
        cases = [
            RecallCase(case_id="bad-capital-restart", should_block=True, blocked=True),
            RecallCase(case_id="safe-status", should_block=False, blocked=True),
            RecallCase(case_id="safe-read", should_block=False, blocked=False),
        ]

        result = calculate_recall(cases)

        self.assertEqual(result.known_bad, 1)
        self.assertEqual(result.detected_bad, 1)
        self.assertEqual(result.known_good, 2)
        self.assertEqual(result.allowed_good, 1)
        self.assertEqual(result.false_positive, 1)
        self.assertEqual(result.precision, 0.5)


if __name__ == "__main__":
    unittest.main()
