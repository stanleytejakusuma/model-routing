import json
import os
import tempfile
import unittest
from pathlib import Path

from model_routing.classifier import _heredoc_authoring_scan, classify_tool_call
from model_routing.registry import CapitalRegistry


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "corpus" / "heredoc_fp_cases.json"
REGISTRY = ROOT / "config" / "capital-registry.example.json"


class HeredocClassifierTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = json.loads(CORPUS.read_text(encoding="utf-8"))
        cls.registry = CapitalRegistry.from_file(REGISTRY)

    def test_adversarial_corpus_has_required_verdicts(self):
        self.assertNotIn("<SVC>", CORPUS.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as temp_dir:
            cwd = Path(temp_dir)
            target = cwd / "inert_exec"
            target.write_text("inert\n", encoding="utf-8")
            (cwd / "link_to_exec").symlink_to(target.name)
            os.mkfifo(cwd / "fifo_sink")

            for expected_capital, group in ((True, "must_block"), (False, "must_allow")):
                for case in self.cases[group]:
                    with self.subTest(case_id=case["id"]):
                        result = classify_tool_call(
                            "Bash", {"command": case["cmd"]}, cwd, self.registry
                        )
                        self.assertEqual(result.is_capital, expected_capital, case["why"])

    def test_secret_surface_sink_keeps_full_scan(self):
        command = (
            "cat > vault-trading.age <<'EOF'\n"
            "systemctl restart signer.service\n"
            "EOF"
        )
        result = classify_tool_call("Bash", {"command": command}, Path("/tmp"), self.registry)
        self.assertTrue(result.is_capital)
        self.assertEqual(result.capital_reason, "capital-secret-surface")

    def test_helper_reduces_only_the_exact_authoring_shape(self):
        accepted = (
            "cat > spec.md <<'EOF'\n"
            "systemctl restart signer.service\n"
            "EOF"
        )
        self.assertEqual(
            _heredoc_authoring_scan(accepted, Path("/tmp"), self.registry),
            "cat > spec.md <<'EOF'\nEOF",
        )

        for rejected in (
            "VAR=1 cat > spec.md <<'EOF'\nhello\nEOF",
            "cat > spec.md < input <<'EOF'\nhello\nEOF",
            "cat > first>second <<'EOF'\nhello\nEOF",
            "cat > #comment <<'EOF'\nsystemctl restart signer.service\nEOF",
            "cat > spec.md <<'EOF'\nhello\nEOF\ntrue",
            "cat > \"$F\" <<'EOF'\nhello\nEOF",
            "cat > spec.md <<'EOF'\n$(systemctl restart signer.service)\nEOF",
        ):
            with self.subTest(command=rejected):
                self.assertIsNone(_heredoc_authoring_scan(rejected, Path("/tmp"), self.registry))
