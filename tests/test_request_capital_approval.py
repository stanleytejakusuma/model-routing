import importlib.util
import contextlib
import io
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from model_routing.registry import CapitalRegistry


REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "request_capital_approval.py"


def load_request_capital_approval():
    spec = importlib.util.spec_from_file_location("request_capital_approval", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


class OpusCapitalReviewerTest(unittest.TestCase):
    def setUp(self):
        self.module = load_request_capital_approval()
        self.request = SimpleNamespace(
            action_type="shell",
            exact_action="systemctl restart signer.service",
            target="signer.service",
            risk_class="capital-high",
            cwd="/tmp/repo",
            repo_id="repo",
            host="local",
        )

    @staticmethod
    def non_repo_result(command):
        return subprocess.CompletedProcess(command, 128, stdout="", stderr="not a git repository")

    def test_approve_uses_direct_opus_cli_and_independently_fetched_repo_state(self):
        observed = {}

        def fake_run(command, **kwargs):
            if command[0] == "git":
                if command[-2:] == ["rev-parse", "--is-inside-work-tree"]:
                    return subprocess.CompletedProcess(command, 0, stdout="true\n", stderr="")
                if command[-2:] == ["status", "--porcelain"]:
                    return subprocess.CompletedProcess(command, 0, stdout=" M capital.py\n", stderr="")
                if command[-2:] == ["diff", "HEAD"]:
                    return subprocess.CompletedProcess(
                        command, 0, stdout="diff --git a/capital.py b/capital.py\n+", stderr=""
                    )
                self.fail(f"unexpected git command: {command}")
            observed["command"] = command
            observed["kwargs"] = kwargs
            return subprocess.CompletedProcess(
                command, 0, stdout="VERDICT: APPROVE\nSafe operational action.\n", stderr=""
            )

        with patch.object(self.module.subprocess, "run", side_effect=fake_run):
            decision = self.module.opus_capital_reviewer(self.request)

        self.assertTrue(decision.approved)
        self.assertEqual(decision.verifier_identity, "claude-cli-opus-capital")
        self.assertEqual(decision.verifier_version, "claude-opus-4-8")
        self.assertEqual(observed["command"][:4], ["claude", "-p", "--model", "claude-opus-4-8"])
        self.assertEqual(observed["kwargs"]["timeout"], 600)
        self.assertIn("REPO STATE (fetched independently)", observed["command"][4])
        self.assertIn(" M capital.py", observed["command"][4])
        self.assertIn("diff --git a/capital.py b/capital.py", observed["command"][4])

    def test_non_repo_cwd_is_marked_in_the_review_prompt(self):
        observed = {}

        def fake_run(command, **kwargs):
            if command[0] == "git":
                return self.non_repo_result(command)
            observed["prompt"] = command[4]
            return subprocess.CompletedProcess(command, 0, stdout="VERDICT: APPROVE\n", stderr="")

        with patch.object(self.module.subprocess, "run", side_effect=fake_run):
            decision = self.module.opus_capital_reviewer(self.request)

        self.assertTrue(decision.approved)
        self.assertIn("REPO STATE (fetched independently)\nnot a git repository", observed["prompt"])

    def test_repo_context_is_truncated_with_an_explicit_marker(self):
        observed = {}

        def fake_run(command, **kwargs):
            if command[0] == "git":
                if command[-2:] == ["rev-parse", "--is-inside-work-tree"]:
                    return subprocess.CompletedProcess(command, 0, stdout="true\n", stderr="")
                if command[-2:] == ["status", "--porcelain"]:
                    return subprocess.CompletedProcess(command, 0, stdout=" M capital.py\n", stderr="")
                return subprocess.CompletedProcess(command, 0, stdout="x" * (20 * 1024), stderr="")
            observed["prompt"] = command[4]
            return subprocess.CompletedProcess(command, 0, stdout="VERDICT: APPROVE\n", stderr="")

        with patch.object(self.module.subprocess, "run", side_effect=fake_run):
            self.module.opus_capital_reviewer(self.request)

        repo_state = observed["prompt"].split("REPO STATE (fetched independently)\n", 1)[1].split(
            "\n\nRespond on the FIRST line", 1
        )[0]
        self.assertIn("[truncated]", repo_state)
        self.assertLessEqual(len(repo_state.encode("utf-8")), 16 * 1024)

    def test_git_fetch_failure_is_reported_without_skipping_review(self):
        observed = {}

        def fake_run(command, **kwargs):
            if command[0] == "git":
                if command[-2:] == ["rev-parse", "--is-inside-work-tree"]:
                    return subprocess.CompletedProcess(command, 0, stdout="true\n", stderr="")
                return subprocess.CompletedProcess(command, 1, stdout="", stderr="permission denied")
            observed["prompt"] = command[4]
            return subprocess.CompletedProcess(command, 0, stdout="VERDICT: APPROVE\n", stderr="")

        with patch.object(self.module.subprocess, "run", side_effect=fake_run):
            decision = self.module.opus_capital_reviewer(self.request)

        self.assertTrue(decision.approved)
        self.assertIn("repo state unavailable: git status failed (exit 1)", observed["prompt"])

    def test_verdict_parser_requires_one_exact_verdict_line(self):
        cases = (
            ("APPROVE\n", False),
            ("VERDICT: APPROVE\nSafe operational action.\n", True),
            ("VERDICT: APPROVE\nVERDICT: REJECT\n", False),
            ("VERDICT: APPROVE-WITH-CHANGES\n", False),
            ("VERDICT: approve\n", False),
            ("\nVERDICT: APPROVE\n", False),
        )

        for output, approved in cases:
            with self.subTest(output=output):
                def fake_run(command, **kwargs):
                    if command[0] == "git":
                        return self.non_repo_result(command)
                    return subprocess.CompletedProcess(command, 0, stdout=output, stderr="")

                with patch.object(self.module.subprocess, "run", side_effect=fake_run):
                    decision = self.module.opus_capital_reviewer(self.request)

                self.assertEqual(decision.approved, approved)

    def test_rejects_timeout_exception_nonzero_exit_and_empty_output(self):
        cases = (
            subprocess.TimeoutExpired(["claude"], 600),
            OSError("claude unavailable"),
            subprocess.CompletedProcess(["claude"], 1, stdout="VERDICT: APPROVE\n", stderr="unavailable"),
            subprocess.CompletedProcess(["claude"], 0, stdout="", stderr=""),
        )

        for result in cases:
            with self.subTest(result=type(result).__name__):
                def fake_run(command, **kwargs):
                    if command[0] == "git":
                        return self.non_repo_result(command)
                    if isinstance(result, Exception):
                        raise result
                    return result

                with patch.object(self.module.subprocess, "run", side_effect=fake_run):
                    decision = self.module.opus_capital_reviewer(self.request)

                self.assertFalse(decision.approved)

    def test_registry_exposes_only_the_expected_reviewers(self):
        self.assertEqual(
            set(self.module.REVIEWERS), {"opus-capital", "approve-stub", "reject-stub"}
        )
        self.assertIs(self.module.REVIEWERS["opus-capital"], self.module.opus_capital_reviewer)

    def test_main_defaults_to_opus_capital_reviewer(self):
        classification = SimpleNamespace(
            is_capital=True,
            is_read_only=False,
            exact_action="systemctl restart signer.service",
            target="signer.service",
            risk_class="capital-high",
            capital_reason="registered service",
            cwd="/tmp/repo",
            repo_id="repo",
            host="local",
        )
        package = SimpleNamespace(
            approved=False,
            approval=SimpleNamespace(defects=("test rejection",)),
        )
        registry = SimpleNamespace(is_pre_blessed=lambda _action: False)
        observed = {}

        def fake_build_approval_package(*args, **kwargs):
            observed["reviewer"] = kwargs["opus_reviewer"]
            return package

        with (
            patch.object(self.module.CapitalRegistry, "from_file", return_value=registry),
            patch.object(self.module, "classify_tool_call", return_value=classification),
            patch.object(self.module, "bind_approval_state", return_value=("none", "")),
            patch.object(self.module, "build_approval_package", side_effect=fake_build_approval_package),
            patch.object(
                sys,
                "argv",
                [str(SCRIPT), "--tool", "Bash", "--command", "restart", "--cwd", "/tmp/repo"],
            ),
        ):
            exit_code = self.module.main()

        self.assertEqual(exit_code, 3)
        self.assertIs(observed["reviewer"], self.module.opus_capital_reviewer)

    def test_reviewer_fetches_state_from_the_bound_repo_when_present(self):
        request = SimpleNamespace(**vars(self.request), state_repo="/tmp/bound-service-repo")
        observed = {}

        def fake_run(command, **kwargs):
            if command[0] == "git":
                observed["repo"] = command[2]
                return self.non_repo_result(command)
            return subprocess.CompletedProcess(command, 0, stdout="VERDICT: APPROVE\n", stderr="")

        with patch.object(self.module.subprocess, "run", side_effect=fake_run):
            decision = self.module.opus_capital_reviewer(request)

        self.assertTrue(decision.approved)
        self.assertEqual(observed["repo"], str(Path("/tmp/bound-service-repo").resolve()))


class StateBindingCaptureTest(unittest.TestCase):
    def setUp(self):
        self.module = load_request_capital_approval()
        self.classification = SimpleNamespace(
            capital_reason="capital-service-mutation",
            exact_action="systemctl restart vault_agent.service",
            target="vault_agent.service",
            cwd="/tmp/action-cwd",
        )

    def test_capture_refuses_the_unmapped_vault_service_restart(self):
        registry = CapitalRegistry.from_file(REPO / "config" / "capital-registry.example.json")
        self.assertIsNone(registry.repo_for_service("vault_agent.service"))

        with self.assertRaisesRegex(
            self.module.StateBindingError,
            "no repo binding for capital service vault_agent.service — add it to the registry",
        ):
            self.module.bind_approval_state(self.classification, registry)

    def test_restart_hashes_and_records_the_bound_service_repo(self):
        repo = Path("/tmp/capital-service-repo")
        registry = SimpleNamespace(repo_for_service=lambda _service: repo)

        with patch.object(self.module, "tree_sha_for_repo", return_value="a" * 40):
            tree_sha, state_repo = self.module.bind_approval_state(self.classification, registry)

        self.assertEqual(tree_sha, "a" * 40)
        self.assertEqual(state_repo, str(repo.resolve()))

    def test_repo_backed_non_restart_hashes_the_action_cwd(self):
        classification = SimpleNamespace(
            capital_reason="capital-secret-surface",
            exact_action="cat signer-key",
            target="signer-key",
            cwd="/tmp/repo-backed-action",
        )
        with (
            patch.object(self.module, "is_git_repository", return_value=True),
            patch.object(self.module, "tree_sha_for_repo", return_value="b" * 40),
        ):
            tree_sha, state_repo = self.module.bind_approval_state(classification, SimpleNamespace())

        self.assertEqual(tree_sha, "b" * 40)
        self.assertEqual(state_repo, str(Path(classification.cwd).resolve()))

    def test_repo_free_action_allows_none_binding(self):
        classification = SimpleNamespace(
            capital_reason="capital-secret-surface",
            exact_action="cat signer-key",
            target="signer-key",
            cwd="/tmp/repo-free-action",
        )
        with patch.object(self.module, "is_git_repository", return_value=False):
            self.assertEqual(self.module.bind_approval_state(classification, SimpleNamespace()), ("none", ""))

    def test_main_refuses_an_unbound_restart_before_review(self):
        classification = SimpleNamespace(
            is_capital=True,
            is_read_only=False,
            capital_reason="capital-service-mutation",
            exact_action="systemctl restart capital.service",
            target="capital.service",
            risk_class="capital-high",
            cwd="/tmp/action-cwd",
            repo_id="capital",
            host="local",
        )
        registry = SimpleNamespace(repo_for_service=lambda _service: None, is_pre_blessed=lambda _action: False)
        output = io.StringIO()

        with (
            patch.object(self.module.CapitalRegistry, "from_file", return_value=registry),
            patch.object(self.module, "classify_tool_call", return_value=classification),
            patch.object(
                sys,
                "argv",
                [str(SCRIPT), "--tool", "Bash", "--command", "restart", "--cwd", "/tmp/action-cwd"],
            ),
            contextlib.redirect_stdout(output),
        ):
            exit_code = self.module.main()

        self.assertEqual(exit_code, 5)
        self.assertIn(
            "REFUSED — no repo binding for capital service capital.service — add it to the registry",
            output.getvalue(),
        )


if __name__ == "__main__":
    unittest.main()
