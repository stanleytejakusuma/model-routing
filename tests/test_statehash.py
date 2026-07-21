import subprocess
import tempfile
import unittest
from pathlib import Path

from model_routing.statehash import StateHashError, tree_sha_for_repo


class TreeShaForRepoTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.repo = Path(self.tempdir.name) / "repo"
        self.repo.mkdir()
        self.git("init")
        self.git("config", "user.email", "statehash-test@example.invalid")
        self.git("config", "user.name", "State Hash Test")
        (self.repo / "tracked.txt").write_text("original\n", encoding="utf-8")
        self.git("add", "tracked.txt")
        self.git("commit", "-m", "initial")

    def tearDown(self):
        self.tempdir.cleanup()

    def git(self, *args):
        return subprocess.run(
            ["git", "-C", str(self.repo), *args],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )

    def test_clean_repo_matches_head_tree_and_does_not_mutate_real_index(self):
        real_index = (self.repo / ".git" / "index").read_bytes()

        observed = tree_sha_for_repo(self.repo)

        expected = self.git("rev-parse", "HEAD^{tree}").stdout.strip()
        self.assertEqual(observed, expected)
        self.assertRegex(observed, r"^[0-9a-f]{40}$")
        self.assertEqual((self.repo / ".git" / "index").read_bytes(), real_index)

    def test_dirty_tracked_file_changes_tree_sha(self):
        baseline = tree_sha_for_repo(self.repo)
        (self.repo / "tracked.txt").write_text("changed\n", encoding="utf-8")

        self.assertNotEqual(tree_sha_for_repo(self.repo), baseline)

    def test_untracked_file_addition_changes_tree_sha(self):
        baseline = tree_sha_for_repo(self.repo)
        (self.repo / "untracked.txt").write_text("review me\n", encoding="utf-8")

        self.assertNotEqual(tree_sha_for_repo(self.repo), baseline)

    def test_untracked_file_deletion_changes_tree_sha(self):
        untracked = self.repo / "untracked.txt"
        untracked.write_text("review me\n", encoding="utf-8")
        reviewed = tree_sha_for_repo(self.repo)
        untracked.unlink()

        self.assertNotEqual(tree_sha_for_repo(self.repo), reviewed)

    def test_drift_then_revert_restores_identical_tree_sha(self):
        reviewed = tree_sha_for_repo(self.repo)
        tracked = self.repo / "tracked.txt"
        tracked.write_text("drift\n", encoding="utf-8")
        self.assertNotEqual(tree_sha_for_repo(self.repo), reviewed)
        tracked.write_text("original\n", encoding="utf-8")

        self.assertEqual(tree_sha_for_repo(self.repo), reviewed)

    def test_non_repository_fails_closed(self):
        non_repo = Path(self.tempdir.name) / "not-a-repo"
        non_repo.mkdir()

        with self.assertRaises(StateHashError):
            tree_sha_for_repo(non_repo)
