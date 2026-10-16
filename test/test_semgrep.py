"""Real Semgrep integration tests; isolated Git fixtures, no network or project builds."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parents[1] / "skills/local-security-review/scripts"
spec = importlib.util.spec_from_file_location("review", SCRIPTS / "render_review.py")
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)


class ReviewTests(unittest.TestCase):
    def test_every_candidate_survives_and_unknown_ids_fail(self):
        report = {"status": "findings", "scope": "working-tree", "findings": [
            {"id": "SAST-0001", "rule": "eval", "path": "a.py", "line": 1, "scanner_severity": "ERROR"},
            {"id": "SAST-0002", "rule": "eval", "path": "b.py", "line": 2, "scanner_severity": "ERROR"},
        ]}
        assessment = {"id": "SAST-0001", "disposition": "false-positive", "confidence": "high",
                      "assessed_severity": "info", "evidence": "a.py:1 evaluates a constant.",
                      "evidence_refs": [{"path": "a.py", "line": 1}],
                      "dismissal_reason": "The entire eval argument is a literal; no attacker-controlled input reaches it.",
                      "recommendation": "No change required."}
        result = review.merge(report, [assessment])
        self.assertEqual(result["counts"], {"false-positive": 1, "unreviewed": 1})
        self.assertIn("SAST-0002", review.markdown(result))
        self.assertEqual(len(result["scan"]["findings"]), 2)
        for invalid in ([assessment, assessment], [{**assessment, "id": "unknown"}]):
            with self.assertRaises(ValueError):
                review.merge(report, invalid)


@unittest.skipUnless(shutil.which("semgrep") and shutil.which("git"), "real Semgrep and Git required")
class RealSemgrepTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rasmus-semgrep-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo with spaces"
        self.repo.mkdir()
        self.env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        self.env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                        GIT_AUTHOR_NAME="Test", GIT_AUTHOR_EMAIL="test@example.invalid",
                        GIT_COMMITTER_NAME="Test", GIT_COMMITTER_EMAIL="test@example.invalid")
        self.git("init", "-q", "-b", "main")
        self.rules = self.root / "rules.yml"
        self.rules.write_text("rules:\n- id: test-eval\n  languages: [python]\n  severity: ERROR\n  message: Review dynamic eval\n  pattern: eval(...)\n")
        (self.repo / "old.py").write_text("eval(input())\n")
        self.git("add", ".")
        self.git("commit", "-qm", "root")
        self.first = self.git("rev-parse", "HEAD")

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.repo), *args], env=self.env, text=True).strip()

    def scan(self, *args):
        process = subprocess.run([sys.executable, str(SCRIPTS / "scan.py"), "sast", str(self.repo),
                                  "--semgrep-config", str(self.rules), *args],
                                 env=self.env, capture_output=True, text=True, timeout=120)
        summary = json.loads(process.stdout)
        path = Path(summary["report"])
        self.addCleanup(shutil.rmtree, path.parent)
        report = json.loads(path.read_text())
        self.assertNotEqual(process.returncode, 2, report)
        self.assertEqual(list(path.parent.iterdir()), [path])
        return report

    def test_full_and_exact_commit_keep_all_findings_and_leave_worktree_untouched(self):
        (self.repo / "new.py").write_text("eval(input())  # nosemgrep\n")
        self.git("add", ".")
        self.git("commit", "-qm", "new risk")
        selected = self.git("rev-parse", "HEAD")
        self.git("commit", "--allow-empty", "-qm", "later commit")
        (self.repo / "new.py").write_text("print('uncommitted safe code')\n")
        (self.repo / "untracked.py").write_text("eval(input())\n")
        before = self.git("status", "--porcelain=v1")
        diff = self.scan("--commit", selected)
        self.assertEqual(diff["commit"], selected)
        self.assertEqual(diff["baseline"], self.first)
        self.assertEqual([item["path"] for item in diff["findings"]], ["new.py"])
        root = self.scan("--commit", self.first)
        self.assertEqual(root["scope"], "root-commit")
        self.assertEqual([item["path"] for item in root["findings"]], ["old.py"])
        full = self.scan()
        self.assertEqual({item["path"] for item in full["findings"]}, {"old.py", "untracked.py"})
        self.assertEqual(before, self.git("status", "--porcelain=v1"))
        self.assertEqual((self.repo / "new.py").read_text(), "print('uncommitted safe code')\n")

    def test_empty_commit(self):
        self.git("commit", "--allow-empty", "-qm", "empty")
        self.assertEqual(self.scan("--commit", "HEAD")["status"], "no-findings")

    def test_uncommitted_diff_includes_staged_unstaged_and_new_files_without_mutation(self):
        (self.repo / "staged.py").write_text("eval(input())\n")
        self.git("add", "staged.py")
        (self.repo / "new file.py").write_text("eval(input())  # nosemgrep\n")
        (self.repo / "old.py").write_text("eval(input())\neval(other_input())\n")
        (self.repo / ".gitignore").write_text("ignored.py\n")
        (self.repo / "ignored.py").write_text("eval(input())\n")
        before = self.git("status", "--porcelain=v1")
        index = (self.repo / ".git/index").read_bytes()
        diff = self.scan("--diff")
        self.assertEqual(diff["scope"], "working-tree-diff")
        self.assertEqual(diff["baseline"], self.first)
        self.assertEqual({item["path"] for item in diff["findings"]}, {"staged.py", "new file.py", "old.py"})
        self.assertEqual(before, self.git("status", "--porcelain=v1"))
        self.assertEqual(index, (self.repo / ".git/index").read_bytes())
        self.assertEqual(self.git("rev-parse", "HEAD"), self.first)

    def test_clean_and_deleted_working_tree_diff(self):
        self.assertEqual(self.scan("--diff")["status"], "no-findings")
        (self.repo / "old.py").unlink()
        self.assertEqual(self.scan("--diff")["status"], "no-findings")

    def test_deletion_rename_and_merge_commit(self):
        self.git("mv", "old.py", "renamed.py")
        self.git("commit", "-qm", "rename")
        self.assertEqual(self.scan("--commit", "HEAD")["findings"], [])
        self.git("checkout", "-qb", "feature")
        (self.repo / "feature.py").write_text("eval(input())\n")
        self.git("add", ".")
        self.git("commit", "-qm", "feature")
        self.git("checkout", "-q", "main")
        self.git("merge", "--no-ff", "-qm", "merge", "feature")
        merged = self.scan("--commit", "HEAD")
        self.assertEqual(merged["parent_count"], 2)
        self.assertEqual([item["path"] for item in merged["findings"]], ["feature.py"])
        self.git("rm", "-q", "renamed.py", "feature.py")
        self.git("commit", "-qm", "delete")
        self.assertEqual(self.scan("--commit", "HEAD")["status"], "no-findings")


if __name__ == "__main__":
    unittest.main()
