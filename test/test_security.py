import argparse
import copy
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / "skills/local-security-review/scripts"
sys.path.insert(0, str(SCRIPTS))
import security
import render_review


READY = {"status": "prerequisites-ready", "checks": {}}


class CombinedTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repo = Path(self.temporary.name).resolve()
        self.calls = []

    def args(self, **kwargs):
        return argparse.Namespace(**{**dict(target=str(self.repo), timeout=60, commit=None,
                                           diff=False, release=False, offline=True), **kwargs})

    def fake(self, args, name=None, status="findings"):
        name = name or args.scanner
        self.calls.append((name, copy.copy(args)))
        prefix = {"sast": "SAST", "sca": "SCA", "secrets": "SECRET"}[name]
        finding = {"id": prefix + "-0001", "engine": name, "rule": "synthetic-rule",
                   "path": str(Path(args.target) / "file.py"), "line": 1,
                   "scanner_severity": "unspecified", "ai_disposition": "unreviewed"}
        report = {"scanner": name, "tool": name, "scope": "working-tree", "status": status,
                  "findings": [finding], "coverage": {"sources": [{"path": finding["path"]}]}}
        directory = Path(tempfile.mkdtemp())
        path = directory / "report.json"
        path.write_text(json.dumps(report))
        return path, report

    def run_scan(self, **kwargs):
        path, report = security.execute(self.args(**kwargs))
        self.addCleanup(shutil.rmtree, path.parent)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(list(path.parent.iterdir()), [path])
        return report

    def test_check_collects_every_setup_without_installation(self):
        with patch.object(security.setup_sast, "check", return_value={"status": "prerequisites-ready"}), \
             patch.object(security.setup_sca, "check", side_effect=ValueError("private diagnostic")), \
             patch.object(security.setup_secrets, "check", return_value={"status": "needs-setup"}), \
             patch.object(security.setup_sast, "install") as install:
            report = security.check()
        self.assertEqual(report["status"], "needs-setup")
        self.assertEqual(set(report["checks"]), {"sast", "sca", "secrets"})
        self.assertEqual(report["checks"]["sca"]["setup"], "security.py --setup")
        self.assertNotIn("private diagnostic", json.dumps(report))
        install.assert_not_called()

    def test_missing_setup_blocks_all_scanners(self):
        with patch.object(security, "check", return_value={"status": "needs-setup"}), \
             patch.object(security.sast, "execute") as sast, patch.object(security.scan, "execute") as scan:
            report = self.run_scan()
        sast.assert_not_called()
        scan.assert_not_called()
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(len(report["engines"]), 3)
        self.assertFalse(report["network_allowed"])

    def test_full_diff_release_modes_preserve_every_finding_and_network_choices(self):
        for flags in ({}, {"diff": True}, {"release": True}, {"offline": False}):
            self.calls = []
            with self.subTest(flags=flags), patch.object(security, "check", return_value=READY), \
                 patch.object(security.sast, "execute", side_effect=lambda a: self.fake(a, "sast")), \
                 patch.object(security.scan, "execute", side_effect=self.fake), \
                 patch.object(security.secrets_deep, "execute", side_effect=lambda a: self.fake(a, "secrets")) as deep:
                report = self.run_scan(**flags)
            self.assertEqual(report["status"], "findings")
            self.assertEqual([n for n, _ in self.calls], ["sast", "sca", "secrets"])
            self.assertEqual(self.calls[0][1].diff, flags.get("diff", False))
            self.assertFalse(self.calls[1][1].diff)
            self.assertEqual(self.calls[1][1].offline, flags.get("offline", True))
            self.assertEqual(deep.call_count, int(flags.get("release", False)))
            review = render_review.merge(report, [])
            self.assertEqual(review["summary"]["scanner_findings"], 3)
            self.assertEqual(review["counts"]["unreviewed"], 3)
            self.assertTrue(all(f["id"] in render_review.markdown(review) for f in report["findings"]))

    def test_failure_continues_other_scanners_and_partial_findings_survive(self):
        def scan(args):
            return self.fake(args, status="incomplete" if args.scanner == "sca" else "findings")
        with patch.object(security, "check", return_value=READY), \
             patch.object(security.sast, "execute", side_effect=ValueError("private raw content")), \
             patch.object(security.scan, "execute", side_effect=scan):
            report = self.run_scan()
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(len(report["engines"]), 3)
        self.assertEqual(len(report["findings"]), 2)
        self.assertNotIn("private raw content", json.dumps(report))

    def git(self, *args):
        return security.scan.git(self.repo, security.secrets_deep.git_env(), *args)

    def commit(self):
        self.git("add", "--all")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false",
                 "-c", "core.hooksPath=/dev/null", "commit", "--quiet", "-m", "Fixture")
        return self.git("rev-parse", "HEAD")

    def test_commit_snapshot_is_shared_exact_and_preserves_dirty_checkout(self):
        self.git("init", "--quiet", "--template=")
        source = self.repo / "file.py"
        source.write_text("selected revision\n")
        selected = self.commit()
        source.write_text("later commit\n")
        self.commit()
        source.write_text("staged\n")
        self.git("add", ".")
        source.write_text("unstaged\n")
        (self.repo / "untracked.txt").write_text("not in snapshot")
        index = (self.repo / ".git/index").read_bytes()
        head = self.git("rev-parse", "HEAD")
        def fake(args, name=None):
            self.assertNotEqual(Path(args.target), self.repo)
            self.assertEqual((Path(args.target) / "file.py").read_text(), "selected revision\n")
            self.assertFalse((Path(args.target) / "untracked.txt").exists())
            self.assertFalse(args.diff)
            self.assertIsNone(args.commit)
            return self.fake(args, name)
        with patch.object(security, "check", return_value=READY), \
             patch.object(security.sast, "execute", side_effect=lambda a: fake(a, "sast")), \
             patch.object(security.scan, "execute", side_effect=fake):
            report = self.run_scan(commit=selected)
        self.assertEqual(report["commit"], selected)
        self.assertTrue(all(f["commit"] == selected and f["path"] == "file.py" for f in report["findings"]))
        self.assertEqual(len({a.target for _, a in self.calls}), 1)
        self.assertFalse(Path(self.calls[0][1].target).exists())
        self.assertEqual((self.repo / ".git/index").read_bytes(), index)
        self.assertEqual(self.git("rev-parse", "HEAD"), head)
        self.assertEqual(source.read_text(), "unstaged\n")

    def test_invalid_commit_never_falls_back_to_working_files(self):
        self.git("init", "--quiet", "--template=")
        with patch.object(security, "check", return_value=READY), \
             patch.object(security.sast, "execute") as sast, patch.object(security.scan, "execute") as scan:
            report = self.run_scan(commit="missing-ref")
        self.assertEqual(report["status"], "incomplete")
        sast.assert_not_called()
        scan.assert_not_called()

    def test_real_all_engines_offline_on_synthetic_commit(self):
        if security.check()["status"] != "prerequisites-ready":
            self.skipTest("All managed prerequisites and supported Python required")
        self.git("init", "--quiet", "--template=")
        (self.repo / "unsafe.py").write_text("import pickle\npickle.loads(input())\n")
        security.setup_sca.fixture(self.repo)
        token = security.setup_secrets.fixture(self.repo)
        selected = self.commit()
        (self.repo / "candidate.env").unlink()
        report = self.run_scan(commit=selected)
        self.assertEqual(report["status"], "findings", report)
        self.assertEqual({f["scanner"] for f in report["findings"]}, {"sast", "sca", "secrets"})
        self.assertNotIn(token, json.dumps(report))
        self.assertTrue(all(f["commit"] == selected for f in report["findings"]))
        self.assertTrue(all(not Path(f["path"]).is_absolute() for f in report["findings"]))
        self.assertFalse((self.repo / "candidate.env").exists())


if __name__ == "__main__":
    unittest.main()
