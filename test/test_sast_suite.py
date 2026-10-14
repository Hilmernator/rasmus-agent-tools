"""Local tool integration, scope, licensing and no-hidden-findings contracts."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / "skills/local-security-review/scripts"
sys.path.insert(0, str(SCRIPTS))
import sast
import setup_sast
import render_review


class LicenseTests(unittest.TestCase):
    def test_unknown_copyleft_and_restrictive_licenses_require_review(self):
        for license_id in ("MIT", "Apache-2.0", "BSD-3-Clause", "BlueOak-1.0.0"):
            self.assertTrue(setup_sast.license_allowed(license_id))
        for license_id in ("UNKNOWN", "AGPL-3.0", "Semgrep-Rules-License-1.0", "MIT OR proprietary"):
            self.assertFalse(setup_sast.license_allowed(license_id))

    def test_projectors_omit_source_and_messages_and_retain_errors(self):
        marker = "secret-marker-never-retained"
        root = Path("/test")
        findings, coverage = sast.project("eslint", [{"filePath": "/test/a.ts", "source": marker,
            "messages": [{"ruleId": "security/example", "line": 1, "severity": 1, "message": marker},
                         {"ruleId": None, "line": 2, "message": marker, "fatal": True}]}], root)
        self.assertEqual(len(findings), 1)
        self.assertEqual(coverage["scanner_errors"], 1)
        self.assertNotIn(marker, json.dumps([findings, coverage]))
        findings, coverage = sast.project("bandit", {"metrics": {"/test/a.py": {}, "_totals": {}},
            "errors": [{"filename": "/test/a.py", "reason": marker}], "results": [{
                "filename": "/test/a.py", "test_id": "B307", "line_number": 2,
                "issue_severity": "MEDIUM", "issue_confidence": "HIGH", "code": marker,
                "issue_text": marker}]}, root)
        self.assertNotIn(marker, json.dumps([findings, coverage]))
        self.assertEqual(coverage["scanner_errors"], 1)


@unittest.skipUnless((setup_sast.toolchain() / "license-inventory.json").is_file() and shutil.which("node"),
                     "explicitly installed locked Bandit/ESLint toolchain required")
class LocalToolsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rai-suite-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.repo = self.root / "repo with spaces"
        self.repo.mkdir()
        self.raw = self.root / "raw"
        self.raw.mkdir()
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(("GIT_", "PYTHON"))
                    and k not in ("NODE_OPTIONS", "NODE_PATH")}
        self.env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                        GIT_AUTHOR_NAME="Test", GIT_AUTHOR_EMAIL="test@example.invalid",
                        GIT_COMMITTER_NAME="Test", GIT_COMMITTER_EMAIL="test@example.invalid")
        self.git("init", "-qb", "main")
        (self.repo / "safe.py").write_text("print('safe')\n")
        self.git("add", ".")
        self.git("commit", "-qm", "root")

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.repo), *args], env=self.env, text=True).strip()

    def language(self, engine, files):
        return sast.language_scan(engine, files, self.repo, self.raw, self.env, 30)

    def test_real_bandit_all_confidence_suppressions_and_safe_control(self):
        (self.repo / "bad.py").write_text("eval(input())  # nosec\n")
        report = self.language("bandit", ["bad.py", "safe.py"])
        self.assertEqual(report["status"], "findings", report)
        self.assertIn("B307", [item["rule"] for item in report["findings"]])
        self.assertEqual({item["path"] for item in report["findings"]}, {"bad.py"})
        self.assertEqual(report["coverage"]["scanned_files"], 2)

    def test_real_typescript_jsx_and_commonjs_without_project_config_execution(self):
        (self.repo / "eslint.config.js").write_text("throw new Error('must not execute');")
        (self.repo / ".bandit").write_text("[bandit]\nskips = B307\n")
        (self.repo / "bad.ts").write_text("/* eslint-disable */\nconst value: string = process.argv[2]; eval(value);\n")
        (self.repo / "view.tsx").write_text("export const View = () => <div>Hello</div>;\n")
        (self.repo / "safe.cjs").write_text("module.exports = 42;\n")
        report = self.language("eslint", ["bad.ts", "view.tsx", "safe.cjs"])
        self.assertEqual(report["status"], "findings", report)
        self.assertIn("security/detect-eval-with-expression", [item["rule"] for item in report["findings"]])
        self.assertEqual(report["coverage"]["scanned_files"], 3)

    def test_parser_failures_missing_tool_and_not_applicable(self):
        for engine, file in (("bandit", "bad.py"), ("eslint", "bad.ts")):
            (self.repo / file).write_text("def ??!! this is broken syntax\n")
            self.assertEqual(self.language(engine, [file])["status"], "incomplete")
            self.assertEqual(self.language(engine, [])["status"], "not-applicable")
            with patch.object(setup_sast, "verified_receipt", side_effect=FileNotFoundError):
                self.assertEqual(self.language(engine, [file])["status"], "incomplete")
            with patch.object(setup_sast, "verified_receipt", side_effect=subprocess.CalledProcessError(2, "python")):
                self.assertEqual(self.language(engine, [file])["status"], "incomplete")

    def test_inventory_includes_tests_ignores_dependencies_and_symlinks(self):
        (self.repo / "test.py").write_text("eval(input())\n")
        (self.repo / ".gitignore").write_text("ignored.py\n")
        (self.repo / "ignored.py").write_text("eval(input())\n")
        (self.repo / "node_modules").mkdir()
        (self.repo / "node_modules/lib.js").write_text("eval(input);\n")
        (self.repo / "outside.py").symlink_to(self.root / "outside.py")
        files, skipped = sast.source_files(self.repo, self.env)
        self.assertEqual(set(files), {"safe.py", "test.py"})
        self.assertIn("outside.py", [item["path"] for item in skipped])
        files, _ = sast.source_files(self.repo, self.env, {"test.py"})
        self.assertEqual(files, ["test.py"])

    def test_suite_preserves_all_candidates_and_failure_across_engines_and_scopes(self):
        (self.repo / "bad.py").write_text("eval(input())\n")
        (self.repo / "bad.ts").write_text("const value: string = process.argv[2]; eval(value);\n")
        for mode in ("full", "diff", "commit"):
            if mode == "commit":
                self.git("add", ".")
                self.git("commit", "-qm", "risks")
            before = self.git("status", "--porcelain")
            index = (self.repo / ".git/index").read_bytes()
            args = argparse.Namespace(target=str(self.repo), commit="HEAD" if mode == "commit" else None,
                diff=mode == "diff", semgrep_config=str(self.root / "unapproved-rules"),
                custom_rules_license_reviewed=False, timeout=30, allow_network=False)
            path, report = sast.execute(args)
            self.addCleanup(shutil.rmtree, path.parent)
            self.assertEqual(report["status"], "incomplete", report)
            self.assertEqual({item["engine"] for item in report["findings"]}, {"bandit", "eslint"}, report)
            ids = [item["id"] for item in report["findings"]]
            self.assertEqual(len(ids), len(set(ids)))
            merged = render_review.merge(report, [])
            self.assertEqual(merged["counts"]["unreviewed"], len(ids))
            self.assertIn("Semgrep rules missing/unapproved", render_review.markdown(merged))
            self.assertEqual(index, (self.repo / ".git/index").read_bytes())
            self.assertEqual(before, self.git("status", "--porcelain"))
            self.assertEqual(list(path.parent.iterdir()), [path])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    @unittest.skipUnless(shutil.which("semgrep"), "real Semgrep required")
    def test_all_three_engines_with_reviewed_fixture_rules_and_clean_diff(self):
        rules = self.root / "rules.yml"
        rules.write_text("rules:\n- id: fixture-eval\n  languages: [python]\n  severity: ERROR\n  message: Fixture\n  pattern: eval(...)\n")
        (self.repo / "bad.py").write_text("eval(input())\n")
        (self.repo / "bad.ts").write_text("const x: string = process.argv[2]; eval(x);\n")
        args = argparse.Namespace(target=str(self.repo), commit=None, diff=True,
            semgrep_config=str(rules), custom_rules_license_reviewed=True, timeout=60, allow_network=False)
        path, report = sast.execute(args)
        self.addCleanup(shutil.rmtree, path.parent)
        self.assertEqual(report["status"], "findings", report)
        self.assertEqual({item["engine"] for item in report["findings"]}, {"semgrep", "bandit", "eslint"})
        self.git("add", ".")
        self.git("commit", "-qm", "risks")
        path, report = sast.execute(args)
        self.addCleanup(shutil.rmtree, path.parent)
        self.assertEqual(report["status"], "no-findings", report)
        self.assertEqual(report["findings"], [])


if __name__ == "__main__":
    unittest.main()
