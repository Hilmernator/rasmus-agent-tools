"""IaC integration, offline boundaries, lossless projection and real scanner checks."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / "skills/local-security-review/scripts"
sys.path.insert(0, str(SCRIPTS))
import iac
import sast
import setup_sast


class IacTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.target = self.root / "repo with spaces"
        self.target.mkdir()
        self.raw = self.root / "raw"
        self.raw.mkdir()

    def run_scan(self, names, changed=None, paths=()):
        return iac.run(self.target, names, [], self.raw, os.environ, 30, changed, paths)

    def test_projection_retains_every_failure_omits_values_and_validates_paths(self):
        result = {"Target": "infra/template.yaml", "Type": "cloudformation", "Misconfigurations": [
            {"ID": "AWS-001", "Severity": "HIGH", "Status": "FAIL", "Message": "SECRET",
             "CauseMetadata": {"StartLine": 3, "Resource": "SECRET", "Code": "SECRET"}},
            {"ID": "AWS-002", "Severity": "LOW", "Status": "EXCEPTION"},
            {"ID": "AWS-003", "Severity": "LOW", "Status": "PASS"}]}
        data = {"SchemaVersion": 2, "Results": [result]}
        findings, coverage = iac.project(data, ["infra/template.yaml"])
        self.assertEqual(len(findings), 2)
        self.assertEqual(coverage["check_counts"], {"passed": 1, "failed": 1, "exceptions": 1})
        self.assertNotIn("SECRET", json.dumps([findings, coverage]))
        for path in ("../escape", "/tmp/escape", "unselected.yaml"):
            result["Target"] = path
            with self.assertRaises(ValueError):
                iac.project(data, ["infra/template.yaml"])

    def test_prerequisite_check_never_downloads(self):
        with patch.object(iac, "CACHE", self.root / "cache"), patch.object(iac.urllib.request, "urlopen") as network:
            self.assertEqual(iac.check()["status"], "needs-setup")
            network.assert_not_called()
            self.assertFalse((self.root / "cache").exists())

    def test_install_checks_archive_and_binary_without_overwriting(self):
        archive = self.root / "release.tar.gz"
        with tarfile.open(archive, "w:gz") as output:
            for name, data in (("trivy", b"fake binary"), ("LICENSE", b"license")):
                member = tarfile.TarInfo(name)
                member.size = len(data)
                output.addfile(member, io.BytesIO(data))
        response = io.BytesIO(archive.read_bytes())
        response.geturl = lambda: "https://example.invalid/release"
        with patch.object(iac, "CACHE", self.root / "cache"), \
             patch.dict(iac.HASHES, {iac.artifact(): hashlib.sha256(archive.read_bytes()).hexdigest()}), \
             patch.object(iac.urllib.request, "urlopen", return_value=response) as network:
            self.assertEqual(iac.install()["status"], "installed")
            binary = Path(iac.checked_executable())
            self.assertEqual(iac.install()["status"], "already-installed")
            self.assertEqual(network.call_count, 1)
            binary.write_bytes(b"changed")
            with self.assertRaises(ValueError):
                iac.install()
            self.assertEqual(binary.read_bytes(), b"changed")

    def test_no_inputs_and_clean_diff_do_not_invoke_tools(self):
        (self.target / ".terraform").mkdir()
        (self.target / ".terraform/cached.tf").write_text('resource "aws_s3_bucket" "cache" {}')
        with patch.object(iac, "checked_executable") as tool:
            self.assertEqual(self.run_scan([])["status"], "not-applicable")
            self.assertEqual(self.run_scan([], changed=set())["status"], "not-applicable")
            self.assertEqual(self.run_scan([], changed={"src/app.py"})["status"], "not-applicable")
            self.assertEqual(self.run_scan([".terraform/cached.tf"])["status"], "not-applicable")
            tool.assert_not_called()

    def test_cdk_missing_templates_and_module_downloads_stay_incomplete(self):
        (self.target / "cdk.json").write_text('{"app":"must never execute"}')
        (self.target / "main.tf").write_text('module "external" { source = "https://example.invalid/module" }')
        with patch.object(iac, "checked_executable", side_effect=FileNotFoundError), patch.object(iac.subprocess, "run") as process:
            report = self.run_scan(["main.tf"])
            self.assertEqual(report["status"], "incomplete")
            self.assertTrue(any("module" in gap for gap in report["coverage"]["gaps"]))
            cdk = self.run_scan(["cdk.json"])
            self.assertEqual(cdk["status"], "incomplete")
            self.assertTrue(any("CDK" in gap for gap in cdk["coverage"]["gaps"]))
            process.assert_not_called()

    def test_explicit_paths_reject_escape_symlinks_and_snapshot_mixing(self):
        (self.root / "outside.json").write_text("{}")
        (self.target / "linked.json").symlink_to(self.root / "outside.json")
        for name in ("../outside.json", str(self.root / "outside.json"), "linked.json"):
            with self.assertRaises(ValueError):
                iac.extra_files(self.target, [name])
        self.assertEqual(self.run_scan([], changed={"a.py"}, paths=["."])["status"], "incomplete")

    def test_fake_process_partial_findings_errors_suppression_and_env(self):
        (self.target / "Dockerfile").write_text("FROM alpine\n# trivy:ignore:DS-0002\nUSER root\n")
        (self.target / "trivy.yaml").write_text("must not load")
        def fake(argv, **kwargs):
            self.assertNotIn("TRIVY_SKIP_FILES", kwargs["env"])
            self.assertNotIn("AWS_SECRET_ACCESS_KEY", kwargs["env"])
            self.assertIn("--skip-check-update", argv)
            self.assertIn("--disable-telemetry", argv)
            self.assertEqual(Path(argv[argv.index("--config") + 1]).read_text(), "{}\n")
            self.assertFalse((Path(argv[-1]) / "trivy.yaml").exists())
            result = {"SchemaVersion": 2, "Results": [{"Target": "Dockerfile", "Type": "dockerfile", "Misconfigurations": [
                {"ID": "DS-0002", "Severity": "HIGH", "Status": "FAIL", "CauseMetadata": {"StartLine": 3}}]}]}
            Path(argv[argv.index("--output") + 1]).write_text(json.dumps(result))
            kwargs["stderr"].write(b"ERROR parsing SECRET_SENTINEL\n")
            return subprocess.CompletedProcess(argv, 0)
        with patch.object(iac, "checked_executable", return_value="fake-trivy"), patch.object(iac.subprocess, "run", side_effect=fake), \
             patch.dict(os.environ, {"TRIVY_SKIP_FILES": "*", "AWS_SECRET_ACCESS_KEY": "SECRET_SENTINEL"}):
            report = self.run_scan(["Dockerfile"])
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(len(report["findings"]), 1)
        self.assertNotIn("SECRET_SENTINEL", json.dumps(report))
        self.assertEqual(report["coverage"]["diagnostic_warnings_or_errors"], 1)


@unittest.skipUnless(os.environ.get("RAI_IAC_TEST_BINARY"), "explicit verified Trivy fixture binary required")
class RealIacTests(unittest.TestCase):
    run_scan = IacTests.run_scan

    def setUp(self):
        IacTests.setUp(self)
        self.binary = Path(os.environ["RAI_IAC_TEST_BINARY"]).resolve()
        patcher = patch.object(iac, "checked_executable", return_value=str(self.binary))
        patcher.start()
        self.addCleanup(patcher.stop)

    @unittest.skipUnless(shutil.which("semgrep") and shutil.which("node") and
                         (setup_sast.toolchain() / "license-inventory.json").is_file(),
                         "installed Semgrep and locked language tools required")
    def test_all_four_engines_full_diff_commit_and_clean_diff(self):
        env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                   GIT_AUTHOR_NAME="Test", GIT_AUTHOR_EMAIL="test@example.invalid",
                   GIT_COMMITTER_NAME="Test", GIT_COMMITTER_EMAIL="test@example.invalid")
        def git(*args):
            return subprocess.check_output(["git", "-C", str(self.target), *args], env=env)
        git("init", "-qb", "main")
        (self.target / "safe.py").write_text("print('safe')\n")
        git("add", ".")
        git("commit", "-qm", "root")
        rules = self.root / "rules.yml"
        rules.write_text("rules:\n- id: fixture-eval\n  languages: [python]\n  severity: ERROR\n  message: Fixture\n  pattern: eval(...)\n")
        (self.target / "bad.py").write_text("eval(input())\n")
        (self.target / "bad.ts").write_text("const x: string = process.argv[2]; eval(x);\n")
        (self.target / "Dockerfile").write_text("FROM alpine:3.20\nUSER root\n")
        for mode in ("full", "diff", "commit", "clean-diff"):
            if mode == "commit":
                git("add", ".")
                git("commit", "-qm", "risks")
            before = git("status", "--porcelain")
            args = argparse.Namespace(target=str(self.target), commit="HEAD" if mode == "commit" else None,
                diff=mode in ("diff", "clean-diff"), semgrep_config=str(rules),
                custom_rules_license_reviewed=True, timeout=60, allow_network=False, iac_path=[])
            path, report = sast.execute(args)
            self.addCleanup(shutil.rmtree, path.parent)
            self.assertEqual(report["status"], "no-findings" if mode == "clean-diff" else "findings", report)
            self.assertEqual({f["engine"] for f in report["findings"]},
                             set() if mode == "clean-diff" else {"semgrep", "bandit", "eslint", "trivy"})
            self.assertEqual(before, git("status", "--porcelain"))

    def test_real_cloudformation_terraform_dockerfile_and_safe_control(self):
        (self.target / "template.yaml").write_text("AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  Bucket:\n    Type: AWS::S3::Bucket\n    Properties:\n      AccessControl: PublicRead\n")
        (self.target / "main.tf").write_text('resource "aws_s3_bucket" "unsafe" { bucket = "synthetic" }\n')
        (self.target / "Dockerfile").write_text("FROM alpine:3.20\nUSER root\n")
        report = self.run_scan(["template.yaml", "main.tf", "Dockerfile"])
        self.assertEqual(report["status"], "findings", report)
        self.assertEqual({f["metadata"]["iac_type"] for f in report["findings"]}, {"terraform", "cloudformation", "dockerfile"})
        self.assertNotIn("synthetic", json.dumps(report))
        safe = self.root / "safe-raw"
        safe.mkdir()
        (self.target / "Dockerfile").write_text("FROM alpine:3.20\nUSER 1000\nHEALTHCHECK CMD echo ok\n")
        report = iac.run(self.target, ["Dockerfile"], [], safe, os.environ, 30)
        self.assertEqual(report["status"], "no-findings", report)

    def test_real_parse_error_and_ignored_cdk_template(self):
        (self.target / "main.tf").write_text('resource "bad" { INVALID ???')
        report = self.run_scan(["main.tf"])
        self.assertEqual(report["status"], "incomplete", report)
        (self.target / "cdk.out").mkdir()
        (self.target / "cdk.out/app.template.json").write_text(json.dumps({"Resources": {"Bucket": {"Type": "AWS::S3::Bucket"}}}))
        raw = self.root / "cdk-raw"
        raw.mkdir()
        report = iac.run(self.target, [], [], raw, os.environ, 30, paths=["cdk.out"])
        self.assertEqual(report["status"], "findings", report)
        self.assertEqual({f["path"] for f in report["findings"]}, {"cdk.out/app.template.json"})


if __name__ == "__main__":
    unittest.main()
