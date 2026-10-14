import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


RUNNER = Path(__file__).resolve().parents[1] / "skills/local-security-review/scripts/scan.py"
MARKER = "synthetic-secret-must-never-appear-in-results"


class ScannerProcessTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.target = root / "target with spaces"
        self.target.mkdir()
        self.bin = root / "bin"
        self.bin.mkdir()
        self.rules = root / "rules.yml"
        self.rules.write_text("rules: []\n")

    def fake(self, scanner, payload, code=0, malformed=False, delay=0, warning=False):
        tool = {"sast": "semgrep", "sca": "osv-scanner", "secrets": "gitleaks"}[scanner]
        program = self.bin / tool
        program.write_text(
            f"#!{sys.executable}\n"
            "import json, pathlib, sys, time\n"
            "if sys.argv[1:] in [['--version'], ['version']]:\n"
            "    print('test-scanner 1.0'); sys.exit(0)\n"
            f"time.sleep({delay})\n"
            "flags = ['--output', '--output-file', '--report-path']\n"
            "flag = next(f for f in flags if f in sys.argv)\n"
            "output = pathlib.Path(sys.argv[sys.argv.index(flag) + 1])\n"
            f"output.write_text({MARKER!r} if {malformed!r} else json.dumps({payload!r}))\n" +
            (f"print({MARKER!r}); print({MARKER!r}, file=sys.stderr)\n" if scanner == "sast" or warning else "") +
            f"sys.exit({code})\n"
        )
        program.chmod(0o755)

    def run_scan(self, scanner, *options):
        env = {**os.environ, "PATH": str(self.bin), "XDG_CACHE_HOME": str(self.bin / "cache")}
        result = subprocess.run(
            [sys.executable, str(RUNNER), scanner, str(self.target), *options],
            env=env, capture_output=True, text=True,
        )
        self.assertNotIn(MARKER, result.stdout + result.stderr)
        summary = json.loads(result.stdout)
        path = Path(summary["report"])
        self.addCleanup(shutil.rmtree, path.parent)
        content = path.read_text()
        self.assertNotIn(MARKER, content)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(list(path.parent.iterdir()), [path])
        self.assertEqual(list(self.target.iterdir()), [])
        return result.returncode, json.loads(content)

    def test_secrets_redacted_on_success_and_failure(self):
        candidate = {"RuleID": "example-token", "File": "config.env", "StartLine": 3,
                     "Commit": "abc123", "Secret": MARKER, "Match": MARKER,
                     "Author": MARKER, "Message": MARKER}
        for exit_code, expected in [(42, 1), (2, 2)]:
            with self.subTest(exit_code=exit_code):
                self.fake("secrets", [candidate], exit_code)
                code, report = self.run_scan("secrets")
                self.assertEqual(code, expected)
                self.assertEqual(report["findings"][0]["path"], "config.env")
        self.fake("secrets", [candidate], 42, warning=True)
        code, report = self.run_scan("secrets")
        self.assertEqual(code, 2)
        self.assertEqual(report["findings"][0]["id"], "SECRET-0001")

    def test_malformed_and_missing_tool_are_incomplete(self):
        code, report = self.run_scan("sca")
        self.assertEqual(code, 2)
        self.assertIn("not found", report["error"])
        self.fake("secrets", [], malformed=True)
        code, report = self.run_scan("secrets")
        self.assertEqual(code, 2)
        self.assertEqual(report["error"], "JSONDecodeError")

    def test_timeout_is_incomplete(self):
        self.fake("secrets", [], delay=3)
        code, report = self.run_scan("secrets", "--timeout", "1")
        self.assertEqual(code, 2)
        self.assertEqual(report["error"], "TimeoutExpired")

    def test_sast_candidates_and_partial_coverage(self):
        data = {"results": [{"check_id": "injection", "path": "app.py",
                             "start": {"line": 4},
                             "extra": {"severity": "ERROR", "lines": MARKER}}],
                "paths": {"scanned": ["app.py"]}, "errors": []}
        self.fake("sast", data, 1)
        code, report = self.run_scan("sast", "--semgrep-config", str(self.rules))
        self.assertEqual(code, 1)
        self.assertEqual(report["coverage"]["scanned_files"], 1)
        self.assertEqual(report["findings"][0]["id"], "SAST-0001")
        self.assertIn("--disable-nosem", report["command"])
        data["errors"] = [{"message": MARKER}]
        self.fake("sast", data, 1)
        code, report = self.run_scan("sast", "--semgrep-config", str(self.rules))
        self.assertEqual(code, 2)
        self.assertEqual(len(report["findings"]), 1)

    def test_sca_inventory_and_advisory(self):
        data = {"results": [{"source": {"path": "package-lock.json"}, "packages": [
            {"package": {"name": "example", "version": "1.0.0", "ecosystem": "npm"},
             "vulnerabilities": [{"id": "TEST-123", "details": MARKER}]}]}]}
        self.fake("sca", data, 1)
        code, report = self.run_scan("sca")
        self.assertEqual(code, 1)
        self.assertEqual(report["findings"][0]["rule"], "TEST-123")
        data["results"][0]["packages"][0]["vulnerabilities"] = []
        self.fake("sca", data)
        self.assertEqual(self.run_scan("sca")[0], 0)
        self.fake("sca", {"results": []})
        self.assertEqual(self.run_scan("sca")[0], 2)

    def test_secrets_no_findings_and_history_scope(self):
        self.fake("secrets", [])
        code, report = self.run_scan("secrets")
        self.assertEqual(code, 0)
        code, report = self.run_scan("secrets", "--history")
        self.assertEqual(code, 2)  # No Git executable/history on the isolated fake PATH.
        self.assertEqual(report["scope"], "local-git-history")

    def test_sca_refresh_modes_and_failed_refresh_never_passes(self):
        data = {"results": [{"source": {"path": "package-lock.json"}, "packages": [
            {"package": {"name": "example", "version": "1", "ecosystem": "npm"},
             "vulnerabilities": [{"id": "TEST-123"}]}]}]}
        self.fake("sca", data, 1)
        for options, mode in [((), "refresh-then-local"), (("--offline",), "offline-cache"),
                              (("--allow-network",), "live-queries")]:
            with self.subTest(mode=mode):
                code, report = self.run_scan("sca", *options)
                self.assertEqual(code, 1)
                self.assertEqual(report["advisory_mode"], mode)
                self.assertEqual(report["network_allowed"], mode != "offline-cache")
                self.assertEqual("--download-offline-databases" in report["command"], mode == "refresh-then-local")
                self.assertEqual("--offline" in report["command"], mode != "live-queries")
                if not options:
                    self.assertEqual(report["database_refresh"]["status"], "succeeded")
                    self.assertEqual(report["database_refresh"]["ecosystems"], ["npm"])
                    self.assertIn("checked_at", report["database_refresh"])
                else:
                    self.assertEqual(report["database_refresh"]["status"], "not-requested")
        for code, warning in [(2, False), (1, True)]:
            self.fake("sca", data, code, warning=warning)
            exit_code, report = self.run_scan("sca")
            self.assertEqual(exit_code, 2)
            self.assertEqual(report["database_refresh"]["status"], "failed-or-unverified")
            self.assertNotIn("checked_at", report["database_refresh"])
            self.assertEqual(len(report["findings"]), 1)

    def test_sast_requires_explicit_rules_without_network(self):
        self.fake("sast", {})
        code, report = self.run_scan("sast")
        self.assertEqual(code, 2)
        self.assertIn("--semgrep-config", report["error"])


if __name__ == "__main__":
    unittest.main()
