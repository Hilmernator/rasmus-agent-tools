"""Setup is non-installing by default; rule downloads never replace caches."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / "skills/local-security-review/scripts"
sys.path.insert(0, str(SCRIPTS))
import setup_sast


class SetupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.rules = self.root / "cache/rules.yaml"
        self.policy = self.root / "policy.json"
        self.payload = b"rules: []\n"
        self.policy.write_text(json.dumps({"source": "https://example.invalid/reviewed-rules",
                                          "sha256": hashlib.sha256(self.payload).hexdigest()}))
        for name, value in (("DEFAULT_RULES", self.rules), ("RULE_POLICY", self.policy)):
            patcher = patch.object(setup_sast, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def response(self, data):
        response = io.BytesIO(data)
        response.geturl = lambda: "https://example.invalid/reviewed-rules"
        return response

    def test_check_reports_missing_without_installing_or_downloading(self):
        with patch.object(setup_sast.shutil, "which", return_value=None), \
             patch.object(setup_sast, "verified_receipt", side_effect=FileNotFoundError), \
             patch.object(setup_sast.urllib.request, "urlopen") as network:
            result = setup_sast.check()
        self.assertEqual(result["status"], "needs-setup")
        self.assertTrue(all(result["checks"][key]["status"] == "missing" for key in ("git", "node", "semgrep", "rules", "toolchain")))
        network.assert_not_called()
        self.assertFalse(self.rules.parent.exists())

    def test_default_cli_is_check_and_reports_incomplete(self):
        env = {**os.environ, "PATH": "", "XDG_CACHE_HOME": str(self.root / "empty-cache")}
        result = subprocess.run([sys.executable, "-B", str(SCRIPTS / "setup_sast.py")],
                                env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "needs-setup")
        self.assertFalse((self.root / "empty-cache").exists())

    def test_pinned_node_range(self):
        for version in ("v20.19.0", "22.13.0", "v24.0.0", "v26.3.0"):
            self.assertTrue(setup_sast.node_supported(version), version)
        for version in ("v18.20.0", "v20.18.9", "v22.12.9", "v23.9.0", "v24.0.0-rc.1", "unknown"):
            self.assertFalse(setup_sast.node_supported(version), version)

    def test_download_checks_hash_and_publishes_exclusively(self):
        with patch.object(setup_sast.urllib.request, "urlopen", return_value=self.response(self.payload)):
            self.assertEqual(setup_sast.fetch_rules()["status"], "installed")
        self.assertEqual(self.rules.read_bytes(), self.payload)
        self.assertEqual(self.rules.stat().st_mode & 0o777, 0o600)
        self.assertEqual(list(self.rules.parent.iterdir()), [self.rules])
        with patch.object(setup_sast.urllib.request, "urlopen") as network:
            self.assertEqual(setup_sast.fetch_rules()["status"], "already-present")
            network.assert_not_called()
        self.rules.write_bytes(b"user-owned rules")
        with patch.object(setup_sast.urllib.request, "urlopen") as network, self.assertRaises(ValueError):
            setup_sast.fetch_rules()
        self.assertEqual(self.rules.read_bytes(), b"user-owned rules")
        network.assert_not_called()

    def test_mismatch_oversize_and_http_redirect_leave_cache_absent(self):
        for data in (b"changed upstream rules", b"x" * 100):
            with patch.object(setup_sast, "MAX_RULE_BYTES", 20), \
                 patch.object(setup_sast.urllib.request, "urlopen", return_value=self.response(data)), \
                 self.assertRaises(ValueError):
                setup_sast.fetch_rules()
            self.assertFalse(self.rules.parent.exists())
        response = self.response(self.payload)
        response.geturl = lambda: "http://example.invalid/insecure"
        with patch.object(setup_sast.urllib.request, "urlopen", return_value=response), self.assertRaises(ValueError):
            setup_sast.fetch_rules()
        self.assertFalse(self.rules.exists())

    def test_concurrent_writer_is_preserved(self):
        def competing_link(source, destination):
            Path(destination).write_bytes(b"another installation")
            raise FileExistsError
        with patch.object(setup_sast.urllib.request, "urlopen", return_value=self.response(self.payload)), \
             patch.object(setup_sast.os, "link", side_effect=competing_link), self.assertRaises(FileExistsError):
            setup_sast.fetch_rules()
        self.assertEqual(self.rules.read_bytes(), b"another installation")
        self.assertEqual(list(self.rules.parent.iterdir()), [self.rules])

    def test_verify_stops_before_running_scanners_when_prerequisites_missing(self):
        with patch.object(setup_sast, "check", return_value={"status": "needs-setup"}), \
             patch.object(setup_sast.subprocess, "run") as process:
            self.assertEqual(setup_sast.verify()["status"], "needs-setup")
            process.assert_not_called()

    def test_verify_rejects_missing_engine_detection_and_cleans_its_report(self):
        import sast
        output = self.root / "output"
        output.mkdir()
        path = output / "report.json"
        path.write_text("{}")
        partial = {"status": "findings", "engines": [{"tool": "semgrep", "status": "findings"}],
                   "findings": [{"engine": "semgrep"}]}
        with patch.object(setup_sast, "check", return_value={"status": "prerequisites-ready"}), \
             patch.object(sast, "execute", return_value=(path, partial)), \
             patch.object(setup_sast.subprocess, "run"):
            result = setup_sast.verify()
        self.assertEqual(result["status"], "verification-failed")
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
