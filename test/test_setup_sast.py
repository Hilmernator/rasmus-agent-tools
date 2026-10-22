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
        self.rules = self.root / "cache/packs"
        self.policy = self.root / "policy.json"
        self.payloads = {"default": b"rules:\n- id: a\n", "rust": b"rules:\n- id: b\n"}
        self.policy.write_text(json.dumps({"source": "https://example.invalid/c/p/{pack}", "packs": list(self.payloads),
                                           "license": "Semgrep-Rules-License-1.0"}))
        for name, value in (("RULES_DIR", self.rules), ("RULE_POLICY", self.policy)):
            patcher = patch.object(setup_sast, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def response(self, data, url="https://example.invalid/c/p/x"):
        response = io.BytesIO(data)
        response.geturl = lambda: url
        response.__enter__ = lambda *a: response
        return response

    def serve(self, overrides=None):
        def opener(url, timeout):
            pack = url.rsplit("/", 1)[1]
            return self.response((overrides or {}).get(pack, self.payloads[pack]), url)
        return opener

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

    def test_fetch_records_hashes_and_check_detects_tampering(self):
        with patch.object(setup_sast.urllib.request, "urlopen", side_effect=self.serve()):
            result = setup_sast.fetch_rules()
        self.assertEqual(result["status"], "installed")
        self.assertEqual((self.rules / "rust.yaml").read_bytes(), self.payloads["rust"])
        manifest = json.loads((self.rules / "manifest.json").read_text())
        self.assertEqual(manifest["packs"]["default"]["sha256"], hashlib.sha256(self.payloads["default"]).hexdigest())
        self.assertEqual(setup_sast.rules_status()["status"], "available")
        with patch.object(setup_sast.urllib.request, "urlopen") as network:
            self.assertEqual(setup_sast.fetch_rules()["status"], "already-present")
            network.assert_not_called()
        (self.rules / "rust.yaml").write_bytes(b"rules: []\n")
        self.assertEqual(setup_sast.rules_status()["status"], "changed")
        with patch.object(setup_sast.urllib.request, "urlopen", side_effect=self.serve()):
            self.assertEqual(setup_sast.fetch_rules(refresh=True)["status"], "installed")
        self.assertEqual(setup_sast.rules_status()["status"], "available")
        self.assertEqual(sorted(p.name for p in self.rules.parent.iterdir()), ["packs"])

    def test_bad_download_never_replaces_the_working_set(self):
        with patch.object(setup_sast.urllib.request, "urlopen", side_effect=self.serve()):
            setup_sast.fetch_rules()
        before = {p.name: p.read_bytes() for p in self.rules.iterdir()}
        insecure = lambda url, timeout: self.response(b"rules: []\n", "http://example.invalid/insecure")
        for name, opener in (("not a rule file", self.serve({"rust": b"<html>login</html>"})),
                             ("oversized", self.serve({"rust": b"rules:" + b"x" * 100})),
                             ("redirected to http", insecure)):
            with self.subTest(name), patch.object(setup_sast, "MAX_RULE_BYTES", 50), \
                 patch.object(setup_sast.urllib.request, "urlopen", side_effect=opener), self.assertRaises(ValueError):
                setup_sast.fetch_rules(refresh=True)
            self.assertEqual({p.name: p.read_bytes() for p in self.rules.iterdir()}, before)
            self.assertEqual(sorted(p.name for p in self.rules.parent.iterdir()), ["packs"])

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
