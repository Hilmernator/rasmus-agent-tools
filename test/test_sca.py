import argparse
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / "skills/local-security-review/scripts"
sys.path.insert(0, str(SCRIPTS))
import scan
import setup_sca
import render_review


class ScaTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("AGENT_TOOLS_SCA_TEST_NETWORK") == "1", "Explicit network test opt-in required")
    def test_real_default_scan_refreshes_then_matches_locally(self):
        with tempfile.TemporaryDirectory() as temporary:
            setup_sca.fixture(Path(temporary))
            args = argparse.Namespace(scanner="sca", target=temporary, allow_network=False,
                                      history=False, semgrep_config=None, commit=None, diff=False, timeout=300)
            path, report = scan.execute(args)
            self.addCleanup(shutil.rmtree, path.parent)
            self.assertEqual(report["status"], "findings", report.get("error"))
            self.assertEqual(report["database_refresh"]["status"], "succeeded")
            self.assertEqual(report["database_refresh"]["ecosystems"], ["PyPI", "npm"])
            self.assertIn("checked_at", report["database_refresh"])
            self.assertEqual(report["advisory_mode"], "refresh-then-local")
            self.assertIn("--offline", report["command"])
            self.assertIn("--download-offline-databases", report["command"])

    def test_setup_check_missing_and_integrity(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(setup_sca, "CACHE", Path(temporary)), patch.object(setup_sca, "DB", Path(temporary) / "db"):
                with patch.object(setup_sca.urllib.request, "urlopen") as download:
                    self.assertEqual(setup_sca.check()["status"], "needs-setup")
                    download.assert_not_called()
                    path = setup_sca.executable()
                    path.parent.mkdir()
                    path.write_bytes(b"not the reviewed binary")
                    with self.assertRaisesRegex(ValueError, "integrity"):
                        setup_sca.install()
                    self.assertEqual(path.read_bytes(), b"not the reviewed binary")
                    download.assert_not_called()

    def test_download_checksum_failure_never_publishes(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(setup_sca, "CACHE", Path(temporary)):
                response = io.BytesIO(b"untrusted binary")
                response.url = "https://example.invalid/binary"
                with patch.object(setup_sca.urllib.request, "urlopen", return_value=response):
                    with self.assertRaisesRegex(ValueError, "checksum"):
                        setup_sca.install()
                self.assertFalse(setup_sca.executable().exists())

    def test_projection_and_renderer_preserve_all_aliases_without_fake_lines(self):
        findings, coverage = scan.project("sca", {"results": [{
            "source": {"path": "requirements.txt", "type": "lockfile"}, "packages": [{
                "package": {"name": "example", "version": "1", "ecosystem": "PyPI"},
                "vulnerabilities": [{"id": "GHSA-example", "aliases": ["CVE-example"], "details": "omit me"},
                                    {"id": "PYSEC-example", "aliases": ["CVE-example"]}]}]}]})
        self.assertEqual([f["id"] for f in findings], ["SCA-0001", "SCA-0002"])
        self.assertEqual(coverage["scanned_packages"], 1)
        self.assertEqual(findings[0]["aliases"], ["CVE-example"])
        self.assertNotIn("omit me", json.dumps(findings))
        report = {"findings": findings, "status": "incomplete", "scope": "working-tree"}
        review = render_review.merge(report, [])
        rendered = render_review.markdown(review)
        self.assertIn("example@1", rendered)
        self.assertNotIn("requirements.txt:1", rendered)
        self.assertEqual(review["summary"]["unresolved_issue_groups"], 2)
        self.assertEqual(review["scan"], report)

    def test_real_offline_sca_and_repository_suppression_isolation(self):
        if setup_sca.check()["status"] != "prerequisites-ready":
            self.skipTest("Pinned OSV and offline npm/PyPI databases not installed")
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            setup_sca.fixture(target)
            (target / "osv-scanner.toml").write_text('[[PackageOverrides]]\nignore = true\n')
            original = {p.name: p.read_bytes() for p in target.iterdir()}
            args = argparse.Namespace(scanner="sca", target=str(target), allow_network=False,
                                      history=False, semgrep_config=None, commit=None, diff=False, timeout=120, offline=True)
            path, report = scan.execute(args)
            self.addCleanup(shutil.rmtree, path.parent)
            self.assertEqual(report["status"], "findings", report.get("error"))
            self.assertEqual({f["package"]["ecosystem"] for f in report["findings"]}, {"npm", "PyPI", "crates.io"})
            self.assertIn("--no-ignore", report["command"])
            # Nested build trees (rust-analyzer keeps lockfile copies under crate/target/) stay excluded.
            exclude = report["command"][report["command"].index("--experimental-exclude") + 1]
            self.assertRegex("crate/target", exclude.removeprefix("r:"))
            self.assertNotRegex("crate/targets", exclude.removeprefix("r:"))
            self.assertTrue(all("fixed_versions" in f for f in report["findings"]))
            self.assertIn("--no-call-analysis=all", report["command"])
            self.assertIn("--offline", report["command"])
            self.assertNotIn("--download-offline-databases", report["command"])
            self.assertFalse(report["network_allowed"])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertTrue(all(item["present"] for item in report["advisory_databases"]))
            self.assertEqual({p.name: p.read_bytes() for p in target.iterdir()}, original)
            # A malformed second root must not disappear behind the successful first root.
            broken = target / "broken"
            broken.mkdir()
            (broken / "package-lock.json").write_text("{malformed")
            path, partial = scan.execute(args)
            self.addCleanup(shutil.rmtree, path.parent)
            self.assertEqual(partial["status"], "incomplete")
            self.assertTrue(partial["findings"])


if __name__ == "__main__":
    unittest.main()
