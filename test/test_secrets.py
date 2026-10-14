import argparse
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
import scan
import setup_secrets
import render_review


class SecretsTests(unittest.TestCase):
    def test_setup_missing_and_corrupt_cache_do_not_install_or_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(setup_secrets, "CACHE", Path(temporary)):
            with patch.object(setup_secrets.urllib.request, "urlopen") as download:
                self.assertEqual(setup_secrets.check()["status"], "needs-setup")
                setup_secrets.root().mkdir(parents=True)
                archive = setup_secrets.root() / "release.tar.gz"
                archive.write_bytes(b"corrupt")
                with self.assertRaisesRegex(ValueError, "checksum"):
                    setup_secrets.install()
                self.assertEqual(archive.read_bytes(), b"corrupt")
                download.assert_not_called()

    def test_download_mismatch_never_publishes(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(setup_secrets, "CACHE", Path(temporary)):
            response = io.BytesIO(b"untrusted archive")
            response.url = "https://example.invalid/archive"
            with patch.object(setup_secrets.urllib.request, "urlopen", return_value=response):
                with self.assertRaisesRegex(ValueError, "checksum"):
                    setup_secrets.install()
            self.assertFalse(setup_secrets.root().exists())

    def test_archive_rejects_links_instead_of_extracting_them(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "archive.tar.gz"
            with tarfile.open(path, "w:gz") as archive:
                link = tarfile.TarInfo("gitleaks")
                link.type = tarfile.SYMTYPE
                link.linkname = "../../outside"
                archive.addfile(link)
            expected = setup_secrets.hashlib.sha256(path.read_bytes()).hexdigest()
            with patch.dict(setup_secrets.HASHES, {setup_secrets.artifact(): expected}):
                with self.assertRaisesRegex(ValueError, "member"):
                    setup_secrets.archive_contents(path)

    def real_scan(self, target, history=False):
        args = argparse.Namespace(scanner="secrets", target=str(target), history=history,
                                  allow_network=False, semgrep_config=None, commit=None, diff=False, timeout=60)
        path, report = scan.execute(args)
        self.addCleanup(shutil.rmtree, path.parent)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(list(path.parent.iterdir()), [path])
        return report

    def test_real_redaction_suppressions_ignored_files_and_negative_control(self):
        if setup_secrets.check()["status"] != "prerequisites-ready":
            self.skipTest("Pinned Gitleaks not installed")
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            token = setup_secrets.fixture(target)
            (target / ".gitignore").write_text("candidate.env\n")
            (target / ".gitleaksignore").write_text("candidate.env:github-pat:1\n")
            (target / ".gitleaks.toml").write_text('[extend]\nuseDefault = true\n[allowlist]\npaths = [\'.*\']\n')
            original = {p.name: p.read_bytes() for p in target.iterdir()}
            with patch.dict(os.environ, {"GITLEAKS_CONFIG_TOML": "malformed secret-bearing config"}):
                report = self.real_scan(target)
            self.assertEqual(report["status"], "findings", report.get("error"))
            self.assertTrue(any(f["rule"] == "github-pat" for f in report["findings"]))
            review = render_review.merge(report, [])
            retained = json.dumps(review) + render_review.markdown(review)
            self.assertNotIn(token, retained)
            self.assertNotIn("malformed secret-bearing config", retained)
            self.assertEqual(review["summary"]["scanner_findings"], len(report["findings"]))
            self.assertFalse(report["network_allowed"])
            self.assertEqual({p.name: p.read_bytes() for p in target.iterdir()}, original)
        self.assertEqual(setup_secrets.verify()["status"], "ready")

    def test_real_deleted_secret_history_and_shallow_coverage(self):
        if setup_secrets.check()["status"] != "prerequisites-ready" or not shutil.which("git"):
            self.skipTest("Pinned Gitleaks and Git required")
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "repo"
            target.mkdir()
            env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
            def git(*args):
                return subprocess.run(["git", "-C", str(target), *args], env=env, check=True,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode().strip()
            git("init", "--quiet", "--template=")
            token = setup_secrets.fixture(target)
            git("add", ".")
            def commit(message):
                git("-c", "user.name=Test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false",
                    "-c", "core.hooksPath=/dev/null", "commit", "--quiet", "-m", message)
            commit("Synthetic fixture")
            exposed_commit = git("rev-parse", "HEAD")
            (target / "candidate.env").unlink()
            git("add", "--all")
            commit("Remove fixture")
            self.assertEqual(self.real_scan(target)["status"], "no-findings")
            report = self.real_scan(target, history=True)
            self.assertEqual(report["status"], "findings", report.get("error"))
            self.assertTrue(any(f["commit"] == exposed_commit for f in report["findings"]))
            self.assertNotIn(token, json.dumps(report))
            self.assertIn(exposed_commit, render_review.markdown(render_review.merge(report, [])))
            self.assertEqual(git("status", "--porcelain"), "")
            shallow = Path(temporary) / "shallow"
            git("clone", "--quiet", "--depth=1", target.as_uri(), str(shallow))
            self.assertEqual(self.real_scan(shallow, history=True)["status"], "incomplete")


if __name__ == "__main__":
    unittest.main()
