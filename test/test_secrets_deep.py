import argparse
import bz2
import io
import json
import lzma
import os
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch
import zipfile

SCRIPTS = Path(__file__).resolve().parents[1] / "skills/local-security-review/scripts"
sys.path.insert(0, str(SCRIPTS))
import render_review
import secret_archives
import secrets_deep
import setup_secrets


def zipped(name, data):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(name, data)
    return buffer.getvalue()


class DeepSecretsTests(unittest.TestCase):
    def git(self, repo, *args):
        return secrets_deep.git(repo, secrets_deep.git_env(), time.monotonic() + 30, *args).decode().strip()

    def commit(self, repo):
        self.git(repo, "add", "--all")
        self.git(repo, "-c", "user.name=Fixture", "-c", "user.email=test@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "--quiet", "--allow-empty", "-m", "Synthetic fixture")
        return self.git(repo, "rev-parse", "HEAD")

    def run_scan(self, repo, **kwargs):
        args = argparse.Namespace(target=str(repo), offline=False, timeout=90,
                                  max_history_mib=32, max_archive_mib=32)
        for key, value in kwargs.items():
            setattr(args, key, value)
        path, report = secrets_deep.execute(args)
        self.addCleanup(shutil.rmtree, path.parent)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(list(path.parent.iterdir()), [path])
        return report

    def test_real_historical_archives_deleted_files_nested_and_ignored_working_files(self):
        if setup_secrets.check()["status"] != "prerequisites-ready":
            self.skipTest("Pinned Gitleaks required")
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary) / "repo"
            repo.mkdir()
            self.git(repo, "init", "--quiet", "--template=")
            token = setup_secrets.fixture(repo)
            payload = (repo / "candidate.env").read_bytes()
            # Extensionless archives and unusual member names must survive metadata mapping.
            (repo / "bundle").write_bytes(zipped("inner.zip", zipped("nested\nfixture.env", payload)))
            (repo / "candidate.env").unlink()
            first = self.commit(repo)
            (repo / "bundle").unlink()
            self.commit(repo)
            (repo / ".gitignore").write_text(".env\n")
            (repo / ".env").write_bytes(payload)
            before = self.git(repo, "status", "--porcelain=v1")
            with patch.object(secrets_deep, "github_remote", return_value=("https://github.com/example/fixture.git", "example/fixture")), \
                 patch.object(secrets_deep, "fetch_github"):
                report = self.run_scan(repo)
            self.assertEqual(report["status"], "findings", report["coverage"])
            self.assertEqual(report["coverage"]["gaps"], [])
            history = [f for f in report["findings"] if f.get("commit") == first]
            self.assertTrue(any(f["path"] == "bundle!inner.zip!nested\nfixture.env" for f in history))
            self.assertTrue(any(f["path"].endswith(".env") and not f.get("commit") for f in report["findings"]))
            self.assertEqual(before, self.git(repo, "status", "--porcelain=v1"))
            self.assertEqual(len(report["findings"]), len({f["id"] for f in report["findings"]}))
            review = render_review.merge(report, [])
            self.assertNotIn(token, json.dumps(review) + render_review.markdown(review))
            self.assertIn(first, render_review.markdown(review))
            self.assertIn("blob", render_review.markdown(review))

    def test_real_offline_limits_and_fetch_failures_keep_findings(self):
        if setup_secrets.check()["status"] != "prerequisites-ready":
            self.skipTest("Pinned Gitleaks required")
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            self.git(repo, "init", "--quiet", "--template=")
            token = setup_secrets.fixture(repo)
            self.commit(repo)
            with patch.object(secrets_deep, "fetch_github") as fetch:
                offline = self.run_scan(repo, offline=True)
                fetch.assert_not_called()
            self.assertEqual(offline["status"], "incomplete")
            self.assertTrue(offline["findings"])
            self.assertTrue(any(f.get("blob") for f in offline["findings"]))
            with patch.object(secrets_deep, "github_remote", return_value=("https://github.com/example/fixture", "example/fixture")), \
                 patch.object(secrets_deep, "fetch_github", side_effect=ValueError(token)):
                failed = self.run_scan(repo)
            self.assertEqual(failed["status"], "incomplete")
            self.assertTrue(failed["findings"])
            self.assertNotIn(token, json.dumps(failed))
            with patch.object(secrets_deep, "MAX_BLOB_BYTES", 8):
                limited = self.run_scan(repo, offline=True)
            self.assertTrue(any("limit" in g["reason"] for g in limited["coverage"]["gaps"]))

    def test_fetch_refspecs_capture_branches_tags_and_prs_in_disposable_mirror(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, mirror = Path(temporary) / "repo", Path(temporary) / "mirror.git"
            repo.mkdir()
            self.git(repo, "init", "--quiet", "--template=")
            head = self.commit(repo)
            self.git(repo, "tag", "release")
            self.git(repo, "update-ref", "refs/pull/42/head", head)
            self.git(repo, "clone", "--quiet", "--mirror", "--no-hardlinks", "--template=", str(repo), str(mirror))
            before = self.git(repo, "show-ref")
            # Actual native fetch, local transport only; GitHub URL validation is tested separately.
            secrets_deep.fetch_github(mirror, str(repo), secrets_deep.git_env(), time.monotonic() + 30)
            refs = self.git(mirror, "for-each-ref", "--format=%(refname)", "refs/rasmus-github/")
            self.assertIn("refs/rasmus-github/pull/42/head", refs)
            self.assertIn("refs/rasmus-github/tags/release", refs)
            self.assertIn("refs/rasmus-github/heads/", refs)
            self.assertEqual(before, self.git(repo, "show-ref"))
            with self.assertRaisesRegex(ValueError, "namespace"):
                secrets_deep.fetch_github(mirror, str(repo), secrets_deep.git_env(), time.monotonic() + 30)

    def test_origin_rejects_credentials_other_hosts_helpers_and_includes(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            self.git(repo, "init", "--quiet", "--template=")
            for url in ("https://token@github.com/org/repo", "https://github.com.evil/org/repo",
                        "ext::malicious", "https://github.com/org/repo?token=secret", "https://github.com/../repo"):
                self.git(repo, "config", "remote.origin.url", url)
                with self.assertRaises(ValueError):
                    secrets_deep.github_remote(repo, secrets_deep.git_env(), time.monotonic() + 30)
            for url in ("https://github.com/org/repo.git", "git@github.com:org/repo.git", "ssh://git@github.com/org/repo"):
                self.git(repo, "config", "remote.origin.url", url)
                self.assertEqual(secrets_deep.github_remote(repo, secrets_deep.git_env(), time.monotonic() + 30)[1], "org/repo")

    def test_archives_are_bounded_and_never_extract_links_or_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            coverage = {"gaps": []}
            reader = secret_archives.ArchiveReader(output, coverage, time.monotonic() + 10,
                                                   max_bytes=64, max_depth=2, max_members=5)
            reader.inspect(zipped("../../escaped", b"value"), {"path": "unsafe.zip"})
            reader.inspect(zipped("large", b"x" * 1000), {"path": "bomb.zip"})
            reader.inspect(b"7z\xbc\xaf\x27\x1c", {"path": "archive"})
            reader.inspect(b"not a zip", {"path": "bad.zip"})
            self.assertEqual(len(coverage["gaps"]), 4)
            self.assertEqual(list(output.iterdir()), [])
            deep = secret_archives.ArchiveReader(output, coverage, time.monotonic() + 10, max_depth=1)
            deep.inspect(zipped("inner.zip", zipped("fixture.env", b"value")), {"path": "nested.zip"})
            self.assertTrue(any("nesting" in g["reason"] for g in coverage["gaps"]))
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
                link = tarfile.TarInfo("link")
                link.type, link.linkname = tarfile.SYMTYPE, "/outside"
                archive.addfile(link)
                file = tarfile.TarInfo("regular.env")
                file.size = 5
                archive.addfile(file, io.BytesIO(b"value"))
            tar_reader = secret_archives.ArchiveReader(output, coverage, time.monotonic() + 10)
            tar_reader.inspect(buffer.getvalue(), {"path": "safe.tgz"})
            self.assertEqual(len(tar_reader.locations), 1)
            self.assertTrue(any("Special/link" in g["reason"] for g in coverage["gaps"]))
            self.assertTrue(all(not p.is_symlink() for p in output.iterdir()))

    def test_compression_formats_encryption_and_exhausted_budget(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            coverage = {"gaps": []}
            reader = secret_archives.ArchiveReader(output, coverage, time.monotonic() + 10)
            reader.inspect(bz2.compress(b"fixture"), {"path": "data.bz2"})
            reader.inspect(lzma.compress(b"fixture"), {"path": "data.xz"})
            self.assertEqual(len(reader.locations), 2)
            self.assertEqual(coverage["gaps"], [])
            encrypted = bytearray(zipped("fixture", b"value"))
            # Mark both local and central headers encrypted; no password is supplied.
            encrypted[6] |= 1
            central = encrypted.index(b"PK\x01\x02")
            encrypted[central + 8] |= 1
            reader.inspect(bytes(encrypted), {"path": "encrypted.zip"})
            self.assertTrue(any("Encrypted" in gap["reason"] for gap in coverage["gaps"]))
            reader.bytes = reader.max_bytes + 1
            with self.assertRaises(ValueError):
                reader.read(io.BytesIO(b"must not be read"))
            reader.deadline = time.monotonic() - 1
            with self.assertRaises(TimeoutError):
                reader.inspect(zipped("fixture", b"value"), {"path": "archive.zip"})

    def test_real_shallow_history_and_lfs_stay_incomplete(self):
        if setup_secrets.check()["status"] != "prerequisites-ready":
            self.skipTest("Pinned Gitleaks required")
        with tempfile.TemporaryDirectory() as temporary:
            repo, shallow = Path(temporary) / "repo", Path(temporary) / "shallow"
            repo.mkdir()
            self.git(repo, "init", "--quiet", "--template=")
            setup_secrets.fixture(repo)
            self.commit(repo)
            (repo / "large.bin").write_text("version https://git-lfs.github.com/spec/v1\noid sha256:" + "0" * 64 + "\nsize 100\n")
            self.commit(repo)
            self.git(repo, "clone", "--quiet", "--depth=1", repo.as_uri(), str(shallow))
            report = self.run_scan(shallow, offline=True)
            self.assertTrue(report["coverage"]["history_shallow"])
            self.assertEqual(report["status"], "incomplete")
            self.assertTrue(any("LFS" in gap["reason"] for gap in report["coverage"]["gaps"]))
            self.assertTrue(report["findings"])


if __name__ == "__main__":
    unittest.main()
