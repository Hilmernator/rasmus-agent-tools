"""Investigation outputs: bulk assessments, agent findings, fix plan, secret probe."""
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
sys.path.insert(0, str(SCRIPTS))
import iac
import scan
import secret_probe

spec = importlib.util.spec_from_file_location("render_review", SCRIPTS / "render_review.py")
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)

REPORT = {"status": "findings", "scope": "working-tree", "findings": [
    {"id": "SAST-0001", "engine": "bandit", "rule": "B101", "path": "tests/test_a.py", "line": 3, "scanner_severity": "LOW"},
    {"id": "SAST-0002", "engine": "bandit", "rule": "B101", "path": "tests/test_b.py", "line": 7, "scanner_severity": "LOW"},
    {"id": "SAST-0003", "engine": "semgrep", "rule": "cors", "path": "src/main.rs", "line": 26, "scanner_severity": "WARNING"},
]}
DISMISS = {"ids": ["SAST-0001", "SAST-0002"], "disposition": "false-positive", "confidence": "high",
           "assessed_severity": "info", "evidence": "Pytest asserts.", "evidence_refs": [{"path": "tests/test_a.py", "line": 3}],
           "dismissal_reason": "Asserts run only in tests.", "recommendation": "No change."}
CORS = {"id": "SAST-0003", "disposition": "likely", "confidence": "medium", "assessed_severity": "low",
        "evidence": "Any origin may call the API.", "evidence_refs": [{"path": "src/main.rs", "line": 26}],
        "preconditions": "Victim browses a hostile page while the API runs.", "recommendation": "Allow only the UI origin."}
HUNTED = [{"id": "AGENT-0001", "title": "Path traversal in GET /get", "rule": "path-traversal",
           "path": "src/handlers/read.rs", "line": 11, "cwe": "CWE-22"}]
TRAVERSAL = {"id": "AGENT-0001", "disposition": "confirmed", "confidence": "high", "assessed_severity": "high",
             "evidence": "Request path reaches fs::read_to_string unchanged.",
             "evidence_refs": [{"path": "src/handlers/read.rs", "line": 11}], "preconditions": "None.",
             "proof": "cargo test traversal: read ../Cargo.toml succeeded.",
             "recommendation": "Canonicalize and require the uploads prefix.", "verify": "cargo test traversal"}


class RenderTests(unittest.TestCase):
    def test_bulk_assessment_agent_findings_and_fix_plan_order(self):
        result = review.merge(REPORT, [DISMISS, CORS, TRAVERSAL], [], HUNTED)
        self.assertEqual(result["counts"], {"false-positive": 2, "likely": 1, "confirmed": 1})
        self.assertEqual((result["summary"]["scanner_findings"], result["summary"]["agent_findings"]), (3, 1))
        # The two-ID dismissal is one issue, not two.
        self.assertEqual(result["summary"]["issue_groups"], 3)
        self.assertIn(["SAST-0001", "SAST-0002"], [issue["finding_ids"] for issue in result["issues"]])
        text = review.markdown(result)
        plan = text.split("## Fix plan")[1].split("## All candidates")[0]
        self.assertLess(plan.index("Path traversal"), plan.index("cors"))
        self.assertIn("**Proven by:** cargo test traversal", plan)
        self.assertIn("**Verify the fix:** cargo test traversal", plan)
        self.assertIn("src/handlers/read.rs:11", plan)
        for finding_id in ("SAST-0001", "SAST-0002", "AGENT-0001"):
            self.assertIn(finding_id, text)

    def test_invalid_bulk_and_agent_entries_fail(self):
        for assessments, hunted in (([{**DISMISS, "id": "SAST-0001"}], []), ([{**DISMISS, "ids": []}], []),
                                    ([DISMISS, {**CORS, "id": "SAST-0001"}], []),
                                    ([], [{**HUNTED[0], "line": 0}]), ([], [{**HUNTED[0], "id": "SAST-0099"}]),
                                    ([{**TRAVERSAL, "proof": " "}], HUNTED)):
            with self.subTest(assessments=str(assessments)[:60], hunted=str(hunted)[:40]), self.assertRaises(ValueError):
                review.merge(REPORT, assessments, [], hunted)


class ScannerProjectionTests(unittest.TestCase):
    def test_semgrep_duplicates_across_packs_and_parse_warnings(self):
        result = {"check_id": "rust.lang.security.unsafe-usage", "path": "a.rs", "start": {"line": 3, "col": 5},
                  "end": {"line": 3, "col": 9}, "extra": {"severity": "WARNING", "metadata": {}}}
        findings, coverage = scan.project("sast", {"results": [result, dict(result)], "paths": {"scanned": ["a.rs"]},
                                                   "errors": [{"type": "PartialParsing", "level": "warn", "path": "b.tsx"}]})
        self.assertEqual([item["id"] for item in findings], ["SAST-0001"])
        self.assertEqual((coverage["scanner_errors"], coverage["parse_warnings"]), (0, 1))

    def test_sca_marks_the_same_advisory_under_another_id(self):
        findings, _ = scan.project("sca", {"results": [{"source": {"path": "Cargo.lock"}, "packages": [{
            "package": {"name": "bytes", "version": "1.10.1", "ecosystem": "crates.io"},
            "vulnerabilities": [{"id": "RUSTSEC-1", "aliases": ["GHSA-1"]}, {"id": "GHSA-1", "aliases": ["RUSTSEC-1"]},
                                {"id": "RUSTSEC-2"}]}]}]})
        self.assertEqual([f.get("duplicate_of") for f in findings], [None, "SCA-0001", None])

    def test_terraform_module_guard_only_flags_downloadable_modules(self):
        self.assertFalse(iac.remote_modules("ec2.tf", b'user_data = file("${path.module}/proxy.sh")\n'))
        self.assertFalse(iac.remote_modules("main.tf", b'module "net" {\n  source = "./modules/net"\n}\n'))
        self.assertTrue(iac.remote_modules("main.tf", b'module "vpc" {\n  source = "terraform-aws-modules/vpc/aws"\n}\n'))
        self.assertTrue(iac.remote_modules("main.tf.json", json.dumps({"module": {"x": {"source": "git::https://e.invalid/m"}}}).encode()))
        self.assertFalse(iac.likely_iac("frontend/package-lock.json"))
        self.assertTrue(iac.likely_iac("infra/Dockerfile"))


@unittest.skipUnless(shutil.which("git"), "Git required")
class SecretProbeTests(unittest.TestCase):
    def test_probe_classifies_without_printing_values(self):
        real = "sk_live_" + "Zq8" + "rT2vX9mKp4LwN7bHs3JdYc6Fu1Ge5Ra0"
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            env = {**{k: v for k, v in os.environ.items() if not k.startswith("GIT_")},
                   "GIT_CONFIG_GLOBAL": os.devnull, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@e.invalid",
                   "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@e.invalid"}
            subprocess.run(["git", "init", "-q", str(repo)], check=True, env=env)
            (repo / "config.py").write_text(f'API_KEY = "{real}"\nOTHER = "your_api_key_here_example"\n'
                                            'ENVKEY = os.environ["API_KEY"]\nWEAK = "SUPER_SECRET_API_KEY"\n')
            (repo / ".gitignore").write_text(".env\n")
            (repo / ".env").write_text(f"TOKEN={real}\n")
            subprocess.run(["git", "-C", str(repo), "add", "config.py", ".gitignore"], check=True, env=env)
            subprocess.run(["git", "-C", str(repo), "commit", "-qm", "x"], check=True, env=env)
            report = repo.parent / f"{repo.name}-report.json"
            findings = [{"id": f"SECRET-000{i}", "path": path, "line": line, "commit": ""}
                        for i, (path, line) in enumerate((("config.py", 1), ("config.py", 2), ("config.py", 3), (".env", 1)), 1)]
            report.write_text(json.dumps({"target": str(repo), "findings": findings}))
            self.addCleanup(report.unlink)
            output = subprocess.run([sys.executable, str(SCRIPTS / "secret_probe.py"), str(report), "--history"],
                                    capture_output=True, text=True, check=True).stdout
            self.assertNotIn(real, output)
            self.assertNotIn("your_api_key", output)
            result = {item["id"]: item for item in json.loads(output)}
            self.assertEqual(result["SECRET-0001"]["hint"], "looks-real-and-committed: rotate")
            self.assertTrue(result["SECRET-0002"]["looks_like_placeholder"])
            self.assertTrue(result["SECRET-0003"]["references_environment_or_template"])
            self.assertEqual(result["SECRET-0004"]["hint"], "looks-real-and-committed: rotate")
            self.assertTrue(result["SECRET-0004"]["git_ignored"])
            self.assertTrue(result["SECRET-0004"]["value_ever_committed"])
            by_file = subprocess.run([sys.executable, str(SCRIPTS / "secret_probe.py"), "--repo", str(repo), "--file", "config.py"],
                                     capture_output=True, text=True, check=True).stdout
            self.assertNotIn(real, by_file)
            hints = {item["id"]: item["hint"] for item in json.loads(by_file)}
            self.assertEqual(hints["config.py:4"], "low-entropy-literal: check where it is used; committed")


if __name__ == "__main__":
    unittest.main()
