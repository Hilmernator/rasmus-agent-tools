"""The findings ledger shared by local-security-review and local-dast."""
import contextlib
import csv
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SKILLS = Path(__file__).resolve().parents[1] / "skills"
sys.path.insert(0, str(SKILLS / "local-security-review/scripts"))
sys.path.insert(0, str(SKILLS / "security-gap-analysis/scripts"))
import gap
import ledger

FALSE_POSITIVE = {"disposition": "false-positive", "dismissal_reason": "The argument is a constant.", "evidence": "Read the caller."}
LIKELY = {"disposition": "likely", "evidence": "User input reaches the call."}
UNREVIEWED = {"disposition": "unreviewed", "evidence": "Not assessed; retained for review."}


def run(*argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = ledger.main([str(a) for a in argv])
    return code, out.getvalue()


def finding(id_, line, scanner="sast", path="app.py", rule="eval-used", **more):
    return {"id": id_, "scanner": scanner, "engine": "semgrep", "rule": rule, "path": path, "line": line, "end_line": line, **more}


class Ledger(unittest.TestCase):
    def setUp(self):
        self.repo = Path(tempfile.mkdtemp()).resolve()
        self.out = Path(tempfile.mkdtemp())
        (self.repo / "app.py").write_text("import os\neval(x)\nprint(1)\n")

    def review(self, *pairs, scope="working-tree", status="findings"):
        path = self.out / "review.json"
        path.write_text(json.dumps({"scan": {"target": str(self.repo), "scope": scope, "status": status},
                                    "findings": [{"scanner_finding": f, "assessment": a} for f, a in pairs]}))
        return run("record", self.repo, path)[1]

    def rows(self):
        with (self.repo / "security/findings.csv").open(newline="") as f:
            return list(csv.DictReader(f))

    def test_new_then_seen_before_then_changed_in_one_row(self):
        out = self.review((finding("SAST-0001", 2), FALSE_POSITIVE))
        self.assertRegex(out, r"1 rows; this run: 1 new; 0 pruned\nSAST-0001 [0-9a-f]{16} new\n")
        out = self.review((finding("SAST-0009", 2), FALSE_POSITIVE))
        self.assertIn("SAST-0009", out)
        self.assertIn("seen before: false-positive, basis code", out)
        out = self.review((finding("SAST-0001", 2), {**LIKELY, "proof": "test_eval fails"}))
        self.assertIn("changed: was false-positive (basis code), now likely", out)
        self.assertEqual([(r["status"], r["basis"], r["note"]) for r in self.rows()], [("likely", "test", "User input reaches the call.")])
        self.assertEqual(sorted(p.name for p in (self.repo / "security").iterdir()), ["findings.csv"])

    def test_the_fingerprint_follows_the_text_not_the_line(self):
        self.review((finding("SAST-0001", 2), FALSE_POSITIVE))
        (self.repo / "app.py").write_text("import os\n\n\n   eval(x)\nprint(1)\n")
        out = self.review((finding("SAST-0001", 4), FALSE_POSITIVE))
        self.assertIn("seen before", out)
        self.assertIn("file changed since that decision", out)
        (self.repo / "app.py").write_text("import os\neval(y)\n")
        out = self.review((finding("SAST-0001", 2), FALSE_POSITIVE))
        self.assertIn("SAST-0001", out)
        self.assertIn(" new", out)
        self.assertIn("1 pruned", out)
        self.assertEqual(len(self.rows()), 1)

    def test_an_unreviewed_finding_gets_no_earlier_verdict_and_no_row(self):
        self.review((finding("SAST-0001", 2), FALSE_POSITIVE))
        out = self.review((finding("SAST-0001", 2), UNREVIEWED), (finding("SAST-0002", 3, rule="print-used"), UNREVIEWED))
        self.assertNotIn("false-positive", out)
        self.assertNotIn("SAST-0001", out)
        self.assertIn("2 unreviewed, not recorded", out)
        self.assertEqual([r["status"] for r in self.rows()], ["false-positive"])

    def test_a_decision_by_the_user_is_kept_and_the_disagreement_shown(self):
        self.review((finding("SAST-0001", 2), LIKELY))
        fp = self.rows()[0]["fingerprint"]
        run("decide", self.repo, fp, "--status", "false-positive", "--note", "=Only reachable in tests.")
        out = self.review((finding("SAST-0001", 2), LIKELY))
        self.assertIn("decided by user: false-positive; this run says likely", out)
        self.assertEqual([(r["status"], r["basis"], r["note"]) for r in self.rows()], [("false-positive", "user", "Only reachable in tests.")])

    def test_only_a_complete_full_scan_drops_what_it_did_not_see(self):
        other = finding("SAST-0002", 3, rule="print-used")
        self.review((finding("SAST-0001", 2), LIKELY), (other, LIKELY))
        for scope, status in (("working-tree-hybrid-diff", "findings"), ("working-tree", "incomplete")):
            self.review((other, LIKELY), scope=scope, status=status)
            self.assertEqual(len(self.rows()), 2, scope)
        self.assertIn("1 pruned", self.review((other, LIKELY)))
        self.assertEqual([r["rule"] for r in self.rows()], ["print-used"])
        (self.repo / "app.py").unlink()
        self.assertIn("1 pruned", self.review(scope="working-tree-hybrid-diff"))
        self.assertEqual(self.rows(), [])

    def test_a_commit_snapshot_is_not_recorded(self):
        self.assertIn("not recorded", self.review((finding("SAST-0001", 2), LIKELY), scope="commit-snapshot"))
        self.assertFalse((self.repo / "security").exists())

    def test_nothing_of_a_secret_is_stored(self):
        (self.repo / "conf.ini").write_text("key = first\n")
        secret = finding("SECRETS-0001", 1, scanner="secrets", path="conf.ini", rule="generic-api-key")
        self.review((secret, {**FALSE_POSITIVE, "dismissal_reason": "", "evidence": "The value is first."}))
        self.assertEqual([r["note"] for r in self.rows()], [""])
        (self.repo / "conf.ini").write_text("key = second\n")
        self.assertIn("seen before", self.review((secret, FALSE_POSITIVE)))
        self.assertEqual([(r["sha"], "first" in r["note"]) for r in self.rows()], [("", False)])

    def test_dependencies_are_keyed_by_package_not_by_version(self):
        dep = finding("SCA-0001", 0, scanner="sca", path="package-lock.json", rule="GHSA-x", package={"name": "left-pad", "version": "1.0.0"})
        self.review((dep, LIKELY))
        dep["package"]["version"] = "1.0.1"
        self.assertIn("seen before", self.review((dep, LIKELY)))

    def test_a_review_of_another_target_and_a_broken_ledger_are_refused(self):
        with self.assertRaises(SystemExit):
            self.review()
            run("record", self.out, self.out / "review.json")
        self.review((finding("SAST-0001", 2), LIKELY))
        path = self.repo / "security/findings.csv"
        path.write_text(path.read_text().replace(",likely,", ",fixed,"))
        with self.assertRaises(SystemExit):
            self.review((finding("SAST-0001", 2), LIKELY))

    def dast(self, assessments, observed=("anonymous-health",)):
        report = {"cases": [{"id": "anonymous-health", "state": "pass"}, {"id": "peer-cannot-read", "state": "assertion-failed"}],
                  "zap": {"status": "complete"}, "findings": [{"id": "DAST-0001", "alert_ref": "10038-1", "observed_cases": list(observed)}]}
        (self.out / "report.json").write_text(json.dumps(report))
        (self.out / "assessments.json").write_text(json.dumps(assessments))
        return run("record", self.repo, self.out / "report.json", "--assessments", self.out / "assessments.json")[1]

    def test_dast_candidates_share_the_file_and_keep_their_own_rows(self):
        self.review((finding("SAST-0001", 2), LIKELY))
        confirmed = {"id": "peer-cannot-read", "disposition": "confirmed", "basis": "test", "note": "The peer read the owner's document."}
        self.assertIn("peer-cannot-read", self.dast([confirmed]))
        out = self.dast([confirmed, {"id": "DAST-0001", "disposition": "false-positive", "basis": "code", "note": "Header is set by the proxy."}])
        self.assertIn("seen before: confirmed, basis test", out)
        # ZAP reports a sample of a rule's instances, so the cases it names differ between runs of one plan. The rule is the row.
        again = self.dast([confirmed, {"id": "DAST-0001", "disposition": "false-positive", "basis": "code", "note": "Header is set by the proxy."}],
                          observed=["anonymous-health", "peer-cannot-read"])
        self.assertIn("seen before: false-positive, basis code", again)
        self.assertEqual([(r["skill"], r["rule"], r["path"]) for r in self.rows()],
                         [("local-dast", "case:peer-cannot-read", ""), ("local-dast", "zap:10038-1", ""), ("local-security-review", "eval-used", "app.py")])
        self.review()
        self.assertEqual({r["skill"] for r in self.rows()}, {"local-dast"})
        for bad in ([{"id": "anonymous-health", "disposition": "likely", "basis": "code", "note": "x"}], [{**confirmed, "basis": "user"}]):
            with self.assertRaises(SystemExit):
                self.dast(bad)

    def test_the_ledger_is_ignored_by_git_unless_it_is_tracked(self):
        def git(*args):
            return subprocess.run(["git", "-C", str(self.repo), *args], capture_output=True, text=True)
        git("init", "-q")
        self.assertIn("ignored: added security/findings.csv", self.review((finding("SAST-0001", 2), LIKELY)))
        self.assertEqual(git("status", "--porcelain", "--", "security").stdout, "")
        self.assertNotIn("ignored:", self.review((finding("SAST-0001", 2), LIKELY)))
        exclude = self.repo / ".git/info/exclude"
        exclude.write_text("")
        git("add", "security/findings.csv")
        self.review((finding("SAST-0001", 2), LIKELY))
        self.assertEqual(exclude.read_text(), "")


class Package(unittest.TestCase):
    def test_both_skills_bundle_the_same_ledger_and_gap_knows_its_header(self):
        self.assertEqual((SKILLS / "local-security-review/scripts/ledger.py").read_bytes(), (SKILLS / "local-dast/scripts/ledger.py").read_bytes())
        self.assertEqual(gap.FINDING_FIELDS, ledger.FIELDS)


if __name__ == "__main__":
    unittest.main()
