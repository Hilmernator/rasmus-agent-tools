"""Evidence-backed grouping preserves every scanner result and assessment."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


RUNNER = Path(__file__).resolve().parents[1] / "skills/local-security-review/scripts/render_review.py"
spec = importlib.util.spec_from_file_location("group_review", RUNNER)
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)


class GroupTests(unittest.TestCase):
    def setUp(self):
        self.report = {"status": "findings", "scope": "working-tree", "findings": [
            {"id": f"SAST-{i:04d}", "engine": engine, "rule": rule,
             "path": "app.py", "line": 10, "scanner_severity": severity}
            for i, engine, rule, severity in [(1, "semgrep", "url-fetch", "ERROR"),
                                             (2, "bandit", "B310", "MEDIUM"),
                                             (3, "bandit", "different-risk", "LOW")]]}
        self.assessments = [{"id": finding["id"], "disposition": "likely", "confidence": "medium",
            "assessed_severity": "medium", "evidence": "app.py:10 follows redirects without validating the next host.",
            "evidence_refs": [{"path": "app.py", "line": 10}],
            "preconditions": "Requires an attacker-controlled redirect on an allowed host; not demonstrated.",
            "recommendation": "Validate each redirect destination."} for finding in self.report["findings"]]
        self.group = {"title": "Possible SSRF via redirects", "finding_ids": ["SAST-0001", "SAST-0002"],
                      "root_cause": "Both refer to the same missing redirect destination check in the same request flow.",
                      "evidence": "app.py:10 is the common request sink; both rules concern this call.",
                      "preconditions": self.assessments[0]["preconditions"],
                      "recommendation": "Validate each redirect destination."}

    def test_group_is_lossless_and_unrelated_same_line_candidate_stays_separate(self):
        original = copy.deepcopy((self.report, self.assessments, self.group))
        result = review.merge(self.report, self.assessments, [self.group])
        self.assertEqual((self.report, self.assessments, self.group), original)
        self.assertEqual(result["scan"], self.report)
        self.assertEqual([r["assessment"] for r in result["findings"]], self.assessments)
        self.assertEqual(len(result["issues"]), 2)
        self.assertEqual(result["issues"][0]["finding_ids"], ["SAST-0001", "SAST-0002"])
        self.assertEqual(result["issues"][1]["finding_ids"], ["SAST-0003"])
        self.assertEqual(result["summary"]["scanner_findings"], 3)
        rendered = review.markdown(result)
        self.assertEqual(rendered.split("## Fix plan")[1].split("## All candidates")[0].count("\n### "), 2)
        for finding in self.report["findings"]:
            self.assertIn(finding["id"], rendered)
        self.assertIn("not demonstrated", rendered)

    def test_no_groups_never_deduplicates_by_location_or_rule(self):
        result = review.merge(self.report, self.assessments)
        self.assertEqual(len(result["issues"]), 3)
        self.assertEqual(review.merge(self.report, [])["counts"], {"unreviewed": 3})
        empty = review.merge({**self.report, "findings": []}, [], [])
        self.assertEqual(empty["summary"]["issue_groups"], 0)
        self.assertIn("No confirmed/likely", review.markdown(empty))

    def test_38_signals_become_one_actionable_issue_and_36_explicit_dismissals(self):
        report = copy.deepcopy(self.report)
        report["findings"] = report["findings"][:2] + [
            {**self.report["findings"][2], "id": f"SAST-{i:04d}"} for i in range(3, 39)]
        assessments = self.assessments[:2] + [
            {**self.assessments[2], "id": f"SAST-{i:04d}", "disposition": "false-positive",
             "confidence": "high", "dismissal_reason": "Fixture input is constant and isolated from deployed paths."}
            for i in range(3, 39)]
        result = review.merge(report, assessments, [self.group])
        self.assertEqual(result["summary"], {"scanner_findings": 38, "agent_findings": 0, "issue_groups": 37,
            "actionable_issue_groups": 1, "unresolved_issue_groups": 0, "false_positive_scanner_findings": 36})
        self.assertEqual(review.markdown(result).split("## Fix plan")[1].split("## All candidates")[0].count("\n### "), 1)
        self.assertEqual(len(result["findings"]), 38)
        self.assertEqual({i for group in result["issues"] for i in group["finding_ids"]},
                         {f["id"] for f in report["findings"]})

    def test_unknown_duplicate_overlapping_and_unexplained_groups_fail(self):
        for groups in ([{**self.group, "finding_ids": ["SAST-0001", "unknown"]}],
                       [{**self.group, "finding_ids": ["SAST-0001", "SAST-0001"]}],
                       [self.group, self.group], [{**self.group, "finding_ids": ["SAST-0001"]}],
                       [{**self.group, "root_cause": " "}], {}, [{**self.group, "preconditions": ""}]):
            with self.subTest(groups=groups), self.assertRaises(ValueError):
                review.merge(self.report, self.assessments, groups)

    def test_disagreement_cannot_hide_or_dismiss_an_actionable_finding(self):
        for disposition in ("needs-review", "unreviewed", "false-positive"):
            assessments = copy.deepcopy(self.assessments)
            assessments[1].update(disposition=disposition, confidence="high", dismissal_reason="Constant fixture input.")
            with self.subTest(disposition=disposition), self.assertRaises(ValueError):
                review.merge(self.report, assessments, [self.group])
        with self.assertRaises(ValueError):
            review.merge(self.report, self.assessments[:1], [self.group])
        self.assessments[0].update(disposition="confirmed", assessed_severity="high", confidence="high")
        self.assessments[1]["confidence"] = "low"
        issue = review.merge(self.report, self.assessments, [self.group])["issues"][0]
        self.assertEqual((issue["disposition"], issue["assessed_severity"], issue["confidence"]), ("likely", "high", "low"))
        self.assessments[1]["assessed_severity"] = "unknown"
        self.assertEqual(review.merge(self.report, self.assessments, [self.group])["issues"][0]["assessed_severity"], "unknown")

    def test_false_positive_requires_explicit_reason_reference_and_high_confidence(self):
        fp = {**self.assessments[0], "disposition": "false-positive", "confidence": "high",
              "dismissal_reason": "This call uses a literal constant; untrusted input cannot reach the argument."}
        for changes in ({"dismissal_reason": ""}, {"evidence_refs": []}, {"confidence": "medium"},
                        {"evidence_refs": [{"path": "app.py", "line": True}]},
                        {"evidence_refs": [{"path": "app.py", "line": 0}]}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                review.merge(self.report, [{**fp, **changes}])
        result = review.merge(self.report, [fp])
        self.assertIn(fp["dismissal_reason"], review.markdown(result))
        self.assertEqual(result["summary"]["false_positive_scanner_findings"], 1)
        self.assertEqual(result["summary"]["unresolved_issue_groups"], 2)
        for changes in ({"preconditions": ""}, {"evidence_refs": []}, {"confidence": "certain"}):
            with self.assertRaises(ValueError):
                review.merge(self.report, [{**self.assessments[0], **changes}])

    def test_cli_groups_counts_appendix_permissions_and_rerender(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, data in (("report", self.report), ("assessments", self.assessments), ("groups", [self.group])):
                (root / f"{name}.json").write_text(json.dumps(data))
            command = [sys.executable, str(RUNNER), str(root / "report.json"), str(root / "assessments.json"),
                       "--groups", str(root / "groups.json")]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            summary = json.loads(result.stdout)["summary"]
            self.assertEqual((summary["scanner_findings"], summary["actionable_issue_groups"]), (3, 2))
            output = root / "review.json"
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            # Rerendering after edits replaces the review; inputs beside the report are found by default.
            self.assertEqual(subprocess.run([sys.executable, str(RUNNER), str(root / "report.json")],
                                            capture_output=True).returncode, 0)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(output.read_text())["summary"]["actionable_issue_groups"], 2)
            invalid = [{**self.assessments[0], "disposition": "confirmed", "preconditions": ""}]
            (root / "assessments.json").write_text(json.dumps(invalid))
            before = output.read_bytes()
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
            self.assertEqual(before, output.read_bytes())


if __name__ == "__main__":
    unittest.main()
