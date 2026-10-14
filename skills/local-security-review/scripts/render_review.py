#!/usr/bin/env python3
"""Merge AI assessments by finding ID without dropping any scanner candidates."""

import argparse
from collections import Counter
import html
import json
import os
from pathlib import Path


DISPOSITIONS = {"confirmed", "likely", "false-positive", "needs-review", "unreviewed"}
SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")
CONFIDENCES = ("unknown", "low", "medium", "high")


def location(finding):
    result = finding["path"]
    if finding.get("line"):
        result += f":{finding['line']}"
    if finding.get("commit"):
        result += f" (commit {finding['commit']})"
    if finding.get("blob"):
        result += f" (blob {finding['blob']})"
    if finding.get("package"):
        package = finding["package"]
        result += f" ({package.get('ecosystem', 'unknown')}: {package.get('name', '?')}@{package.get('version', '?')})"
    return result


def require_text(item, *keys):
    for key in keys:
        if not isinstance(item.get(key), str) or not item[key].strip():
            raise ValueError(f"Requires nonempty {key}")


def validate_assessment(item):
    if item.get("disposition") not in DISPOSITIONS:
        raise ValueError("Invalid AI disposition")
    require_text(item, "confidence", "assessed_severity", "evidence", "recommendation")
    if item["confidence"] not in CONFIDENCES or item["assessed_severity"] not in SEVERITIES:
        raise ValueError("Invalid confidence or assessed severity")
    refs = item.get("evidence_refs")
    if item["disposition"] in ("confirmed", "likely", "false-positive") or "evidence_refs" in item:
        if not isinstance(refs, list) or not refs:
            raise ValueError("Confirmed/likely/false-positive assessments require evidence_refs; otherwise use needs-review")
        for ref in refs:
            if not isinstance(ref, dict):
                raise ValueError("Each evidence reference requires path and line")
            require_text(ref, "path")
            if type(ref.get("line")) is not int or ref["line"] < 1:
                raise ValueError("Evidence reference line must be a positive integer")
    if item["disposition"] == "false-positive":
        require_text(item, "dismissal_reason")
        if item["confidence"] != "high":
            raise ValueError("False-positive requires high confidence; otherwise use needs-review")
    elif item["disposition"] in ("confirmed", "likely"):
        require_text(item, "preconditions")


def group_issues(rows, groups):
    """Validate explicit semantic groups; never infer identity from line/rule/CWE."""
    if not isinstance(groups, list):
        raise ValueError("Groups must be an array")
    by_id = {row["scanner_finding"]["id"]: row for row in rows}
    grouped = {}
    for group in groups:
        if not isinstance(group, dict):
            raise ValueError("Each group must be an object")
        require_text(group, "title", "root_cause", "evidence", "preconditions", "recommendation")
        ids = group.get("finding_ids")
        if not isinstance(ids, list) or len(ids) < 2:
            raise ValueError("Explicit groups require at least two finding IDs")
        for finding_id in ids:
            if not isinstance(finding_id, str) or finding_id not in by_id or finding_id in grouped:
                raise ValueError("Unknown or repeated group member (including overlapping groups)")
            grouped[finding_id] = group
        dispositions = {by_id[finding_id]["assessment"]["disposition"] for finding_id in ids}
        if "unreviewed" in dispositions or (len(dispositions) > 1 and not dispositions <= {"confirmed", "likely"}):
            raise ValueError("Resolve conflicting or missing assessments before grouping")
    issues, visited = [], set()
    for finding_id, row in by_id.items():
        if finding_id in visited:
            continue
        group = grouped.get(finding_id)
        ids = sorted(group["finding_ids"]) if group else [finding_id]
        visited.update(ids)
        assessments = [by_id[item]["assessment"] for item in ids]
        first = row["assessment"]
        severity = "unknown" if any(a["assessed_severity"] == "unknown" for a in assessments) else min(
            (a["assessed_severity"] for a in assessments), key=SEVERITIES.index)
        issue = {"id": f"ISSUE-{len(issues) + 1:04d}", "finding_ids": ids,
                 "title": group["title"] if group else f"{row['scanner_finding']['rule']} at {location(row['scanner_finding'])}",
                 "disposition": "likely" if any(a["disposition"] == "likely" for a in assessments) else first["disposition"],
                 "assessed_severity": severity,
                 "confidence": min((a["confidence"] for a in assessments), key=CONFIDENCES.index),
                 "evidence": group["evidence"] if group else first["evidence"],
                 "preconditions": group["preconditions"] if group else first.get("preconditions", "Not recorded"),
                 "recommendation": group["recommendation"] if group else first["recommendation"],
                 "grouping_basis": group["root_cause"] if group else "Ungrouped scanner candidate; no identity inferred"}
        issues.append(issue)
    return issues


def merge(report, assessments, groups=None):
    findings = report["findings"]
    ids = [item["id"] for item in findings]
    id_set = set(ids)
    if len(ids) != len(id_set):
        raise ValueError("Scanner finding IDs must be unique")
    by_id = {}
    for item in assessments:
        if item["id"] not in id_set or item["id"] in by_id:
            raise ValueError("Unknown or duplicate assessment ID")
        validate_assessment(item)
        by_id[item["id"]] = item
    rows = []
    for finding in findings:
        assessment = by_id.get(finding["id"], {
            "id": finding["id"], "disposition": "unreviewed", "confidence": "unknown",
            "assessed_severity": "unknown", "evidence": "Not assessed; retained for review.",
            "recommendation": "Review source and rule before deciding.",
        })
        rows.append({"scanner_finding": finding, "assessment": assessment})
    issues = group_issues(rows, [] if groups is None else groups)
    counts = dict(Counter(row["assessment"]["disposition"] for row in rows))
    return {"schema_version": 2, "scan": report, "counts": counts, "findings": rows, "issues": issues,
            "summary": {"scanner_findings": len(rows), "issue_groups": len(issues),
                        "actionable_issue_groups": sum(i["disposition"] in ("confirmed", "likely") for i in issues),
                        "unresolved_issue_groups": sum(i["disposition"] in ("needs-review", "unreviewed") for i in issues),
                        "false_positive_scanner_findings": counts.get("false-positive", 0)}}


def markdown(review):
    def safe(value):
        return html.escape(str(value)).replace("|", "&#124;").replace("`", "&#96;").replace("\n", "<br>").replace("\r", "")

    scan = review["scan"]
    lines = ["# Security review", "",
             f"Scanner status: {safe(scan['status'])}. Scanner findings: {len(review['findings'])}.",
             f"Scope: {safe(scan['scope'])}. Commit: {safe(scan.get('commit', 'working tree'))}.",
             f"Summary: {safe(json.dumps(review['summary']))}.",
             "Issue groups are review decisions, not proof of confirmed or exhaustively deduplicated vulnerabilities.",
             f"Per-scanner assessment counts: {safe(json.dumps(review['counts']))}.", "",
             "## Recommended fixes", ""]
    actionable = [issue for issue in review["issues"] if issue["disposition"] in ("confirmed", "likely")]
    for issue in sorted(actionable, key=lambda item: SEVERITIES.index(item["assessed_severity"])):
        lines += [f"### {safe(issue['id'])} — {safe(issue['title'])}", "",
                  f"Assessment: {safe(issue['disposition'])} / {safe(issue['assessed_severity'])} / {safe(issue['confidence'])}.",
                  f"Scanner references: {safe(', '.join(issue['finding_ids']))}.",
                  f"Observed evidence: {safe(issue['evidence'])}",
                  f"Exploit preconditions / uncertainty: {safe(issue['preconditions'])}",
                  f"Grouping basis: {safe(issue['grouping_basis'])}",
                  f"Recommended fix: {safe(issue['recommendation'])}", ""]
    if not actionable:
        lines.append("No confirmed/likely fixes identified. Unreviewed findings are not a pass.")
    remaining = [issue for issue in review["issues"] if issue["disposition"] not in ("confirmed", "likely")
                 and len(issue["finding_ids"]) > 1]
    if remaining:
        lines += ["", "## Other explicitly grouped candidates", ""]
        for issue in remaining:
            lines.append(f"- {safe(issue['id'])} ({safe(issue['disposition'])}): {safe(issue['title'])}. "
                         f"Scanner references: {safe(', '.join(issue['finding_ids']))}. "
                         f"Evidence: {safe(issue['evidence'])}. Grouping basis: {safe(issue['grouping_basis'])}. "
                         f"Preconditions: {safe(issue['preconditions'])}. Next step: {safe(issue['recommendation'])}")
    issue_ids = {finding_id: issue["id"] for issue in review["issues"] for finding_id in issue["finding_ids"]}
    lines += ["", "## All scanner findings (lossless appendix)", "",
              "| ID / Issue | Engine | Rule | Location | Scanner severity | AI disposition / severity / confidence | Evidence / dismissal rationale / preconditions | Recommendation |",
              "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for row in review["findings"]:
        finding, assessment = row["scanner_finding"], row["assessment"]
        evidence = assessment["evidence"]
        if assessment.get("evidence_refs"):
            evidence += " References: " + ", ".join(f"{ref['path']}:{ref['line']}" for ref in assessment["evidence_refs"])
        for key in ("dismissal_reason", "preconditions"):
            if assessment.get(key):
                evidence += f" {key}: {assessment[key]}"
        cells = [f"{finding['id']} / {issue_ids[finding['id']]}", finding.get("engine", scan.get("tool", "unknown")), finding["rule"], location(finding),
                 finding["scanner_severity"],
                 f"{assessment['disposition']} / {assessment['assessed_severity']} / {assessment['confidence']}",
                 evidence, assessment["recommendation"]]
        lines.append("| " + " | ".join(safe(cell) for cell in cells) + " |")
    lines += ["", "## Coverage and limitations", "", "```json",
              json.dumps({key: scan.get(key) for key in ("version", "baseline", "rules", "preflight", "engines", "phases", "advisory_mode", "database_refresh", "advisory_databases", "history_shallow", "coverage", "coverage_notes", "error", "submodules", "snapshot_exclusions")}, indent=2),
              "```", ""]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("assessments", type=Path, help="JSON array of AI assessments; [] retains everything as unreviewed")
    parser.add_argument("--groups", type=Path, help="optional JSON array of evidence-backed groups of scanner finding IDs")
    args = parser.parse_args()
    try:
        groups = json.loads(args.groups.read_text()) if args.groups else None
        review = merge(json.loads(args.report.read_text()), json.loads(args.assessments.read_text()), groups)
        for name, content in (("review.json", json.dumps(review, indent=2) + "\n"),
                              ("review.md", markdown(review))):
            path = args.report.parent / name
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w") as file:
                file.write(content)
        print(json.dumps({"review": str(args.report.parent / "review.md"), "counts": review["counts"], "summary": review["summary"]}))
    except (OSError, ValueError, KeyError, TypeError) as error:
        detail = str(error) if type(error) is ValueError else type(error).__name__
        parser.exit(2, f"Review could not be rendered ({detail}). Check schema and output paths.\n")


if __name__ == "__main__":
    main()
