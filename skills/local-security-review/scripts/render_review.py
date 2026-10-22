#!/usr/bin/env python3
"""Merge AI assessments and agent-hunt findings by ID without dropping any candidate.

Inputs beside report.json are picked up automatically: assessments.json (required to
review anything), groups.json and agent_findings.json (both optional).
"""

import argparse
from collections import Counter
import html
import json
import os
from pathlib import Path
import tempfile


DISPOSITIONS = {"confirmed", "likely", "false-positive", "needs-review", "unreviewed"}
SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")
CONFIDENCES = ("unknown", "low", "medium", "high")
ACTIONABLE = ("confirmed", "likely")


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
    elif item["disposition"] in ACTIONABLE:
        require_text(item, "preconditions")
    for key in ("proof", "verify"):
        if key in item:
            require_text(item, key)


def expand(assessments):
    """One entry may cover many IDs ("ids") when one rationale truly fits them all.

    Returns the per-ID entries and the ID lists of multi-ID entries, which become one issue.
    """
    if not isinstance(assessments, list):
        raise ValueError("Assessments must be an array")
    expanded, bulk = [], []
    for item in assessments:
        if not isinstance(item, dict):
            raise ValueError("Each assessment must be an object")
        ids = item.get("ids") if "ids" in item else [item.get("id")]
        if not isinstance(ids, list) or not ids or ("ids" in item and "id" in item):
            raise ValueError("Use either id or a nonempty ids array")
        for finding_id in ids:
            entry = {key: value for key, value in item.items() if key != "ids"}
            entry["id"] = finding_id
            expanded.append(entry)
        if len(ids) > 1:
            bulk.append((ids, item))
    return expanded, bulk


def title(finding):
    if finding.get("title"):
        return finding["title"]
    if finding.get("package"):
        package = finding["package"]
        summary = f" – {finding['summary']}" if finding.get("summary") else ""
        return f"{package.get('name', '?')}@{package.get('version', '?')}: {finding['rule']}{summary} ({finding['path']})"
    return f"{finding['rule'].rsplit('.', 1)[-1]} at {location(finding)}"


def agent_findings(items):
    """Findings from the agent's own hunt; same review rules as scanner candidates."""
    if not isinstance(items, list):
        raise ValueError("Agent findings must be an array")
    findings = []
    for item in items:
        if not isinstance(item, dict) or not str(item.get("id", "")).startswith("AGENT-"):
            raise ValueError("Agent finding IDs must start with AGENT-")
        require_text(item, "title", "rule", "path")
        if type(item.get("line")) is not int or item["line"] < 1:
            raise ValueError("Agent finding line must be a positive integer")
        findings.append({"id": item["id"], "scanner": "agent", "engine": "agent", "rule": item["rule"],
                         "title": item["title"], "path": item["path"], "line": item["line"],
                         "scanner_severity": "n/a", **({"cwe": item["cwe"]} if item.get("cwe") else {})})
    return findings


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
        if "unreviewed" in dispositions or (len(dispositions) > 1 and not dispositions <= set(ACTIONABLE)):
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
        finding = row["scanner_finding"]
        issue = {"id": f"ISSUE-{len(issues) + 1:04d}", "finding_ids": ids,
                 "title": group["title"] if group else title(finding),
                 "locations": list(dict.fromkeys(location(by_id[item]["scanner_finding"]) for item in ids)),
                 "disposition": "likely" if any(a["disposition"] == "likely" for a in assessments) else first["disposition"],
                 "assessed_severity": severity,
                 "confidence": min((a["confidence"] for a in assessments), key=CONFIDENCES.index),
                 "evidence": group["evidence"] if group else first["evidence"],
                 "preconditions": group["preconditions"] if group else first.get("preconditions", "Not recorded"),
                 "recommendation": group["recommendation"] if group else first["recommendation"],
                 "verify": group.get("verify") if group else first.get("verify"),
                 "proof": "\n".join(sorted({a["proof"] for a in assessments if a.get("proof")})) or None,
                 "grouping_basis": group["root_cause"] if group else "Single finding"}
        issues.append(issue)
    return issues


def merge(report, assessments, groups=None, hunted=None):
    findings = report["findings"] + agent_findings(hunted or [])
    ids = [item["id"] for item in findings]
    id_set = set(ids)
    if len(ids) != len(id_set):
        raise ValueError("Scanner finding IDs must be unique")
    by_id = {}
    expanded, bulk = expand(assessments)
    for item in expanded:
        if item["id"] not in id_set or item["id"] in by_id:
            raise ValueError(f"Unknown or duplicate assessment ID: {str(item['id'])[:40]}")
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
    if groups is not None and not isinstance(groups, list):
        raise ValueError("Groups must be an array")
    groups = list(groups or [])
    explicit = {finding_id for group in groups if isinstance(group, dict) for finding_id in group.get("finding_ids") or []}
    rules = {finding["id"]: finding["rule"].rsplit(".", 1)[-1] for finding in findings}
    for ids, item in bulk:
        if not explicit.intersection(ids):
            names = sorted({rules[finding_id] for finding_id in ids if finding_id in rules})
            groups.append({"title": item.get("title") or f"{', '.join(names[:3])}{' …' if len(names) > 3 else ''}: {len(ids)} findings",
                           "finding_ids": ids, "root_cause": "One shared assessment covers every member",
                           "evidence": item["evidence"], "preconditions": item.get("preconditions") or "Not recorded",
                           "recommendation": item["recommendation"], **({"verify": item["verify"]} if item.get("verify") else {})})
    issues = group_issues(rows, groups)
    counts = dict(Counter(row["assessment"]["disposition"] for row in rows))
    return {"schema_version": 3, "scan": report, "counts": counts, "findings": rows, "issues": issues,
            "summary": {"scanner_findings": len(report["findings"]), "agent_findings": len(findings) - len(report["findings"]),
                        "issue_groups": len(issues),
                        "actionable_issue_groups": sum(i["disposition"] in ACTIONABLE for i in issues),
                        "unresolved_issue_groups": sum(i["disposition"] in ("needs-review", "unreviewed") for i in issues),
                        "false_positive_scanner_findings": counts.get("false-positive", 0)}}


def markdown(review):
    def safe(value):
        return html.escape(str(value), quote=False).replace("|", "&#124;").replace("`", "&#96;").replace("\n", "<br>").replace("\r", "")

    scan = review["scan"]
    summary = review["summary"]
    actionable = sorted((issue for issue in review["issues"] if issue["disposition"] in ACTIONABLE),
                        key=lambda item: (SEVERITIES.index(item["assessed_severity"]), item["disposition"] != "confirmed"))
    lines = ["# Security review", "",
             f"{len(actionable)} issue(s) to fix, {summary['unresolved_issue_groups']} unresolved, "
             f"{summary['false_positive_scanner_findings']} false positive(s) dismissed with evidence. "
             f"Candidates: {summary['scanner_findings']} from scanners, {summary['agent_findings']} from the agent hunt.",
             f"Scanner status: {safe(scan['status'])}. Scope: {safe(scan['scope'])}. Commit: {safe(scan.get('commit', 'working tree'))}.",
             "", "## Fix plan", ""]
    for number, issue in enumerate(actionable, 1):
        where = issue["locations"][:8] + ([f"+{len(issue['locations']) - 8} more"] if len(issue["locations"]) > 8 else [])
        lines += [f"### {number}. {safe(issue['title'])}", "",
                  f"- **Severity / status:** {safe(issue['assessed_severity'])}, {safe(issue['disposition'])} ({safe(issue['confidence'])} confidence), {safe(issue['id'])}",
                  f"- **Where:** {safe(', '.join(where))}",
                  f"- **Evidence and impact:** {safe(issue['evidence'])}",
                  f"- **Preconditions / uncertainty:** {safe(issue['preconditions'])}",
                  *([f"- **Proven by:** {safe(issue['proof'])}"] if issue.get("proof") else []),
                  f"- **Fix:** {safe(issue['recommendation'])}",
                  *([f"- **Verify the fix:** {safe(issue['verify'])}"] if issue.get("verify") else []),
                  f"- **Signals:** {safe(', '.join(issue['finding_ids']))}. Grouping basis: {safe(issue['grouping_basis'])}", ""]
    if not actionable:
        lines.append("No confirmed/likely fixes identified. Unreviewed findings are not a pass.")
    unresolved = [issue for issue in review["issues"] if issue["disposition"] in ("needs-review", "unreviewed")]
    if unresolved:
        lines += ["", "## Unresolved (needs a decision or more evidence)", ""]
        for issue in unresolved:
            lines.append(f"- {safe(issue['id'])} ({safe(issue['disposition'])}, {safe(', '.join(issue['finding_ids']))}): "
                         f"{safe(issue['title'])}. {safe(issue['evidence'])} Next step: {safe(issue['recommendation'])}")
    issue_ids = {finding_id: issue["id"] for issue in review["issues"] for finding_id in issue["finding_ids"]}
    lines += ["", "## All candidates (lossless appendix)", "",
              "| ID / Issue | Engine | Rule | Location | Scanner severity | AI disposition / severity / confidence | Evidence / dismissal rationale / preconditions | Recommendation |",
              "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for row in review["findings"]:
        finding, assessment = row["scanner_finding"], row["assessment"]
        evidence = assessment["evidence"]
        if assessment.get("evidence_refs"):
            evidence += " References: " + ", ".join(f"{ref['path']}:{ref['line']}" for ref in assessment["evidence_refs"])
        for key in ("dismissal_reason", "preconditions", "proof"):
            if assessment.get(key):
                evidence += f" {key}: {assessment[key]}"
        cells = [f"{finding['id']} / {issue_ids[finding['id']]}", finding.get("engine", scan.get("tool", "unknown")), finding["rule"], location(finding),
                 finding["scanner_severity"],
                 f"{assessment['disposition']} / {assessment['assessed_severity']} / {assessment['confidence']}",
                 evidence, assessment["recommendation"]]
        lines.append("| " + " | ".join(safe(cell) for cell in cells) + " |")
    lines += ["", "## Coverage", ""] + [f"- {safe(line)}" for line in coverage_lines(scan)]
    lines += ["", "Full engine metadata (versions, rules, scanned paths) is in review.json under `scan`.", ""]
    return "\n".join(lines)


def coverage_lines(scan):
    """One line per engine plus every gap, instead of the raw metadata dump."""
    lines = []
    for engine in scan.get("engines", []):
        for child in engine.get("engines") or [engine]:
            name = child.get("tool") or child.get("scanner") or "engine"
            coverage = child.get("coverage") or {}
            line = f"{name}: {child.get('status', 'unknown')}"
            if child.get("reason"):
                line += f" ({child['reason']})"
            if child.get("error"):
                line += f"; error: {child['error']}"
            if coverage.get("scanned_files") is not None:
                line += f"; {coverage['scanned_files']} files"
            if coverage.get("scanned_packages") is not None:
                line += f"; {coverage['scanned_packages']} packages in {len(coverage.get('sources', []))} lockfile(s)"
            if coverage.get("parse_warnings"):
                line += f"; {coverage['parse_warnings']} file(s) only partially parsed"
            if coverage.get("manifests_without_lockfiles"):
                line += "; no lockfile for " + ", ".join(coverage["manifests_without_lockfiles"])
            if child.get("database_refresh", {}).get("status") not in (None, "succeeded", "not-needed"):
                line += f"; advisory refresh {child['database_refresh']['status']}"
            gaps = coverage.get("gaps") or child.get("coverage_gaps") or []
            line += "".join(f"; gap: {gap if isinstance(gap, str) else gap.get('reason', gap)}" for gap in gaps)
            lines.append(line)
    for gap in scan.get("coverage", {}).get("gaps", []):
        lines.append(f"gap: {gap}")
    if scan.get("error"):
        lines.append(f"scan error: {scan['error']}")
    return lines or ["No engine metadata in report."]


def write_private(path, content):
    # Replace atomically so a rerun after fixing assessments simply updates the review.
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}-")
    with os.fdopen(descriptor, "w") as file:
        file.write(content)
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("assessments", type=Path, nargs="?", help="default: assessments.json beside the report")
    parser.add_argument("--groups", type=Path, help="default: groups.json beside the report, if present")
    parser.add_argument("--agent-findings", type=Path, help="default: agent_findings.json beside the report, if present")
    args = parser.parse_args()
    folder = args.report.parent

    def optional(path, name):
        path = path or folder / name
        return json.loads(path.read_text()) if path.is_file() else None

    try:
        # No assessments file (e.g. zero candidates) keeps every candidate unreviewed.
        assessments = optional(args.assessments, "assessments.json") or []
        review = merge(json.loads(args.report.read_text()), assessments,
                       optional(args.groups, "groups.json"), optional(args.agent_findings, "agent_findings.json"))
        write_private(folder / "review.json", json.dumps(review, indent=2) + "\n")
        write_private(folder / "review.md", markdown(review))
        print(json.dumps({"review": str(folder / "review.md"), "counts": review["counts"], "summary": review["summary"]}))
    except (OSError, ValueError, KeyError, TypeError) as error:
        detail = str(error) if type(error) is ValueError else type(error).__name__
        parser.exit(2, f"Review could not be rendered ({detail}). Check schema and output paths.\n")


if __name__ == "__main__":
    main()
