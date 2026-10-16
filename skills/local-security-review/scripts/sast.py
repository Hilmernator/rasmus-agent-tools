#!/usr/bin/env python3
"""Run Semgrep plus language-specific scanners, retaining all candidates."""

import argparse
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

import scan
import setup_sast
import iac


SCRIPTS = Path(__file__).resolve().parent
EXTENSIONS = {"bandit": {".py"}, "eslint": {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}}
EXCLUDED = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache"}


def source_files(target, env, changed=None, language_only=True):
    """Git inventory includes tests and tracked ignored files; never follow symlinks."""
    if Path(scan.git(target, env, "rev-parse", "--show-toplevel")).resolve() != target:
        raise ValueError("SAST suite requires the repository root")
    names = scan.git(target, env, "ls-files", "--cached", "--others", "--exclude-standard", "-z").split("\0")
    files, skipped = [], []
    for name in sorted(set(names) - {""}):
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("Unsafe path in source inventory")
        path = target / relative
        reason = None
        if any(part in EXCLUDED for part in relative.parts):
            reason = "dependency/cache directory"
        elif path.is_symlink() or not path.resolve().is_relative_to(target):
            reason = "symlink or external path"
        elif not path.is_file():
            reason = "missing file or submodule/directory"
        elif changed is not None and name not in changed:
            reason = "unchanged file outside changed-file scope"
        elif language_only and relative.suffix not in set.union(*EXTENSIONS.values()):
            reason = "not a Bandit/ESLint language (Semgrep coverage is separate)"
        elif path.stat().st_size > 1024 * 1024:
            reason = "file exceeds 1 MiB language-scanner limit"
        if reason:
            skipped.append({"path": name, "reason": reason})
        else:
            files.append(name)
    return files, skipped


def relative_path(name, target):
    path = Path(name)
    path = path if path.is_absolute() else target / path
    return str(path.resolve().relative_to(target))


def project(engine, data, target):
    findings, scanned, errors = [], [], []
    if engine == "bandit":
        scanned = [relative_path(name, target) for name in data["metrics"] if name != "_totals"]
        errors = [{"path": relative_path(item["filename"], target), "type": "parse-or-read-error"}
                  for item in data["errors"]]
        for item in data["results"]:
            findings.append({"rule": item["test_id"], "path": relative_path(item["filename"], target),
                             "line": item["line_number"], "end_line": max(item.get("line_range") or [item["line_number"]]),
                             "scanner_severity": item["issue_severity"],
                             "metadata": {"confidence": item["issue_confidence"], "cwe": item.get("issue_cwe")}})
    else:
        for item in data:
            name = relative_path(item["filePath"], target)
            scanned.append(name)
            for message in item["messages"]:
                if not message.get("ruleId"):
                    errors.append({"path": name, "line": message.get("line"), "type": "parse-or-configuration-error"})
                    continue
                findings.append({"rule": message["ruleId"], "path": name, "line": message["line"],
                                 "end_line": message.get("endLine", message["line"]),
                                 "scanner_severity": "ERROR" if message["severity"] == 2 else "WARNING",
                                 "metadata": {}})
    return findings, {"scanned_paths": scanned, "scanned_files": len(scanned),
                      "errors": errors, "scanner_errors": len(errors)}


def language_scan(engine, files, target, temporary, env, timeout):
    report = {"tool": engine, "status": "not-applicable", "findings": [],
              "coverage": {"selected_paths": files}, "scope": "selected files, all findings (no baseline subtraction)"}
    if not files:
        report["reason"] = "No eligible files for this language in the selected scope"
        return report
    report["status"] = "incomplete"
    try:
        root, receipt = setup_sast.verified_receipt()
        report["toolchain_lock_sha256"] = receipt["lock_sha256"]
        report["versions"] = {p["name"]: p["version"] for p in receipt["packages"]
                              if p["name"] in ("bandit", "eslint", "eslint-plugin-security", "@typescript-eslint/parser", "typescript")}
        if engine == "eslint" and not shutil.which("node"):
            raise ValueError("Node.js is required for ESLint")
        all_scanned, errors = [], []
        # Bound argv length without spawning a process per file.
        for start in range(0, len(files), 100):
            batch = files[start:start + 100]
            raw = Path(temporary) / f"{engine}.json"
            if engine == "bandit":
                argv = [str(root / "venv/bin/python"), "-I", "-m", "bandit",
                        "--ini", os.devnull, "-c", str(setup_sast.ASSETS / "bandit.yaml"),
                        "--ignore-nosec", "--severity-level", "all", "--confidence-level", "all",
                        "-f", "json", "-o", str(raw), "--", *[str(target / name) for name in batch]]
            else:
                inventory = Path(temporary) / "files.json"
                inventory.write_text(json.dumps(batch))
                argv = ["node", str(SCRIPTS / "eslint_scan.cjs"), str(root), str(target), str(inventory), str(raw)]
            with (Path(temporary) / "process.log").open("wb") as log:
                result = subprocess.run(argv, cwd=temporary, env=env, stdout=log, stderr=log, timeout=timeout)
            if not raw.is_file() or raw.stat().st_size > scan.MAX_REPORT_BYTES:
                raise ValueError("Scanner output missing or exceeds 32 MiB")
            data = json.loads(raw.read_text())
            raw.unlink()
            findings, coverage = project(engine, data, target)
            report["findings"].extend(findings)
            all_scanned.extend(coverage["scanned_paths"])
            errors.extend(coverage["errors"])
            report["coverage"].update(scanned_paths=all_scanned, scanned_files=len(all_scanned), errors=errors)
            if result.returncode not in ((0, 1) if engine == "bandit" else (0,)):
                raise ValueError("Scanner process failed; findings are partial")
        missing = sorted(set(files) - set(all_scanned))
        report["coverage"]["missing_paths"] = missing
        if errors or missing:
            raise ValueError("Scanner could not analyze every selected file; findings are partial")
        report["status"] = "findings" if report["findings"] else "no-findings"
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        report["error"] = str(error) if type(error) is ValueError else type(error).__name__
    return report


def execute(args):
    target = Path(args.target).expanduser().resolve(strict=True)
    if getattr(args, "iac_path", None) and (args.commit or args.diff):
        raise ValueError("--iac-path requires a full working-tree scan, not a commit/diff")
    output = Path(tempfile.mkdtemp(prefix="rasmus-sast-")).resolve()
    if output.is_relative_to(target):
        output.rmdir()
        raise ValueError("Target contains report directory; choose a narrower target")
    report = {"schema_version": 1, "scanner": "sast", "tool": "semgrep+bandit+eslint+trivy",
              "target": str(target), "started_at": datetime.now(timezone.utc).isoformat(),
              "scope": "working-tree", "requested_commit": args.commit, "network_allowed": False,
              "status": "incomplete", "findings": [], "engines": [],
              "coverage_notes": ["Semgrep uses native baseline comparison; Bandit/ESLint report all findings in changed files for commit/diff scans.",
                                 "Trivy scans full eligible IaC when IaC changes; these findings are not necessarily introduced by the change.",
                                 "Tests included; Semgrep/Bandit/ESLint suppressions disabled. IaC suppressions are explicit incomplete coverage.",
                                 "No AI filtering applied. License inventory is technical evidence, not legal approval."], "coverage": {}}
    env = {k: v for k, v in os.environ.items() if not k.startswith(("GIT_", "SEMGREP_", "PYTHON"))
           and k not in ("NODE_OPTIONS", "NODE_PATH")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT="0", GIT_LFS_SKIP_SMUDGE="1")
    try:
        with tempfile.TemporaryDirectory(prefix="raw-", dir=output) as temporary:
            args.baseline = None
            selected = scan.commit_snapshot(args, target, temporary, env, report) if args.commit else (
                scan.diff_snapshot(args, target, temporary, env, report) if args.diff else target)
            changed = set(report["changed_paths"]) if args.baseline else None
            files, skipped = source_files(selected, env, changed)
            report["coverage"]["language_scanner_exclusions"] = skipped
            semgrep_args = copy.copy(args)
            semgrep_args.target = str(selected)
            semgrep_args.scanner, semgrep_args.history = "sast", False
            semgrep_args.commit, semgrep_args.diff = ("HEAD" if args.commit or args.diff else None), False
            policy = json.loads((SCRIPTS.parent / "assets/semgrep-policy.json").read_text())
            config = Path(args.semgrep_config).expanduser().resolve() if args.semgrep_config else scan.DEFAULT_RULES
            allowed = args.custom_rules_license_reviewed if args.semgrep_config else (
                config.is_file() and hashlib.sha256(config.read_bytes()).hexdigest() == policy["sha256"])
            if allowed:
                path, semgrep = scan.execute(semgrep_args)
                # Keep projected results in the aggregate, not extra report trees.
                path.unlink()
                path.parent.rmdir()
            else:
                semgrep = {"tool": "semgrep", "status": "incomplete", "findings": [],
                           "error": "Semgrep rules missing/unapproved: use the reviewed snapshot or explicitly reviewed custom rules"}
            semgrep["license_policy"] = {"custom_rules": "user-reviewed; not validated by plugin"} if args.semgrep_config else policy
            semgrep.pop("target", None)
            report["engines"].append(semgrep)
            for engine, extensions in EXTENSIONS.items():
                chosen = [name for name in files if Path(name).suffix in extensions]
                report["engines"].append(language_scan(engine, chosen, selected, temporary, env, args.timeout))
            all_files, excluded = source_files(selected, env, language_only=False)
            report["engines"].append(iac.run(selected, all_files, excluded, temporary, env, args.timeout,
                                             changed, getattr(args, "iac_path", ())))
            for engine in report["engines"]:
                for finding in engine.pop("findings"):
                    finding.update(id=f"SAST-{len(report['findings']) + 1:04d}", engine=engine["tool"], ai_disposition="unreviewed")
                    report["findings"].append(finding)
            if any(engine["status"] == "incomplete" for engine in report["engines"]):
                report["error"] = "At least one scanner is incomplete; see engines"
            else:
                report["status"] = "findings" if report["findings"] else "no-findings"
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        report["error"] = str(error) if type(error) is ValueError else type(error).__name__
    path = output / "report.json"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as file:
        json.dump(report, file, indent=2)
        file.write("\n")
    return path, report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target")
    parser.add_argument("--semgrep-config")
    parser.add_argument("--custom-rules-license-reviewed", action="store_true",
                        help="acknowledge separate license review of the explicitly supplied local rule configuration")
    parser.add_argument("--iac-path", action="append", default=[],
                        help="explicit repository-relative IaC file/directory, including ignored templates; full scans only")
    parser.add_argument("--timeout", type=int, default=300, help="timeout per scanner batch in seconds")
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument("--commit")
    scope.add_argument("--diff", action="store_true")
    args = parser.parse_args()
    args.allow_network = False
    if args.timeout < 1:
        parser.error("timeout must be positive")
    try:
        path, report = execute(args)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps({"report": str(path), "status": report["status"], "candidates": len(report["findings"])}))
    return {"no-findings": 0, "findings": 1, "incomplete": 2}[report["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
