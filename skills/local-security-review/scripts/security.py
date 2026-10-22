#!/usr/bin/env python3
"""Check prerequisites and combine the existing SAST, SCA and secret runners."""

import argparse
import copy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile

import iac
import sast
import scan
import secrets_deep
import setup_sast
import setup_sca
import setup_secrets


def check():
    checks = {}
    for name, setup in (("sast", setup_sast), ("sca", setup_sca), ("secrets", setup_secrets)):
        try:
            checks[name] = setup.check()
        except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, subprocess.SubprocessError):
            checks[name] = {"status": "needs-setup", "error": "Prerequisite check failed; run security.py --setup"}
        checks[name]["setup"] = "security.py --setup"
    return {"status": "prerequisites-ready" if all(c["status"] == "prerequisites-ready" for c in checks.values()) else "needs-setup",
            "checks": checks, "note": "Read-only checks, not functional verification. No installation or download performed."}


SEMGREP_VERSION = "1.176.0"


def setup():
    """Install only what --check reports missing, then run every functional verification.

    Downloads: pinned scanner binaries, locked Python/npm packages, Semgrep packs and
    advisory databases into the per-user cache. Nothing is written to the target repo.
    """
    steps = {}

    def step(name, action):
        try:
            result = action()
            steps[name] = result if isinstance(result, dict) else {"status": "done"}
        except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, subprocess.SubprocessError) as error:
            steps[name] = {"status": "failed", "error": str(error) if type(error) is ValueError else type(error).__name__}

    sast_checks = setup_sast.check()["checks"]
    if sast_checks["semgrep"]["status"] != "available":
        if not shutil.which("uv"):
            steps["semgrep"] = {"status": "failed", "error": "Semgrep missing and uv unavailable; install uv first"}
        else:
            step("semgrep", lambda: subprocess.run(["uv", "tool", "install", f"semgrep=={SEMGREP_VERSION}"],
                                                   check=True, capture_output=True, timeout=900))
    if sast_checks["toolchain"]["status"] != "available":
        step("sast-toolchain", setup_sast.install)
    if sast_checks["rules"]["status"] != "available":
        step("semgrep-rules", lambda: setup_sast.fetch_rules(refresh=sast_checks["rules"]["status"] == "changed"))
    if sast_checks["iac"]["status"] != "available":
        step("trivy", iac.install)
    if setup_sca.check()["status"] != "prerequisites-ready":
        step("osv-scanner", setup_sca.install)
        step("advisory-databases", lambda: setup_sca.verify(update=True))
    if setup_secrets.check()["status"] != "prerequisites-ready":
        step("gitleaks", setup_secrets.install)
    step("verify-sast", setup_sast.verify)
    step("verify-sca", setup_sca.verify)
    step("verify-secrets", setup_secrets.verify)
    ready = all(steps[name].get("status") == "ready" for name in ("verify-sast", "verify-sca", "verify-secrets"))
    return {"status": "ready" if ready else "setup-incomplete", "steps": steps,
            "note": "Per-user cache only; rerun after fixing any failed step (completed steps are skipped)."}


def collect(name, runner, args, report, selected):
    try:
        path, child = runner(args)
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, subprocess.SubprocessError):
        report["engines"].append({"scanner": name, "status": "incomplete", "error": "Scanner could not finish; no raw diagnostics retained"})
        return
    try:
        for finding in child.pop("findings"):
            item = dict(finding, scanner=name)
            if report.get("commit"):
                item["commit"] = report["commit"]
                location = Path(item["path"])
                if location.is_absolute() and location.is_relative_to(selected):
                    item["path"] = str(location.relative_to(selected))
            report["findings"].append(item)
        if report.get("commit"):
            child["input_commit"] = report["commit"]
            child["scope"] = "full-commit-snapshot"
            for source in child.get("coverage", {}).get("sources", []):
                location = Path(source["path"])
                if location.is_absolute() and location.is_relative_to(selected):
                    source["path"] = str(location.relative_to(selected))
        child["target"] = report["target"]
        report["engines"].append(child)
    finally:
        # These projected report trees are created by our runners, not consumer paths.
        shutil.rmtree(path.parent)


def execute(args):
    target = Path(args.target).expanduser().resolve(strict=True)
    if not target.is_dir() or args.timeout < 1:
        raise ValueError("Target must be a directory and timeout must be positive")
    if getattr(args, "iac_path", None) and (args.commit or args.diff):
        raise ValueError("--iac-path requires full/release mode")
    output = Path(tempfile.mkdtemp(prefix="rasmus-security-all-")).resolve()
    if output.is_relative_to(target):
        output.rmdir()
        raise ValueError("Target contains temporary directory; choose a narrower target")
    report = {"schema_version": 1, "scanner": "combined", "tool": "semgrep+bandit+eslint+trivy+osv-scanner+gitleaks",
              "target": str(target), "started_at": datetime.now(timezone.utc).isoformat(),
              "scope": "commit-snapshot" if args.commit else "release" if args.release else "working-tree-hybrid-diff" if args.diff else "working-tree",
              "requested_commit": args.commit, "network_allowed": False,
              "status": "incomplete", "findings": [], "engines": [], "coverage": {},
              "coverage_notes": [
                  "Full is the default. Diff limits SAST to working changes vs HEAD; SCA and secrets still scan current files broadly.",
                  "Commit mode scans a complete isolated snapshot with every scanner, not only introduced findings; uncommitted work is excluded.",
                  "Diff is neither staged-only nor a PR comparison against the target branch. Use full/commit before merge.",
                  "Release uses full SAST/SCA and deep secrets (available GitHub history and bounded archives).",
                  "SCA checks database updates unless explicitly offline. Setup/installations are separate permissioned flows.",
                  "Component exclusions, scan failures and all candidates remain visible. AI review and release approval are separate."]}
    report["preflight"] = check()
    if report["preflight"]["status"] != "prerequisites-ready":
        report["error"] = "Prerequisites missing or broken: run security.py --setup, then rerun; no scanners started"
        report["engines"] = [{"scanner": name, "status": "incomplete", "error": "Not started: setup gate"}
                             for name in ("sast", "sca", "secrets")]
    else:
        with tempfile.TemporaryDirectory(prefix="snapshot-", dir=output) as temporary:
            selected = target
            snapshot_ready = True
            if args.commit:
                try:
                    metadata = {}
                    env = secrets_deep.git_env()
                    env["GIT_ALLOW_PROTOCOL"] = "file"
                    selected = scan.commit_snapshot(copy.copy(args), target, temporary, env, metadata)
                    report["commit"] = metadata["commit"]
                    report["submodules"] = metadata["submodules"]
                    if report["submodules"]:
                        report["coverage"]["gaps"] = ["Submodule contents not initialized in commit snapshot"]
                except (OSError, ValueError, subprocess.SubprocessError):
                    snapshot_ready = False
                    report["error"] = "Commit snapshot unavailable; no working-tree fallback and no scanners started"
                    report["engines"] = [{"scanner": name, "status": "incomplete", "error": "Snapshot unavailable"}
                                         for name in ("sast", "sca", "secrets")]
            if snapshot_ready:
                report["network_allowed"] = not args.offline
                common = dict(target=str(selected), timeout=args.timeout, commit=None, diff=False,
                              history=False, allow_network=False, semgrep_config=None)
                sast_args = argparse.Namespace(**{**common, "diff": args.diff}, custom_rules_license_reviewed=False,
                                               iac_path=getattr(args, "iac_path", ()))
                collect("sast", sast.execute, sast_args, report, selected)
                collect("sca", scan.execute, argparse.Namespace(**common, scanner="sca", offline=args.offline), report, selected)
                if args.release:
                    secret_args = argparse.Namespace(target=str(selected), offline=args.offline, timeout=args.timeout,
                                                     max_history_mib=512, max_archive_mib=256)
                    collect("secrets", secrets_deep.execute, secret_args, report, selected)
                else:
                    collect("secrets", scan.execute, argparse.Namespace(**common, scanner="secrets"), report, selected)
        ids = [item["id"] for item in report["findings"]]
        if len(ids) != len(set(ids)):
            report["error"] = "Duplicate scanner IDs; combined review cannot be rendered safely"
        elif not report.get("error") and not report["coverage"].get("gaps") and all(
                child["status"] in ("no-findings", "findings", "not-applicable") for child in report["engines"]):
            report["status"] = "findings" if report["findings"] else "no-findings"
    path = output / "report.json"
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as file:
        json.dump(report, file, indent=2)
        file.write("\n")
    return path, report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", nargs="?", default=".")
    parser.add_argument("--check", action="store_true", help="check all prerequisites without installing or scanning")
    parser.add_argument("--setup", action="store_true", help="install missing scanners/rules/databases into the user cache, then verify")
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument("--diff", action="store_true", help="SAST vs HEAD; SCA and secrets still scan full working files")
    scope.add_argument("--commit", nargs="?", const="HEAD", help="all scanners on a full snapshot of this commit (default HEAD)")
    scope.add_argument("--release", action="store_true", help="full scan with GitHub history and archives for secrets")
    parser.add_argument("--offline", action="store_true", help="skip SCA refresh and deep GitHub fetch; disclose coverage limits")
    parser.add_argument("--iac-path", action="append", default=[], help="additional repository-relative IaC inputs, including ignored templates; full/release only")
    parser.add_argument("--timeout", type=int, default=600, help="time budget per scanner batch/deep scan")
    args = parser.parse_args()
    if args.setup:
        # Installer chatter goes to stderr so stdout stays one JSON document.
        saved = os.dup(1)
        os.dup2(2, 1)
        try:
            result = setup()
        finally:
            sys.stdout.flush()
            os.dup2(saved, 1)
            os.close(saved)
        print(json.dumps(result, indent=2))
        return 0 if result["status"] == "ready" else 2
    if args.check:
        result = check()
        print(json.dumps(result, indent=2))
        return 0 if result["status"] == "prerequisites-ready" else 2
    try:
        path, report = execute(args)
    except (OSError, ValueError):
        parser.exit(2, "Combined scan could not start; check target and timeout.\n")
    engines = {}
    for engine in report["engines"]:
        for child in engine.get("engines") or [engine]:
            name = child.get("tool") or child.get("scanner")
            engines[name] = child.get("status")
    counts = {}
    for finding in report["findings"]:
        counts[finding.get("engine", finding["scanner"])] = counts.get(finding.get("engine", finding["scanner"]), 0) + 1
    print(json.dumps({"report": str(path), "status": report["status"], "candidates": len(report["findings"]),
                      "engines": {name: f"{status}, {counts.get(name, 0)} candidates" for name, status in engines.items()}}))
    return {"no-findings": 0, "findings": 1, "incomplete": 2}[report["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
