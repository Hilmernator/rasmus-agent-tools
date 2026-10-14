#!/usr/bin/env python3
"""Run one installed scanner and retain only review metadata, never raw output."""

import argparse
import hashlib
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tarfile


TOOLS = {"sast": "semgrep", "sca": "osv-scanner", "secrets": "gitleaks"}
MAX_REPORT_BYTES = 32 * 1024 * 1024
DEFAULT_RULES = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "rai-security/semgrep/security-audit.yaml"


def sca_command(binary, target, raw, config, allow_network, refresh=False):
    return [str(binary), "scan", "source", "--recursive", "--no-resolve",
            "--no-call-analysis=all", "--all-packages", "--all-vulns", "--format=json", "--verbosity=warn",
            "--experimental-no-default-plugins", "--experimental-plugins=lockfile,sbom",
            "--config", str(config), "--output-file", str(raw),
            *([] if allow_network else ["--offline"]),
            *(["--download-offline-databases"] if refresh else []), str(target)]


def command(args, target, raw):
    if args.scanner == "sast":
        config = args.semgrep_config or (str(DEFAULT_RULES) if DEFAULT_RULES.is_file() else None)
        if config:
            config = Path(config).expanduser().resolve(strict=True)
        elif args.allow_network:
            config = "p/security-audit"
        else:
            raise ValueError("SAST needs --semgrep-config with reviewed local rules, or --allow-network")
        baseline = ["--baseline-commit", args.baseline] if args.baseline else []
        return ["semgrep", "scan", "--oss-only", "--config", str(config),
                "--metrics=off", "--disable-version-check", "--strict", "--error",
                "--disable-nosem", "--verbose", "--no-rewrite-rule-ids",
                "--json", "--output", str(raw), *baseline, "."], (0, 1)
    if args.scanner == "sca":
        # Explicit config replaces ALL consumer suppressions, including nested files.
        config = raw.parent / "osv-scanner.toml"
        config.write_text("# No ignored vulnerabilities or package overrides.\n")
        return sca_command(args.sca_binary, target, raw, config, args.allow_network,
                           not args.allow_network and not getattr(args, "offline", False)), (0, 1)
    config = raw.parent / "gitleaks.toml"
    config.write_text("[extend]\nuseDefault = true\n")
    ignore = raw.parent / ".gitleaksignore"
    ignore.write_text("")
    return [args.secrets_binary, "git" if args.history else "dir", str(target),
            "--redact=100", "--no-banner", "--no-color", "--log-level=error",
            "--config", str(config), "--gitleaks-ignore-path", str(ignore), "--ignore-gitleaks-allow",
            "--max-decode-depth=5", "--max-archive-depth=0",
            *(["--log-opts=--all --full-history --no-ext-diff --no-textconv"] if args.history else []),
            "--exit-code=42", "--report-format=json", "--report-path", str(raw)], (0, 42)


def project(scanner, data):
    """Allowlist structural fields; omit scanner snippets/messages and secrets."""
    if scanner == "secrets":
        if not isinstance(data, list):
            raise ValueError("Gitleaks report is not a findings array")
        return [{"id": f"SECRET-{index:04d}", "engine": "gitleaks",
                 "rule": item["RuleID"], "path": item["File"],
                 "line": item["StartLine"], "end_line": item.get("EndLine", item["StartLine"]),
                 "commit": item.get("Commit", ""), "ai_disposition": "unreviewed",
                 "scanner_severity": "unspecified"} for index, item in enumerate(data, 1)], {
                     "scanned_files": None, "note": "Gitleaks JSON does not include a scanned-file inventory."}
    if scanner == "sast":
        findings = [{"id": f"SAST-{index:04d}",
                     "rule": item["check_id"], "path": item["path"],
                     "line": item["start"]["line"],
                     "end_line": item.get("end", item["start"])["line"],
                     "scanner_severity": item["extra"]["severity"],
                     "ai_disposition": "unreviewed",
                     "metadata": {key: value for key, value in item["extra"].get("metadata", {}).items()
                                  if key in ("cwe", "owasp", "confidence", "references")}}
                    for index, item in enumerate(data["results"], 1)]
        return findings, {"scanned_files": len(data["paths"]["scanned"]),
                          "scanned_paths": data["paths"]["scanned"],
                          "skipped": [{key: item[key] for key in ("path", "reason") if key in item}
                                      for item in data["paths"].get("skipped", [])],
                          "scanner_errors": len(data.get("errors", [])),
                          "errors": [{key: item[key] for key in ("type", "code", "level", "path") if key in item}
                                     for item in data.get("errors", [])]}
    findings = []
    packages = 0
    sources = []
    for source in data["results"]:
        sources.append({"path": source["source"]["path"],
                        "type": source["source"].get("type", "unknown"),
                        "packages": len(source["packages"])})
        for item in source["packages"]:
            packages += 1
            for vuln in item.get("vulnerabilities", []):
                findings.append({"id": f"SCA-{len(findings) + 1:04d}", "engine": "osv-scanner",
                                 "rule": vuln["id"], "path": source["source"]["path"],
                                 "package": item["package"],
                                 "aliases": vuln.get("aliases", []),
                                 "advisory_url": f"https://osv.dev/vulnerability/{vuln['id']}",
                                 "modified": vuln.get("modified"), "withdrawn": vuln.get("withdrawn"),
                                 "ai_disposition": "unreviewed",
                                 "scanner_severity": vuln.get("severity", []),
                                 "affected": vuln.get("affected", [])})
    return findings, {"scanned_packages": packages, "sources": sources,
                      "scanner_errors": len(data.get("errors", []))}


def git(target, env, *args):
    result = subprocess.run(["git", "-C", str(target), *args], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    if result.returncode:
        raise ValueError("Git snapshot/baseline unavailable; check the local commit and history (no automatic fetch)")
    return os.fsdecode(result.stdout).rstrip("\n")


def diff_snapshot(args, target, temporary, env, report):
    if Path(git(target, env, "rev-parse", "--show-toplevel")).resolve() != target:
        raise ValueError("Diff scanning requires the repository root as target")
    if git(target, env, "ls-files", "--unmerged"):
        raise ValueError("Resolve merge conflicts before a diff scan")
    if any(item.startswith("S ") for item in git(target, env, "ls-files", "-t", "-z").split("\0")):
        raise ValueError("Sparse/skip-worktree files are not supported in diff mode; use a complete checkout")
    args.baseline = git(target, env, "rev-parse", "--verify", "HEAD^{commit}")
    snapshot = Path(temporary).resolve() / "snapshot"
    git(target, env, "clone", "--shared", "--no-checkout", "--quiet", "--", str(target), str(snapshot))
    git(snapshot, env, "update-ref", "--no-deref", "HEAD", args.baseline)
    git(snapshot, env, "remote", "remove", "origin")
    paths = git(target, env, "ls-files", "--cached", "--others", "--exclude-standard", "-z").split("\0")
    report["snapshot_exclusions"] = []
    for name in sorted(set(paths) - {""}):
        relative = Path(name)
        source, destination = target / relative, snapshot / relative
        if relative.is_absolute() or ".." in relative.parts or any(part.lower() == ".git" for part in relative.parts):
            raise ValueError("Unsafe path in Git file inventory")
        if not source.parent.resolve().is_relative_to(target):
            raise ValueError("Working file parent resolves outside the repository")
        if not destination.parent.resolve().is_relative_to(snapshot):
            raise ValueError("Snapshot file parent resolves outside the isolated clone")
        if source.is_symlink():
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.symlink_to(os.readlink(source))
        elif source.is_file():
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
        elif source.is_dir():
            report["snapshot_exclusions"].append({"path": name, "reason": "submodule or directory replacing tracked file"})
        elif source.exists():
            raise ValueError("Unsupported special file in working tree")
    # Only the disposable clone gets an index and synthetic commit. Force-add
    # preserves tracked files that now match an ignore rule; inventory was filtered above.
    git(snapshot, env, "add", "--all", "--force", "--", ".")
    git(snapshot, env, "-c", "user.name=RAI Scanner", "-c", "user.email=scanner@example.invalid",
        "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
        "commit", "--quiet", "--allow-empty", "-m", "Temporary working-tree scan snapshot")
    report.update(scope="working-tree-diff", baseline=args.baseline,
                  changed_paths=git(snapshot, env, "diff-tree", "--no-commit-id", "--name-only", "-z",
                                    "--diff-filter=ACMRT", "-r", args.baseline, "HEAD").split("\0")[:-1])
    return snapshot


def commit_snapshot(args, target, temporary, env, report):
    # A local clone avoids checking out or adding worktrees in the user's repo.
    root = Path(git(target, env, "rev-parse", "--show-toplevel")).resolve()
    if root != target:
        raise ValueError("Commit scanning requires the repository root as target")
    commit = git(target, env, "rev-parse", "--verify", "--end-of-options", f"{args.commit}^{{commit}}")
    parents = git(target, env, "show", "--no-patch", "--format=%P", commit).split()
    shallow = git(target, env, "rev-parse", "--is-shallow-repository")
    if not parents and shallow == "true":
        raise ValueError("Cannot establish a root commit in shallow history; obtain history explicitly first")
    args.baseline = parents[0] if parents else None
    snapshot = Path(temporary).resolve() / "snapshot"
    git(target, env, "clone", "--shared", "--no-checkout", "--quiet", "--", str(target), str(snapshot))
    git(snapshot, env, "checkout", "--quiet", "--detach", commit)
    # Remove the remote so no subsequent scanner operation can fetch/push.
    git(snapshot, env, "remote", "remove", "origin")
    report.update(commit=commit, baseline=args.baseline, parent_count=len(parents),
                  scope="commit-diff" if parents else "root-commit")
    report["changed_paths"] = git(snapshot, env, "diff-tree", "--no-commit-id", "--name-only", "-z",
                                  "--diff-filter=ACMRT", "-r", *(parents[:1]), commit).split("\0")[:-1] if parents else None
    entries = git(snapshot, env, "ls-tree", "-r", commit).splitlines()
    report["submodules"] = [entry.split("\t", 1)[1] for entry in entries if entry.startswith("160000 ")]
    return snapshot


def execute(args):
    target = Path(args.target).expanduser().resolve(strict=True)
    if not target.is_dir():
        raise ValueError("scan target must be a directory")
    if args.history and args.scanner != "secrets":
        raise ValueError("--history applies only to secrets")
    if args.scanner == "secrets" and args.allow_network:
        raise ValueError("Secrets scanning is local-only; --allow-network does not apply")
    if args.semgrep_config and args.scanner != "sast":
        raise ValueError("--semgrep-config applies only to SAST")
    if getattr(args, "offline", False) and (args.scanner != "sca" or args.allow_network):
        raise ValueError("--offline applies only to SCA and cannot be combined with --allow-network")
    if (args.commit or args.diff) and args.scanner != "sast":
        raise ValueError("--commit and --diff are currently supported only for SAST")
    args.baseline = None
    # Output outside the source tree avoids self-scanning and accidental commits.
    output = Path(tempfile.mkdtemp(prefix="rai-security-")).resolve()
    if output.is_relative_to(target):
        output.rmdir()
        raise ValueError("target contains the temporary directory; choose a narrower target")
    os.chmod(output, 0o700)
    report = {"schema_version": 1, "scanner": args.scanner, "tool": TOOLS[args.scanner],
              "target": str(target), "started_at": datetime.now(timezone.utc).isoformat(),
              "scope": "working-tree-diff" if args.diff else "commit-diff" if args.commit else "local-git-history" if args.history else "working-tree",
              "requested_commit": args.commit,
              "network_allowed": args.allow_network, "status": "incomplete",
              "findings": [], "coverage": {}}
    try:
        binary = shutil.which(report["tool"])
        if args.scanner == "secrets":
            import setup_secrets
            if setup_secrets.root().exists() or setup_secrets.root().is_symlink():
                binary = setup_secrets.checked_executable()
            args.secrets_binary = binary
            report["coverage_notes"] = [
                "Bundled Gitleaks rules and built-in allowlists apply; no proof of absence or credential validity.",
                "Consumer .gitleaks.toml/.gitleaksignore and inline gitleaks:allow suppressions are disabled.",
                "Working-file scanning includes untracked/ignored files such as .env; symlinks and .git internals are not followed.",
                "Decoding is bounded to depth 5; archives are not unpacked. Binary files and built-in path/rule allowlists limit coverage.",
                "History includes all locally available refs, not fetched remote history, unreachable objects or submodules.",
                "No network requests, credential validation, tool installation or automatic rule updates.",
            ]
        if args.scanner == "sca":
            import setup_sca
            # Reuse the isolated pin when installed; never silently fall back on corruption.
            if setup_sca.executable().exists() or setup_sca.executable().is_symlink():
                binary = setup_sca.checked_executable()
            args.sca_binary = binary
            refresh = not args.allow_network and not getattr(args, "offline", False)
            report["network_allowed"] = args.allow_network or refresh
            report["advisory_mode"] = "live-queries" if args.allow_network else "refresh-then-local" if refresh else "offline-cache"
            report["database_refresh"] = {"status": "pending" if refresh else "not-requested"}
            report["advisory_databases"] = setup_sca.databases()
            report["coverage_notes"] = [
                "Known advisory matching, not proof of exploitability or package license compliance.",
                "Dependency resolution and all call analysis are disabled; manifests without exact locked versions are insufficient.",
                "OSV file ignores still apply; repository vulnerability/package suppressions are disabled.",
                "Compare coverage.sources against repository lockfiles/SBOMs; missing and unsupported inputs need explicit review.",
                "Default scans check OSV database updates for scanned ecosystems before local matching; --offline explicitly reuses the cache.",
                "Cache mtime can remain unchanged when remote contents match; the refresh result is recorded separately. Upstream publication lag still applies.",
            ]
        if not binary:
            raise ValueError(f"Required executable not found on PATH: {report['tool']}")
        env = os.environ.copy()
        # Prevent inherited engine/output options from selecting hosted Semgrep.
        for key in list(env):
            if key.startswith(("SEMGREP_", "GIT_", "GITLEAKS_")):
                del env[key]
        env["SEMGREP_SEND_METRICS"] = "off"
        env["SEMGREP_ENABLE_VERSION_CHECK"] = "0"
        env["NO_COLOR"] = "1"
        # Isolated Git operations must not load global hooks, filters or helpers.
        env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                   GIT_TERMINAL_PROMPT="0", GIT_LFS_SKIP_SMUDGE="1")
        if args.scanner == "secrets" and args.history:
            if Path(git(target, env, "rev-parse", "--show-toplevel")).resolve() != target:
                raise ValueError("Secret history scanning requires the repository root")
            report["history_shallow"] = git(target, env, "rev-parse", "--is-shallow-repository") == "true"
        if args.scanner == "sca":
            env["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"] = str(setup_sca.DB)
        with tempfile.TemporaryDirectory(prefix="raw-", dir=output) as temporary:
            env["SEMGREP_SETTINGS_FILE"] = str(Path(temporary) / "semgrep-settings.yml")
            env["SEMGREP_LOG_FILE"] = str(Path(temporary) / "semgrep.log")
            scan_target = target
            if args.commit:
                scan_target = commit_snapshot(args, target, temporary, env, report)
            elif args.diff:
                scan_target = diff_snapshot(args, target, temporary, env, report)
            raw = Path(temporary) / "report.json"
            argv, accepted = command(args, scan_target, raw)
            if args.scanner == "secrets":
                config = Path(argv[argv.index("--config") + 1])
                report["rules"] = {"source": "installed Gitleaks bundled rules; no consumer overrides",
                                   "wrapper_config_sha256": hashlib.sha256(config.read_bytes()).hexdigest()}
            if args.scanner == "sast":
                config = Path(argv[argv.index("--config") + 1])
                report["rules"] = {"source": str(config), "sha256": None}
                if config.is_file():
                    report["rules"]["sha256"] = hashlib.sha256(config.read_bytes()).hexdigest()
                report["coverage_notes"] = [
                    "CE analysis is not a proof of security; supported languages and configured rules limit detection.",
                    "Git/Semgrep ignores, size limits and unsupported files may exclude source; inspect coverage.skipped.",
                    "Inline nosemgrep suppression is disabled; no AI filtering has been applied.",
                ]
            report["command"] = ["<temporary-report>" if arg == str(raw) else arg
                                 for arg in argv]
            with open(Path(temporary) / "process.log", "wb") as log:
                version_args = [binary, "version" if args.scanner == "secrets" else "--version"]
                version = subprocess.run(version_args, cwd=temporary, env=env,
                                         stdout=subprocess.PIPE, stderr=log, timeout=30)
                if version.returncode:
                    raise ValueError("Scanner version check failed")
                report["version"] = version.stdout.decode("utf-8", errors="replace").strip()[:300]
                result = subprocess.run(argv, cwd=scan_target, env=env, stdout=log,
                                        stderr=log, timeout=args.timeout)
            report["exit_code"] = result.returncode
            if args.scanner == "sca":
                report["advisory_databases"] = setup_sca.databases()
            if not raw.is_file() or raw.stat().st_size > MAX_REPORT_BYTES:
                raise ValueError("Scanner report missing or exceeds 32 MiB; narrow the scan scope")
            with raw.open() as file:
                data = json.load(file)
            report["findings"], report["coverage"] = project(args.scanner, data)
            if args.scanner in ("sca", "secrets"):
                diagnostics = (Path(temporary) / "process.log").stat().st_size
                report["coverage"]["diagnostic_bytes"] = diagnostics
                if diagnostics:
                    raise ValueError("Scanner emitted diagnostics; findings are partial. Inspect scope, prerequisites and file accessibility")
            if result.returncode not in accepted:
                raise ValueError("Scanner failed; check installed CLI compatibility and local rules/database availability")
            coverage = report["coverage"]
            if coverage.get("scanner_errors", 0):
                raise ValueError("Scanner reported scan errors; findings are partial")
            empty_diff = args.baseline and not report["changed_paths"]
            if (coverage.get("scanned_files") == 0 and not empty_diff) or coverage.get("scanned_packages") == 0:
                raise ValueError("No supported files/packages scanned; inspect scope and ignore rules")
            if result.returncode != 0 and not report["findings"]:
                raise ValueError("Scanner signalled findings but report contained none")
            if report.get("history_shallow"):
                raise ValueError("Shallow Git history: available findings retained, historical coverage incomplete; no automatic fetch")
            if args.scanner == "sca" and refresh:
                report["database_refresh"] = {"status": "succeeded",
                                              "checked_at": datetime.now(timezone.utc).isoformat(),
                                              "ecosystems": sorted({item["package"].get("ecosystem", "unknown")
                                                                    for source in data["results"] for item in source["packages"]})}
            report["status"] = "findings" if report["findings"] else "no-findings"
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, subprocess.TimeoutExpired) as error:
        # Only our own ValueErrors are safe to display; JSON errors can echo input.
        report["error"] = str(error) if type(error) is ValueError else type(error).__name__
        if report.get("database_refresh", {}).get("status") == "pending":
            report["database_refresh"]["status"] = "failed-or-unverified"
    report_path = output / "report.json"
    descriptor = os.open(report_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as file:
        json.dump(report, file, indent=2)
        file.write("\n")
    return report_path, report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scanner", choices=TOOLS)
    parser.add_argument("target")
    parser.add_argument("--semgrep-config", help="reviewed local Semgrep rules file/directory")
    parser.add_argument("--allow-network", action="store_true", help="allow Semgrep rule downloads / OSV advisory queries")
    parser.add_argument("--offline", action="store_true", help="SCA: explicitly skip the default database refresh; use cached advisories only")
    parser.add_argument("--history", action="store_true", help="scan local Git history instead of working files")
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument("--commit", help="SAST: exact local commit, new findings vs first parent (root: full snapshot)")
    scope.add_argument("--diff", action="store_true", help="SAST: working files (including eligible untracked) vs HEAD; not staged-only")
    parser.add_argument("--timeout", type=int, default=300, help="scanner timeout in seconds")
    args = parser.parse_args()
    if args.timeout < 1:
        parser.error("timeout must be positive")
    try:
        path, report = execute(args)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps({"report": str(path), "status": report["status"],
                      "candidates": len(report["findings"])}))
    return {"no-findings": 0, "findings": 1, "incomplete": 2}[report["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
