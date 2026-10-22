"""Pinned local Trivy IaC checks, without executing or configuring consumer code."""

import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tarfile
import tempfile
import urllib.request

VERSION = "0.74.0"
HASHES = {
    "macOS-ARM64": "1caada5e0e2091909357c7525d3aa76f4b660b13821bc143b190c7483e31cc11",
    "macOS-64bit": "472816f6888dda689d075c30254d4210b4d1035acf365aa72332f584c2f60485",
    "Linux-ARM64": "b94ce1976bbf3c15b514b605ee88be7c6d94a29be2302847ff01cb794d47aad5",
    "Linux-64bit": "2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a",
}
CACHE = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "rasmus-security/iac"
ARCHIVE_LIMIT = 128 * 1024 * 1024
MEMBER_LIMIT = 256 * 1024 * 1024
FILE_LIMIT = 1024 * 1024
TOTAL_LIMIT = 64 * 1024 * 1024
REPORT_LIMIT = 32 * 1024 * 1024
SCANNERS = "cloudformation,terraform,terraformplan-json,dockerfile,kubernetes"
EXCLUDED = {".git", "node_modules", ".venv", "venv", ".terraform", "__pycache__"}


def artifact():
    system = {"Darwin": "macOS", "Linux": "Linux"}.get(platform.system())
    arch = {"arm64": "ARM64", "aarch64": "ARM64", "x86_64": "64bit", "AMD64": "64bit"}.get(platform.machine())
    key = f"{system}-{arch}"
    if key not in HASHES:
        raise ValueError("IaC setup supports macOS/Linux arm64/x64")
    return key


def root():
    return CACHE / VERSION / artifact()


def archive_contents(path):
    if path.is_symlink() or path.stat().st_size > ARCHIVE_LIMIT or hashlib.sha256(path.read_bytes()).hexdigest() != HASHES[artifact()]:
        raise ValueError("Trivy archive integrity mismatch; preserve cache and inspect")
    contents = {}
    with tarfile.open(path, "r:gz") as archive:
        for name in ("trivy", "LICENSE"):
            members = [m for m in archive.getmembers() if m.name == name]
            if len(members) != 1 or not members[0].isfile() or not 0 < members[0].size <= MEMBER_LIMIT:
                raise ValueError("Unexpected Trivy archive member")
            contents[name] = archive.extractfile(members[0]).read(MEMBER_LIMIT + 1)
            if len(contents[name]) != members[0].size:
                raise ValueError("Truncated Trivy archive")
    return contents


def checked_executable():
    directory = root()
    if directory.is_symlink():
        raise ValueError("Trivy installation cannot be a symlink")
    for name, expected in archive_contents(directory / "release.tar.gz").items():
        path = directory / name
        if path.is_symlink() or path.stat().st_size != len(expected) or path.read_bytes() != expected:
            raise ValueError("Installed Trivy binary/license differs from pinned archive")
    binary = directory / "trivy"
    if not os.access(binary, os.X_OK):
        raise ValueError("Trivy binary is not executable")
    return str(binary)


def check():
    result = {"status": "needs-setup", "version": VERSION,
              "license": "Apache-2.0 engine; MIT checks; bundled dependencies include MPL-2.0 (separate tool policy)"}
    try:
        result.update(status="prerequisites-ready", executable=checked_executable(),
                      license_path=str(root() / "LICENSE"), archive_sha256=HASHES[artifact()])
    except (OSError, ValueError, tarfile.TarError) as error:
        result["status"] = "needs-setup"
        result["error"] = str(error) if type(error) is ValueError else type(error).__name__
    return result


def install():
    directory = root()
    if directory.exists() or directory.is_symlink():
        return {"status": "already-installed", "executable": checked_executable()}
    url = f"https://github.com/aquasecurity/trivy/releases/download/v{VERSION}/trivy_{VERSION}_{artifact()}.tar.gz"
    directory.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=directory.parent) as temporary:
        downloaded = Path(temporary) / "release.tar.gz"
        with urllib.request.urlopen(url, timeout=60) as response, downloaded.open("wb") as file:
            if not response.geturl().startswith("https://"):
                raise ValueError("Refusing non-HTTPS IaC download")
            size = 0
            for block in iter(lambda: response.read(1024 * 1024), b""):
                size += len(block)
                if size > ARCHIVE_LIMIT:
                    raise ValueError("Trivy archive exceeds download limit")
                file.write(block)
        for name, content in archive_contents(downloaded).items():
            (Path(temporary) / name).write_bytes(content)
        (Path(temporary) / "trivy").chmod(0o755)
        directory.mkdir(mode=0o700)
        for name in ("trivy", "LICENSE", "release.tar.gz"):
            os.link(Path(temporary) / name, directory / name)
    result = check()
    if result["status"] != "prerequisites-ready":
        raise ValueError("Trivy installation verification failed; preserve cache and inspect")
    return dict(result, status="installed", source=url)


def candidate(name):
    path = Path(name)
    return (path.suffix.lower() in {".tf", ".tofu", ".tfvars", ".json", ".yaml", ".yml", ".template"}
            or path.name.lower() in ("dockerfile", "containerfile")
            or path.name.lower().startswith(("dockerfile.", "containerfile."))
            or path.name.lower().endswith((".dockerfile", ".containerfile")))


def likely_iac(name):
    path = Path(name)
    return (path.suffix.lower() in {".tf", ".tofu", ".tfvars", ".template"} or "dockerfile" in path.name.lower()
            or "containerfile" in path.name.lower())


MODULE_BLOCK = re.compile(rb'(?m)^\s*module\s+"[^"]*"\s*\{')
MODULE_SOURCE = re.compile(rb'(?m)^\s*source\s*=\s*"([^"]*)"')


def remote_modules(name, data):
    """True when a module block may resolve outside the repository (registry, git, http)."""
    if name.endswith(".json"):
        blocks = json.loads(data).get("module") or {}
        sources = [str(body.get("source", "")) for body in (blocks.values() if isinstance(blocks, dict) else [])
                   if isinstance(body, dict)]
        return bool(blocks) and not all(source.startswith(("./", "../")) for source in sources)
    if not MODULE_BLOCK.search(data):
        return False
    # ponytail: any non-local source line in a module-bearing file counts, even outside the module block.
    sources = MODULE_SOURCE.findall(data)
    return not sources or not all(source.startswith((b"./", b"../")) for source in sources)


def extra_files(target, paths):
    """Explicit full-scan inputs may include Git-ignored synthesized templates."""
    files = set()
    for name in paths:
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("IaC paths must be repository-relative")
        base = target / relative
        if base.is_symlink() or not base.resolve(strict=True).is_relative_to(target):
            raise ValueError("IaC path escapes repository or is a symlink")
        entries = [base] if base.is_file() else base.rglob("*")
        found = False
        for path in entries:
            if any(part in EXCLUDED for part in path.relative_to(target).parts):
                continue
            if candidate(path.name) and (path.is_file() or path.is_symlink()):
                files.add(str(path.relative_to(target)))
                found = True
                if len(files) > 10000:
                    raise ValueError("Explicit IaC file limit reached")
        if not found:
            raise ValueError("Explicit IaC path contains no candidate files")
    return files


def safe_name(name):
    if not isinstance(name, str):
        raise ValueError("IaC report path must be a string")
    path = Path(name)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("Unsafe IaC report path")
    return path.as_posix()


def project(data, selected):
    if not isinstance(data, dict) or data.get("SchemaVersion") != 2 or not isinstance(data.get("Results", []), list):
        raise ValueError("Invalid Trivy JSON report")
    findings, evaluated = [], set()
    counts = {"passed": 0, "failed": 0, "exceptions": 0}
    for result in data.get("Results", []):
        name = safe_name(result["Target"])
        if name in selected:
            evaluated.add(name)
        elif name != "." and not any(path.startswith(name + "/") for path in selected):
            raise ValueError("Trivy result outside selected input")
        if result.get("Type") == "terraform" and result.get("Misconfigurations"):
            evaluated.update(path for path in selected if str(Path(path).parent) == name and path.endswith((".tf", ".tf.json", ".tofu", ".tofu.json")))
        for item in result.get("Misconfigurations", []):
            status = item["Status"]
            if status == "PASS":
                counts["passed"] += 1
                continue
            if status not in ("FAIL", "EXCEPTION"):
                raise ValueError("Unknown IaC check status")
            counts["failed" if status == "FAIL" else "exceptions"] += 1
            cause = item.get("CauseMetadata", {})
            # Rule IDs and locations only: resource names, messages and code can contain secrets.
            findings.append({"rule": item["ID"], "path": name, "line": cause.get("StartLine") or None,
                             "end_line": cause.get("EndLine") or None, "scanner_severity": item["Severity"],
                             "metadata": {"iac_type": result["Type"], "check_status": status}})
    return findings, {"evaluated_paths": sorted(evaluated), "check_counts": counts}


def run(target, names, excluded, temporary, env, timeout, changed=None, paths=()):
    report = {"tool": "trivy", "version": VERSION, "status": "incomplete", "findings": [],
              "scope": "full IaC snapshot when IaC changes; no baseline subtraction",
              "coverage": {"selected_paths": [], "exclusions": [], "gaps": []},
              "rules": "embedded in checksum-pinned binary; no rule/database downloads"}
    coverage = report["coverage"]
    gaps = coverage["gaps"]
    try:
        if changed is not None and paths:
            raise ValueError("Explicit IaC paths are only supported for full working scans")
        candidates = sorted({name for name in names if candidate(name)} | extra_files(target, paths))
        cdk = [name for name in names if Path(name).name == "cdk.json"]
        if changed is not None and not cdk and not any(candidate(name) for name in changed):
            report.update(status="not-applicable", reason="No IaC candidate changed in this scope")
            return report
        if changed == set():
            report.update(status="not-applicable", reason="No changed files")
            return report
        coverage["exclusions"] = [entry for entry in excluded if candidate(entry["path"])]
        # Large lockfiles/data JSON match the candidate suffixes; only real IaC exclusions are gaps.
        if any(likely_iac(entry["path"]) for entry in coverage["exclusions"]):
            gaps.append("IaC candidates excluded by file, size or symlink policy")
        if cdk and not paths:
            gaps.append("CDK sources need current synthesized CloudFormation: full scan with --iac-path; synth/AWS execution is not automatic")
        contents = {}
        total = 0
        for name in candidates:
            if any(part in EXCLUDED for part in Path(name).parts):
                coverage["exclusions"].append({"path": name, "reason": "dependency/cache directory"})
                continue
            path = target / name
            if any((target / parent).is_symlink() for parent in (Path(name), *Path(name).parents)) or not path.resolve().is_relative_to(target) or not path.is_file() or path.stat().st_size > FILE_LIMIT:
                coverage["exclusions"].append({"path": name, "reason": "symlink, external, missing or over 1 MiB"})
                gaps.append("IaC candidate could not be safely selected")
                continue
            data = path.read_bytes()
            if len(data) > FILE_LIMIT:
                raise ValueError("IaC file grew beyond limit during scan")
            total += len(data)
            if total > TOTAL_LIMIT:
                raise ValueError("IaC input exceeds 64 MiB")
            if re.search(rb"(?i)(?:trivy|tfsec):ignore", data):
                gaps.append(f"Inline IaC suppression present: {name}; coverage is incomplete")
            if Path(name).name in ("Chart.yaml", "Chart.yml"):
                gaps.append(f"Helm rendering is not enabled: {name}; supply rendered Kubernetes manifests")
            contents[name] = data
        terraform = {name for name in contents if name.endswith((".tf", ".tf.json", ".tofu", ".tofu.json"))}
        # ponytail: regex over HCL, not a parser. Local "./" sources need no download; any other
        # source could make Trivy fetch, so that Terraform set is skipped. Use a native
        # disable-downloads flag if Trivy exposes one in a future release.
        modules = any(remote_modules(name, contents[name]) for name in terraform)
        if modules:
            gaps.append("Terraform module declarations require a separately prepared plan; no module downloads or partial-source evaluation")
            for name in sorted(terraform):
                contents.pop(name)
                coverage["exclusions"].append({"path": name, "reason": "Terraform module-bearing source scope (network disabled)"})
        if not contents:
            if not gaps:
                report.update(status="not-applicable", reason="No eligible IaC candidate files")
            return report
        executable = checked_executable()
        work = Path(temporary) / "iac"
        work.mkdir()
        input_dir = work / "input"
        input_dir.mkdir()
        for name, data in contents.items():
            destination = input_dir / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
        coverage["selected_paths"] = sorted(contents)
        coverage["explicit_paths"] = list(paths)
        (work / "config.yaml").write_text("{}\n")
        raw = work / "report.json"
        # No target configs, plugin paths, credentials or scanner env overrides.
        child_env = {key: value for key, value in env.items() if key in ("PATH", "LANG", "LC_ALL", "TMPDIR", "TMP", "TEMP", "SYSTEMROOT")}
        child_env.update(AWS_EC2_METADATA_DISABLED="true", AWS_SHARED_CREDENTIALS_FILE=os.devnull, AWS_CONFIG_FILE=os.devnull)
        argv = [executable, "config", "--config", str(work / "config.yaml"), "--cache-dir", str(work / "cache"),
                "--module-dir", str(work / "modules"), "--disable-telemetry", "--skip-check-update", "--skip-version-check",
                "--ignorefile", os.devnull, "--include-non-failures", "--misconfig-scanners", SCANNERS,
                "--format", "json", "--output", str(raw), "--timeout", f"{timeout}s", str(input_dir)]
        with (work / "process.log").open("wb") as log:
            result = subprocess.run(argv, cwd=work, env=child_env, stdout=log, stderr=log, timeout=timeout)
        if not raw.is_file() or raw.stat().st_size > REPORT_LIMIT:
            raise ValueError("IaC report missing or exceeds 32 MiB")
        report["findings"], projected = project(json.loads(raw.read_text()), contents)
        coverage.update(projected)
        log_path = work / "process.log"
        if log_path.stat().st_size > REPORT_LIMIT:
            raise ValueError("IaC diagnostics exceed 32 MiB")
        # Trivy can log parse/evaluation errors and still exit zero. Keep their presence,
        # never the diagnostic text. The embedded-check fallback is expected offline.
        diagnostics = [line for line in log_path.read_bytes().splitlines() if re.search(rb"\b(?:WARN|ERROR)\b", line)
                       and b"Falling back to embedded checks" not in line]
        # Terraform without tfvars is normal; Trivy still evaluates with defaults/unknowns.
        unset = [line for line in diagnostics if b"Variable values were not found" in line]
        warnings = [line for line in diagnostics if line not in unset]
        if unset:
            coverage["notes"] = ["Terraform variables without values were evaluated as defaults/unknown; "
                                 "checks that depend on them may be missed"]
        coverage["diagnostic_warnings_or_errors"] = len(warnings)
        # Component tags such as "[terraform parser]" say where to look without echoing file content.
        coverage["diagnostic_sources"] = sorted({tag.decode(errors="replace") for line in warnings
                                                 for tag in re.findall(rb"\[([a-z][a-z /-]{1,40})\]", line)})
        if warnings or result.returncode:
            gaps.append("Trivy reported scan/evaluation diagnostics or a process failure; raw messages withheld")
        if coverage["check_counts"]["exceptions"]:
            gaps.append("IaC checks were suppressed or excepted")
        coverage["unclassified_or_unevaluated_paths"] = sorted(set(contents) - set(coverage["evaluated_paths"]))
        expected = {name for name in contents if Path(name).suffix in (".tf", ".tofu", ".template")
                    or "dockerfile" in Path(name).name.lower() or "containerfile" in Path(name).name.lower()
                    or name.endswith((".tf.json", ".tofu.json", ".template.json"))
                    or b"AWS::" in contents[name] or b"apiVersion" in contents[name] or b"resource_changes" in contents[name]}
        coverage["missing_expected_paths"] = sorted(expected - set(coverage["evaluated_paths"]))
        if coverage["missing_expected_paths"]:
            gaps.append("Expected IaC files have no evaluation evidence")
        if not coverage["evaluated_paths"] and not gaps:
            report.update(status="not-applicable", reason="No supported IaC recognized; unclassified JSON/YAML paths remain listed")
            return report
        if not gaps:
            report["status"] = "findings" if report["findings"] else "no-findings"
    except (OSError, ValueError, KeyError, TypeError, AttributeError, tarfile.TarError, subprocess.SubprocessError):
        report["error"] = "IaC input, installation or scan failed; findings may be partial; raw diagnostics withheld"
    return report
