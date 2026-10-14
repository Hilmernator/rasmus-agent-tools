#!/usr/bin/env python3
"""Release secret scan: working files, reachable Git blobs and bounded archives."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shlex
import signal
import shutil
import stat
import subprocess
import tempfile
import time

import scan
from secret_archives import ArchiveReader, MIB, archive_kind


MAX_COMMITS = 10000
MAX_ENTRIES = 200000
MAX_BLOB_BYTES = 32 * MIB
GIT_OPTIONS = ["-c", "core.hooksPath=/dev/null", "-c", "protocol.ext.allow=never",
               "-c", "http.followRedirects=false", "-c", "maintenance.auto=false", "-c", "gc.auto=0"]


def git_env():
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT="0",
               GIT_NO_LAZY_FETCH="1", GIT_NO_REPLACE_OBJECTS="1", GIT_LFS_SKIP_SMUDGE="1",
               GIT_ALLOW_PROTOCOL="file:https:ssh",
               GIT_SSH_COMMAND="ssh -F /dev/null -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=15")
    return env


def git(repo, env, deadline, *args, input=None, output=None):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("Deep scan time limit reached")
    # Never relay Git stderr: a remote/config/path can contain credentials.
    with tempfile.TemporaryFile() as captured:
        with subprocess.Popen(["git", *GIT_OPTIONS, "-C", str(repo), *args], env=env,
                              stdin=subprocess.PIPE, stdout=output or captured, stderr=subprocess.DEVNULL,
                              start_new_session=True) as process:
            try:
                process.communicate(input=input, timeout=min(remaining, 120))
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                raise
        if process.returncode:
            raise ValueError("Git operation failed; check history availability and GitHub authentication")
        if output is not None:
            return b""
        if captured.tell() > 32 * MIB:
            raise ValueError("Git metadata exceeds the 32 MiB inventory limit")
        captured.seek(0)
        return captured.read()


def github_remote(repo, env, deadline):
    remote = git(repo, env, deadline, "config", "--local", "--no-includes", "--get", "remote.origin.url").decode().strip()
    match = re.fullmatch(r"(?:https://github\.com/|git@github\.com:|ssh://git@github\.com/)([A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*)(?:/)?", remote)
    if not match:
        raise ValueError("origin must be a credential-free github.com HTTPS or SSH repository URL")
    return remote, match[1].removesuffix(".git")


def fetch_github(repo, url, env, deadline):
    if git(repo, env, deadline, "for-each-ref", "--format=%(refname)", "refs/rai-github/").strip():
        raise ValueError("Fetch namespace already exists; preserve local refs instead of replacing them")
    # Use existing gh authentication for HTTPS without reading tokens into Python.
    auth = []
    if url.startswith("https:") and shutil.which("gh"):
        auth = ["-c", "credential.helper=", "-c",
                f"credential.https://github.com.helper=!{shlex.quote(shutil.which('gh'))} auth git-credential"]
    shallow = git(repo, env, deadline, "rev-parse", "--is-shallow-repository").strip() == b"true"
    git(repo, env, deadline, *auth, "fetch", "--quiet", "--no-tags", "--no-recurse-submodules",
        *(["--unshallow"] if shallow else []), "--", url,
        "+refs/heads/*:refs/rai-github/heads/*", "+refs/tags/*:refs/rai-github/tags/*",
        "+refs/pull/*:refs/rai-github/pull/*")


def history_blobs(repo, env, deadline, coverage, max_bytes):
    commits = git(repo, env, deadline, "log", "--all", "HEAD", f"--max-count={MAX_COMMITS + 1}", "--format=%H %T").splitlines()
    if len(commits) > MAX_COMMITS:
        coverage["gaps"].append({"reason": "Historical commit inventory limit reached"})
    trees, blobs = set(), {}
    entries = total_bytes = 0
    # ponytail: walk unique commit trees with a finite entry budget; use an object-stream
    # inventory if large repositories regularly exceed this deliberately simple bound.
    for row in commits[:MAX_COMMITS]:
        commit, tree = row.decode("ascii").split()
        if tree in trees:
            continue
        trees.add(tree)
        listing = git(repo, env, deadline, "ls-tree", "-r", "-l", "-z", tree)
        for record in listing.split(b"\0"):
            if not record:
                continue
            entries += 1
            if entries > MAX_ENTRIES:
                coverage["gaps"].append({"reason": "Historical tree-entry inventory limit reached"})
                return blobs
            fields, name = record.split(b"\t", 1)
            mode, kind, oid, size = fields.split()
            metadata = {"path": os.fsdecode(name), "commit": commit, "blob": oid.decode(), "origin": "history"}
            if kind != b"blob" or mode == b"120000":
                coverage["gaps"].append({**metadata, "reason": "Submodule or symlink content not followed"})
                continue
            if metadata["blob"] in blobs:
                continue
            size = int(size)
            if size > MAX_BLOB_BYTES or total_bytes + size > max_bytes:
                coverage["gaps"].append({**metadata, "reason": "Historical blob-size or total-byte limit reached"})
                continue
            total_bytes += size
            blobs[metadata["blob"]] = (size, metadata)
    coverage.update(historical_commits_considered=min(len(commits), MAX_COMMITS),
                    historical_unique_trees=len(trees), historical_unique_blobs=len(blobs),
                    historical_blob_bytes=total_bytes)
    return blobs


def stage_history(repo, env, deadline, coverage, output, archives, max_bytes):
    blobs = history_blobs(repo, env, deadline, coverage, max_bytes)
    locations = {}
    # One native batch operation avoids spawning Git for every historical file.
    with tempfile.TemporaryFile() as contents:
        git(repo, env, deadline, "cat-file", "--batch", input="".join(oid + "\n" for oid in blobs).encode(), output=contents)
        contents.seek(0)
        for oid, (size, metadata) in blobs.items():
            archives.check_time()
            if contents.readline(200).split() != [oid.encode(), b"blob", str(size).encode()]:
                raise ValueError("Historical blob unavailable or batch response malformed")
            data = contents.read(size)
            if len(data) != size or contents.read(1) != b"\n":
                raise ValueError("Historical blob was truncated")
            name = f"blob-{len(locations):08d}.txt"
            (output / name).write_bytes(data)
            locations[name] = metadata
            if data.startswith(b"version https://git-lfs.github.com/spec/v1"):
                archives.gap(metadata, "Git LFS pointer only; referenced content was not fetched")
            archives.inspect(data, metadata)
    return locations


def working_archives(target, archives):
    count = 0
    def walk_error(_error):
        archives.gap({"origin": "working-tree"}, "Working directory inventory inaccessible")
    for directory, dirs, files in os.walk(target, followlinks=False, onerror=walk_error):
        dirs[:] = [name for name in dirs if name.lower() != ".git"]
        for name in [*dirs, *files]:
            if name.lower() == ".git":
                continue
            archives.check_time()
            count += 1
            if count > MAX_ENTRIES:
                archives.gap({"origin": "working-tree"}, "Working file inventory limit reached")
                return
            path = Path(directory) / name
            metadata = {"path": str(path.relative_to(target)), "origin": "working-tree"}
            try:
                mode = path.lstat().st_mode
                if stat.S_ISDIR(mode):
                    continue
                if not stat.S_ISREG(mode):
                    archives.gap(metadata, "Symlink or special working file not followed")
                    continue
                if not path.parent.resolve().is_relative_to(target):
                    archives.gap(metadata, "Working path parent resolves outside target")
                    continue
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(descriptor, "rb") as stream:
                    if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                        archives.gap(metadata, "Working file changed type during inventory")
                        continue
                    prefix = stream.read(512)
                    if prefix.startswith(b"version https://git-lfs.github.com/spec/v1"):
                        archives.gap(metadata, "Git LFS pointer only; referenced content was not fetched")
                    if not archive_kind(name, prefix):
                        continue
                    stream.seek(0)
                    data = stream.read(MAX_BLOB_BYTES + 1)
                if len(data) > MAX_BLOB_BYTES:
                    archives.gap(metadata, "Archive input exceeds the 32 MiB file limit")
                    continue
                archives.inspect(data, metadata)
            except OSError:
                archives.gap(metadata, "Working file unreadable")


def run_phase(target, timeout, report, phase, locations=None):
    args = argparse.Namespace(scanner="secrets", target=str(target), history=False,
                              allow_network=False, semgrep_config=None, commit=None, diff=False, timeout=timeout)
    path, result = scan.execute(args)
    try:
        report["phases"].append({"phase": phase, **{key: result[key] for key in
                               ("status", "version", "rules", "coverage", "error") if key in result}})
        for finding in result["findings"]:
            item = {**finding, "origin": phase}
            if locations is not None:
                name = Path(item["path"]).name
                if name not in locations:
                    raise ValueError("Scanner returned an unmapped temporary path")
                item.update(locations[name])
            item["id"] = f"SECRET-{len(report['findings']) + 1:04d}"
            report["findings"].append(item)
        if result["status"] == "incomplete":
            report["coverage"]["gaps"].append({"phase": phase, "reason": "Scanner phase incomplete; see phase metadata"})
    finally:
        shutil.rmtree(path.parent)


def execute(args):
    target = Path(args.target).expanduser().resolve(strict=True)
    if not target.is_dir() or args.timeout < 1 or args.max_history_mib < 1 or args.max_archive_mib < 1:
        raise ValueError("Target must be a directory and limits must be positive")
    output = Path(tempfile.mkdtemp(prefix="rai-secrets-deep-")).resolve()
    if output.is_relative_to(target):
        output.rmdir()
        raise ValueError("Target contains the temporary directory; choose a narrower target")
    report = {"schema_version": 1, "scanner": "secrets", "tool": "gitleaks", "scope": "release-deep",
              "target": str(target), "started_at": datetime.now(timezone.utc).isoformat(),
              "network_allowed": not args.offline, "status": "incomplete", "findings": [], "phases": [],
              "coverage": {"gaps": [], "remote_refresh": "not-requested", "limits": {
                  "timeout_seconds": args.timeout, "history_mib": args.max_history_mib,
                  "archive_expanded_mib": args.max_archive_mib, "file_mib": 32,
                  "archive_depth": 5, "archive_members": 10000, "commits": MAX_COMMITS, "inventory_entries": MAX_ENTRIES}},
              "coverage_notes": [
                  "Working files include untracked/ignored content; .git internals and symlinks are not followed.",
                  "Every reachable regular Git blob in inventoried commit trees is scanned once, including deleted files and merge-only changes.",
                  "Historical path/commit is one representative occurrence per blob, not an exhaustive exposure timeline; blob IDs identify whole Git objects, not credentials.",
                  "Historical and extracted member scans use opaque names; path-based allowlists may differ from working-file scans. Bundled rule allowlists, binary detection and decode depth 5 still limit detection.",
                  "Archive support: ZIP/TAR and gzip/bzip2/xz, detected by header or filename; other formats and unknown binary encodings are not guaranteed detectable.",
                  "Remote coverage is the refs GitHub exposes at fetch time; deleted/unreachable history, reflogs, other remotes, external submodule/LFS data, Actions logs/artifacts, release assets and comments are outside scope.",
                  "No credential validation, source upload, installation, source/index/ref changes or automatic release approval. No-findings is not proof of absence."]}
    coverage = report["coverage"]
    deadline = time.monotonic() + args.timeout
    env = git_env()
    with tempfile.TemporaryDirectory(prefix="raw-", dir=output) as temporary:
        scratch = Path(temporary)
        members, historical = scratch / "members", scratch / "history"
        members.mkdir()
        historical.mkdir()
        archives = ArchiveReader(members, coverage, deadline, max_bytes=args.max_archive_mib * MIB)
        try:
            run_phase(target, max(1, deadline - time.monotonic()), report, "working-tree")
            working_archives(target, archives)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            coverage["gaps"].append({"phase": "working-tree", "reason": "Working scan/inventory failed or timed out"})
        try:
            root = git(target, env, deadline, "rev-parse", "--show-toplevel").decode().strip()
            if Path(root).resolve() != target:
                raise ValueError("Deep scan requires the Git repository root")
            mirror = scratch / "mirror.git"
            git(scratch, env, deadline, "clone", "--quiet", "--mirror", "--no-hardlinks", "--template=", "--", str(target), str(mirror))
            if args.offline:
                coverage["gaps"].append({"reason": "Offline requested; GitHub refs were not refreshed"})
            else:
                coverage["remote_refresh"] = "failed"
                try:
                    url, coverage["github_repository"] = github_remote(target, env, deadline)
                    fetch_github(mirror, url, env, deadline)
                    refs = git(mirror, env, deadline, "for-each-ref", "--format=%(refname) %(objectname)", "refs/rai-github/")
                    coverage["github_refs"] = refs.decode().splitlines()
                    coverage["remote_refresh"] = "succeeded"
                except (OSError, ValueError, subprocess.TimeoutExpired):
                    coverage["gaps"].append({"reason": "GitHub refresh failed; check origin URL/authentication/network, local history retained"})
            coverage["history_shallow"] = git(mirror, env, deadline, "rev-parse", "--is-shallow-repository").strip() == b"true"
            if coverage["history_shallow"]:
                coverage["gaps"].append({"reason": "Shallow history remains incomplete"})
            # Even older Git versions must not lazily fetch missing promisor objects.
            local_env = {**env, "GIT_ALLOW_PROTOCOL": ""}
            locations = stage_history(mirror, local_env, deadline, coverage, historical, archives, args.max_history_mib * MIB)
            if locations:
                archives.check_time()
                run_phase(historical, max(1, deadline - time.monotonic()), report, "history", locations)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            coverage["gaps"].append({"phase": "history", "reason": "Historical inventory/scan failed or timed out; requires repository root and available Git objects"})
        try:
            if archives.locations:
                archives.check_time()
                run_phase(members, max(1, deadline - time.monotonic()), report, "archive-members", archives.locations)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            coverage["gaps"].append({"phase": "archive-members", "reason": "Archive scan failed or timed out"})
        coverage.update(archive_containers=archives.containers, archive_members_considered=archives.members,
                        archive_members_staged=len(archives.locations), archive_expanded_bytes=archives.bytes)
    if not coverage["gaps"]:
        report["status"] = "findings" if report["findings"] else "no-findings"
    path = output / "report.json"
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as file:
        json.dump(report, file, indent=2)
        file.write("\n")
    return path, report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target")
    parser.add_argument("--offline", action="store_true", help="skip GitHub fetch; release coverage remains incomplete")
    parser.add_argument("--timeout", type=int, default=600, help="overall time budget in seconds")
    parser.add_argument("--max-history-mib", type=int, default=512)
    parser.add_argument("--max-archive-mib", type=int, default=256)
    args = parser.parse_args()
    try:
        path, report = execute(args)
    except (OSError, ValueError):
        parser.exit(2, "Deep scan could not start; check target and positive limits.\n")
    print(json.dumps({"report": str(path), "status": report["status"], "candidates": len(report["findings"])}))
    return {"no-findings": 0, "findings": 1, "incomplete": 2}[report["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
