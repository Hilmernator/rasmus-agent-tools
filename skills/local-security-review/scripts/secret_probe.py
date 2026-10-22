#!/usr/bin/env python3
"""Answer safe yes/no questions about SECRET- findings without printing any value.

The matched line is read locally; only booleans, sizes and buckets are printed, so an
agent can separate placeholders and env references from real committed credentials.
"""

import argparse
import json
import math
import os
from pathlib import Path
import re
import subprocess

PLACEHOLDER = re.compile(r"(?i)example|sample|dummy|placeholder|changeme|change_me|your[_-]|xxxx|fake|redacted|"
                         r"todo|insert|replace|<[^>]*>|\*{4,}|^test|_test$|^demo|lorem|foobar")
ENV_REFERENCE = re.compile(r"\$\{|\$[A-Z_]{3,}|process\.env|import\.meta\.env|os\.environ|getenv|env::var|"
                           r"System\.getenv|ENV\[|secrets\.|\{\{")
TEST_PATH = re.compile(r"(?i)(^|/)(tests?|spec|__tests__|fixtures?|testdata|examples?|mocks?)(/|$)|(^|/)test_|_test\.|\.spec\.|\.test\.")
BUILD_PARTS = {"node_modules", "target", ".next", "dist", "build", ".venv", "venv", "__pycache__", ".turbo"}
TOKEN = re.compile(r"[A-Za-z0-9_\-+/=.:~]{8,}")


def entropy(value):
    counts = {char: value.count(char) for char in set(value)}
    return -sum(count / len(value) * math.log2(count / len(value)) for count in counts.values())


def git(repo, *args):
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT="0")
    return subprocess.run(["git", "-C", str(repo), *args], env=env, capture_output=True, timeout=120)


def candidate(text):
    """Longest token after an assignment-like separator, else the longest token on the lines."""
    assigned = re.findall(r"[:=]\s*[\"']?([^\s\"',;]{8,})", text)
    tokens = assigned or TOKEN.findall(text)
    return max(tokens, key=len) if tokens else ""


def probe(repo, finding, history):
    if finding.get("empty"):
        return {"id": finding["id"], "readable": True, "secret_shaped_lines": 0}
    path, commit = finding["path"], finding.get("commit") or ""
    if commit:
        shown = git(repo, "show", f"{commit}:{path}")
        lines = shown.stdout.decode(errors="replace").splitlines() if shown.returncode == 0 else []
    else:
        file = (repo / path).resolve()
        if not file.is_relative_to(repo) or not file.is_file():
            return {"id": finding["id"], "readable": False}
        lines = file.read_text(errors="replace").splitlines()
    start, end = finding.get("line") or 1, finding.get("end_line") or finding.get("line") or 1
    text = "\n".join(lines[start - 1:end])
    if not text:
        return {"id": finding["id"], "readable": False}
    token = candidate(text)
    tracked = git(repo, "ls-files", "--error-unmatch", "--", path).returncode == 0
    result = {
        "id": finding["id"], "readable": True,
        "looks_like_placeholder": bool(PLACEHOLDER.search(token)) or len(set(token)) <= 4,
        "references_environment_or_template": bool(ENV_REFERENCE.search(text)),
        "token_length": len(token),
        "entropy_bits_per_char": round(entropy(token), 1) if token else 0.0,
        "high_entropy": len(token) >= 16 and entropy(token) >= 3.5,
        "test_or_example_path": bool(TEST_PATH.search(path)),
        "build_or_dependency_output": any(part in BUILD_PARTS for part in Path(path).parts),
        "tracked_in_git": tracked or bool(commit),
        "git_ignored": not commit and git(repo, "check-ignore", "-q", "--", path).returncode == 0,
    }
    if history and token:
        # The value is passed to local git only; nothing is printed or sent anywhere.
        found = git(repo, "log", "--all", "-n", "1", "--format=%H", f"-S{token}")
        result["value_ever_committed"] = bool(found.stdout.strip()) if found.returncode == 0 else None
    exposed = result["tracked_in_git"] or result.get("value_ever_committed")
    if result["looks_like_placeholder"] or result["references_environment_or_template"]:
        result["hint"] = "placeholder-or-reference"
    elif not result["high_entropy"]:
        # Hand-written values (e.g. "SUPER_SECRET_API_KEY") can still be real, weak credentials.
        result["hint"] = "low-entropy-literal: check where it is used" + ("; committed" if exposed else "")
    else:
        result["hint"] = "looks-real-and-committed: rotate" if exposed else "looks-real-local-only: keep out of git"
    return result


def file_findings(repo, path):
    """Every assignment-like line in a file the scanner did not flag (config, .env)."""
    lines = (repo / path).read_text(errors="replace").splitlines()
    return [{"id": f"{path}:{number}", "path": path, "line": number}
            for number, line in enumerate(lines, 1) if re.search(r"[:=]\s*[\"']?[^\s\"',;]{8,}", line)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, nargs="?", help="combined or secrets report.json")
    parser.add_argument("ids", nargs="*", help="SECRET- IDs (default: all)")
    parser.add_argument("--file", action="append", default=[],
                        help="repository-relative file to probe line by line instead of report findings (needs --repo)")
    parser.add_argument("--repo", type=Path, help="repository root for --file (default: the report's target)")
    parser.add_argument("--history", action="store_true", help="also check whether the value was ever committed (git log -S)")
    args = parser.parse_args()
    report = json.loads(args.report.read_text()) if args.report else {"findings": []}
    repo = (args.repo or Path(report.get("target", "."))).resolve()
    if args.file:
        findings = []
        for name in args.file:
            if Path(name).is_absolute() or not (repo / name).resolve().is_relative_to(repo):
                parser.error("--file must stay inside the repository")
            lines = file_findings(repo, name)
            findings += lines or [{"id": name, "path": name, "line": 0, "empty": True}]
    else:
        wanted = set(args.ids)
        findings = [item for item in report["findings"]
                    if item["id"].startswith("SECRET-") and (not wanted or item["id"] in wanted)]
    print(json.dumps([probe(repo, finding, args.history) for finding in findings], indent=2))


if __name__ == "__main__":
    main()
