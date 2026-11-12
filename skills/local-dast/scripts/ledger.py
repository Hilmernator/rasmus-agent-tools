#!/usr/bin/env python3
"""The findings ledger: security/findings.csv in the reviewed repository.

One row per finding and skill, updated in place; no other file is written. Run `record` last, when every
candidate has its disposition. It says which findings are new, which were seen before and which changed,
then stores this run's rows. A finding that is still unreviewed gets no label and no row, so an earlier
verdict never stands in for a missing one. local-security-review and local-dast bundle the same file.

  ledger.py record <repo> <review.json>                        output of render_review.py
  ledger.py record <repo> <report.json> --assessments <file>   output of dast.py and the agent's verdicts
  ledger.py decide <repo> <fingerprint> --status <status> --note <why>   the user's own decision
"""
import argparse
import collections
import csv
import datetime
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

FIELDS = ["fingerprint", "skill", "rule", "path", "status", "basis", "sha", "first_seen", "last_seen", "note"]
STATUSES = ("confirmed", "likely", "needs-review", "false-positive")
BASES = ("test", "code", "assumed", "user")  # how the status is known; `user` is set only by `decide`
NOTE = 160


def git(repo, *args):
    try:
        return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)
    except OSError:
        return subprocess.CompletedProcess(args, 1, "", "")


def ensure_ignored(repo, entry):
    """Keep the ledger out of commits without touching a tracked file: add it to .git/info/exclude."""
    if git(repo, "rev-parse", "--is-inside-work-tree").stdout.strip() != "true":
        return
    if git(repo, "ls-files", "--", entry).stdout.strip() or git(repo, "check-ignore", "-q", entry).returncode == 0:
        return
    exclude = Path(git(repo, "rev-parse", "--git-path", "info/exclude").stdout.strip())
    exclude = exclude if exclude.is_absolute() else repo / exclude
    exclude.parent.mkdir(parents=True, exist_ok=True)
    with exclude.open("a") as f:
        f.write(f"\n# local security state, not for commits\n{entry}\n")
    print(f"ignored: added {entry} to {exclude}")


def stamp(repo):
    sha = git(repo, "rev-parse", "--short", "HEAD").stdout.strip()
    return datetime.date.today().isoformat() + (f" {sha}" if sha else "")


def load(path):
    if not path.exists():
        return []
    with path.open(newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames != FIELDS:
            sys.exit(f"{path}: header must be {','.join(FIELDS)}")
        rows = list(reader)
    for r in rows:
        if r["status"] not in STATUSES or r["basis"] not in BASES:
            sys.exit(f"{path}: {r['fingerprint']} has a status or basis outside {STATUSES} and {BASES}")
    if len({(r["fingerprint"], r["skill"]) for r in rows}) != len(rows):
        sys.exit(f"{path}: a fingerprint is listed twice for one skill")
    return rows


def save(path, rows):
    path.parent.mkdir(exist_ok=True)
    tmp = path.with_name(".findings.csv.tmp")
    with tmp.open("w", newline="") as f:
        w = csv.DictWriter(f, FIELDS, lineterminator="\n")
        w.writeheader()
        w.writerows(sorted(rows, key=lambda r: (r["skill"], r["path"], r["rule"], r["fingerprint"])))
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def one_line(text):
    # A spreadsheet runs a cell that starts with one of these; the text comes from scanners and agents.
    text = " ".join(str(text or "").split()).lstrip("=+-@")
    return text if len(text) <= NOTE else text[:NOTE - 1] + "…"


def short(text):
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def review_items(repo, doc):
    """Candidates of local-security-review. The fingerprint follows the flagged text, not its line number."""
    files = {}

    def data(path):
        if path not in files:
            full = (repo / path).resolve()
            files[path] = full.read_bytes() if full.is_relative_to(repo) and full.is_file() else None
        return files[path]

    items = []
    for row in doc["findings"]:
        f, a = row["scanner_finding"], row["assessment"]
        path, kind, extra = f["path"], f.get("scanner", ""), ""
        if Path(path).is_absolute() and Path(path).is_relative_to(repo):
            path = str(Path(path).relative_to(repo))
        # A secret's line is never hashed: the ledger must not hold anything a secret can be checked against.
        raw = None if kind == "secrets" else data(path)
        if kind in ("sast", "agent") and raw is not None and f.get("line"):
            lines = raw.decode("utf-8", "replace").splitlines()[f["line"] - 1:f.get("end_line") or f["line"]]
            extra = short("\n".join(x.strip() for x in lines))
        elif kind == "sca":
            extra = (f.get("package") or {}).get("name", "")
        status = a["disposition"]
        note = a.get("dismissal_reason") or ("" if kind == "secrets" else a.get("evidence"))
        items.append({"id": f["id"], "key": (f.get("engine", kind), f["rule"], path, extra), "line": f.get("line") or 0,
                      "status": status, "basis": "test" if a.get("proof") else "assumed" if status == "needs-review" else "code",
                      "sha": hashlib.sha1(raw).hexdigest()[:12] if raw is not None else "", "note": note})
    return items


def dast_items(doc, assessments):
    """Candidates of local-dast: ZAP alerts and failed cases, keyed by rule and case labels only."""
    items = {f["id"]: {"id": f["id"], "key": ("zap", f"zap:{f['alert_ref']}", "", ",".join(f["observed_cases"]))}
             for f in doc["findings"]}
    items.update({c["id"]: {"id": c["id"], "key": ("case", f"case:{c['id']}", "", "")}
                  for c in doc["cases"] if c["state"] == "assertion-failed"})
    for item in items.values():
        item.update(line=0, status="unreviewed", basis="", sha="", note="")
    if not isinstance(assessments, list):
        sys.exit("assessments must be a list of {id, disposition, basis, note}")
    for a in assessments:
        if not isinstance(a, dict) or a.get("id") not in items:
            sys.exit(f"assessment for an ID that is not a candidate of this report: {str(a)[:60]}")
        if a.get("disposition") == "unreviewed":
            continue
        if a.get("disposition") not in STATUSES or a.get("basis") not in BASES[:3] or not str(a.get("note") or "").strip():
            sys.exit(f"{a['id']}: needs a disposition in {STATUSES}, a basis in {BASES[:3]} and a note")
        items[a["id"]].update(status=a["disposition"], basis=a["basis"], note=a["note"])
    return list(items.values())


def record(args):
    repo = Path(args.repo).resolve()
    if not repo.is_dir():
        sys.exit(f"{repo} is not a directory")
    doc = json.loads(Path(args.file).read_text())
    if isinstance(doc.get("scan"), dict):
        skill, scan = "local-security-review", doc["scan"]
        if Path(scan["target"]).resolve() != repo:
            sys.exit(f"{args.file} is a review of {scan['target']}, not of {repo}")
        if scan.get("scope") == "commit-snapshot":
            print("not recorded: the ledger describes the working tree, and this review read a commit snapshot")
            return 0
        full = scan.get("scope") in ("working-tree", "release") and scan.get("status") != "incomplete"
        items = review_items(repo, doc)
    elif "cases" in doc and "zap" in doc:
        if not args.assessments:
            sys.exit("a local-dast report needs --assessments")
        # ponytail: local-dast rows are never pruned, because a run sends only the cases of its plan.
        # Ceiling: a row outlives a case that was removed. Way up: a `drop <fingerprint>` command.
        skill, full = "local-dast", False
        items = dast_items(doc, json.loads(Path(args.assessments).read_text()))
    else:
        sys.exit(f"{args.file} is neither a review.json of render_review.py nor a report.json of dast.py")

    path = repo / "security/findings.csv"
    rows = load(path)
    mine = {r["fingerprint"]: r for r in rows if r["skill"] == skill}
    now, seen, labels = stamp(repo), set(), []
    occurrence, counts = collections.Counter(), collections.Counter()
    for item in sorted(items, key=lambda i: (i["key"], i["line"], i["id"])):
        occurrence[item["key"]] += 1
        fp = short("\x1f".join((*item["key"], str(occurrence[item["key"]]))))
        old = mine.get(fp)
        seen.add(fp)
        if item["status"] == "unreviewed":
            counts["unreviewed, not recorded"] += 1
            if old:
                old["last_seen"] = now
            continue
        new = {"fingerprint": fp, "skill": skill, "rule": item["key"][1], "path": item["key"][2], "status": item["status"],
               "basis": item["basis"], "sha": item["sha"], "first_seen": now, "last_seen": now, "note": one_line(item["note"])}
        if not old:
            label = "new"
            rows.append(new)
            mine[fp] = new
        elif old["basis"] == "user":
            label = f"decided by user: {old['status']}" + ("" if old["status"] == new["status"] else f"; this run says {new['status']}")
            old["last_seen"] = now
        else:
            label = (f"seen before: {old['status']}, basis {old['basis']}, since {old['first_seen']}" if old["status"] == new["status"]
                     else f"changed: was {old['status']} (basis {old['basis']}), now {new['status']}")
            if old["sha"] and new["sha"] and old["sha"] != new["sha"]:
                label += "; file changed since that decision"
            old.update(new, first_seen=old["first_seen"])
        counts[label.split(":")[0]] += 1
        labels.append(f"{item['id']} {fp} {label}")

    def gone(r):
        missing = bool(r["path"]) and not (repo / r["path"]).exists()
        return r["skill"] == skill and r["fingerprint"] not in seen and (full or missing)

    kept = [r for r in rows if not gone(r)]
    if kept or path.exists():
        save(path, kept)
        ensure_ignored(repo, "security/findings.csv")
    print(f"{path}: {len(kept)} rows; this run: " + (", ".join(f"{n} {k}" for k, n in counts.items()) or "no candidates")
          + f"; {len(rows) - len(kept)} pruned")
    print("\n".join(labels))
    return 0


def decide(args):
    repo = Path(args.repo).resolve()
    path = repo / "security/findings.csv"
    rows = load(path)
    hit = [r for r in rows if r["fingerprint"] == args.fingerprint]
    if not hit:
        sys.exit(f"{path} has no row {args.fingerprint}; record the finding first")
    for r in hit:
        r.update(status=args.status, basis="user", note=one_line(args.note), last_seen=stamp(repo))
    save(path, rows)
    print(f"{args.fingerprint}: {args.status}, decided by user")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("record")
    p.add_argument("repo")
    p.add_argument("file")
    p.add_argument("--assessments")
    p = sub.add_parser("decide")
    p.add_argument("repo")
    p.add_argument("fingerprint")
    p.add_argument("--status", required=True, choices=STATUSES)
    p.add_argument("--note", required=True)
    args = ap.parse_args(argv)
    return {"record": record, "decide": decide}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
