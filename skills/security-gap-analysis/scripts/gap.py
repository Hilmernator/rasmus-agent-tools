"""Keep a repository's security/ folder consistent: requirements, file coverage and the boundary inventory.

  gap.py init      REPO --select asvs:2 [--select aisvs:2] [--select masvs]
  gap.py show      REPO [PREFIX ...] [--status S]
  gap.py set       REPO PREFIX ... --status S [--evidence "path:line; path:line-line"] [--notes TEXT]
  gap.py files     REPO [--list STATUS] [--mark PATH ... --status S [--notes TEXT]]
  gap.py inventory REPO [--list STATUS] [--mark --kind K --path P --lines A-B --status S [--notes TEXT]]
  gap.py check     REPO [--complete]

A PREFIX is standard:id-prefix, for example asvs:V6, asvs:V6.2.1, aisvs:9, aisvs-ac:AC.4, masvs:MASVS-STORAGE.
A PATH is a file or a directory; "." is the whole repository.
"""
import argparse
import csv
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

CATALOGS = Path(__file__).resolve().parents[1] / "catalogs"
FIELDS = ["standard", "id", "level", "status", "evidence", "notes", "assessed"]
STATUSES = ["unassessed", "met", "partial", "missing", "not-applicable", "unverifiable", "risk-accepted"]
NEEDS_EVIDENCE = {"met", "partial"}
NEEDS_NOTES = set(STATUSES) - {"unassessed", "met"}
EVIDENCE = re.compile(r"^(?P<path>[^:]+):(?P<start>\d+)(?:-(?P<end>\d+))?$")

FILE_FIELDS = ["path", "lines", "status", "sha", "notes"]
FILE_STATUSES = ["unread", "read", "skimmed", "skipped"]
INV_FIELDS = ["kind", "path", "line", "text", "status", "notes"]
INV_STATUSES = ["unreviewed", "boundary", "internal", "test"]
SKIP_DIRS = {".git", "node_modules", "target", "dist", "build", ".venv", "venv", "__pycache__", "vendor", ".next"}
CODE = re.compile(r"\.(m|c)?(t|j)sx?$|\.(py|rs|go|java|kt|kts|rb|php|cs|swift|m|mm|c|cc|cpp|h|hpp|html?|vue|svelte|astro"
                  r"|sh|ps1|ya?ml|toml|tf|xml|plist|entitlements|gradle)$|(^|/)Dockerfile[^/]*$|(^|/)package\.json$")
# Where input from outside can enter, or where code acts on something outside. Recall matters more than
# precision: every hit is either named in the profile or marked internal or test with a reason.
SIGNALS = [
    ("listen", r"TcpListener|UdpSocket::bind|UnixListener|\.listen\(|createServer\(|HTTPServer\(|socketserver\."
               r"|uvicorn\.run|\bapp\.run\((\)|\s*(host|port|debug)=)|axum::serve|hyper::Server|warp::serve|ListenAndServe|^\s*EXPOSE\s"
               r"|containerPort|bind\(\s*\(?\s*[\"'](0\.0\.0\.0|127\.0\.0\.1|localhost|::)"),
    ("route", r"\b(app|router|server|fastify|api|hono)\.(get|post|put|patch|delete|all|route|use)\(\s*[\"'`]"
              r"|@\w+\.(get|post|put|patch|delete|route|api_route|websocket)\(|#\[(get|post|put|patch|delete|route)\("
              r"|\.route\(\s*\"|HandleFunc\(|\(\s*\"(GET|POST|PUT|PATCH|DELETE)\"\s*,|\bpath\(\s*[\"']"
              r"|\bdef\s+\w*handler\(\s*event\b|exports\.handler\s*=|export\s+const\s+handler\b"
              r"|^\s*Type:\s*(Http)?Api\s*$|^\s*Type:\s*(SQS|SNS|S3|Kinesis|DynamoDB|Schedule|EventBridgeRule)\s*$"
              r"|AWS::(ApiGateway|ApiGatewayV2|AppSync|Lambda::Url)\b"
              r"|export\s+(async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\b|^\s*[\"']use server[\"']"
              r"|\b(public|protected)Procedure\b|@(Get|Post|Put|Patch|Delete|Request)Mapping\("),
    ("process", r"Command::new\(|\bsubprocess\.|os\.system\(|os\.popen\(|child_process|\bexecFile(Sync)?\(|(?<!::)\bspawn(Sync)?\("
                r"|\bexecSync\(|Runtime\.getRuntime\(\)\.exec|ProcessBuilder|NSTask|Process\(\)"),
    ("network-out", r"https?://[a-z0-9-]+(\.[a-z0-9-]+)+|reqwest::|ureq::|\bfetch\(|axios|requests\.(get|post|put|delete|request)"
                    r"|urllib\.request|httpx\.|http\.Client|URLSession|aiohttp"),
    ("deserialize", r"pickle\.loads?|torch\.load|yaml\.load\(|marshal\.loads|jsonpickle|ObjectInputStream|BinaryFormatter"
                    r"|\bunserialize\(|joblib\.load|from_pretrained|\.safetensors|NSKeyedUnarchiver"),
    ("html-sink", r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|dangerouslySetInnerHTML|v-html|\|\s*safe\b"
                  r"|mark_safe|Markup\("),
    ("eval", r"\beval\(|new Function\(|\bexec\(|vm\.run|setTimeout\(\s*[\"'`]"),
    ("sql", r"\b(SELECT\s.+\sFROM|INSERT\s+INTO|UPDATE\s.+\sSET|DELETE\s+FROM)\b|\.execute\(|\.raw\(|sqlx::query|rusqlite"),
    ("ai", r"anthropic|openai|langchain|llama_index|ollama|generativeai|bedrock|BedrockRuntime|\bmcp\b|McpServer"
           r"|\"claude\"|\"codex\"|from transformers|import transformers|import torch"),
    ("auth", r"jwt\.|jsonwebtoken|jose\b|passport\.|Auth0|Cognito|OAuth|oidc|openid|[Aa]uthorization|Bearer|getServerSession"
             r"|NextAuth|msal|api[_-]?key|password|Set-Cookie|session\["),
    ("headers", r"Access-Control-Allow|Content-Security-Policy|\bcors\(|X-Frame-Options|Strict-Transport-Security"),
    ("env", r"env::var|process\.env|os\.environ|getenv\(|ENV\["),
    ("ipc", r"UnixStream|NSXPC|postMessage|addEventListener\(\s*[\"']message|WKWebView|ipcMain|ipcRenderer|contextBridge"
            r"|registerProtocol|deep.?link|tauri::command|android:exported=\"true\"|CFBundleURLSchemes|<intent-filter"),
    ("weak-crypto", r"\b(md5|MD5|sha1|SHA1|Md5|Sha1)\b|\bECB\b|Math\.random\(|\brandom\.random\("
                    r"|verify\s*=\s*False|danger_accept_invalid_(certs|hostnames)|rejectUnauthorized:\s*false"
                    r"|InsecureSkipVerify:\s*true|NODE_TLS_REJECT_UNAUTHORIZED|NSAllowsArbitraryLoads"
                    r"|usesCleartextTraffic=\"true\""),
    ("cli", r"\benv::args(_os)?\(|\bclap::|derive\([^)]*\bParser\b|import argparse|argparse\.|sys\.argv|process\.argv|\bclick\.(command|group)"
            r"|\btyper\.|io::stdin\(|sys\.stdin|process\.stdin"),
    ("upload", r"\bmultipart\b|MultipartFile|\bmulter\b|UploadFile|formidable|busboy|\.extractall\(|tarfile\.open|zipfile\.ZipFile|ZipArchive"
               r"|ZipInputStream|tar::Archive|\btar\s+-?x|\bunzip\b|[Cc]ontent-[Dd]isposition"),
    ("store", r"localStorage|sessionStorage|document\.cookie|indexedDB|SecItem(Add|CopyMatching|Update)|\bKeychain"
              r"|SharedPreferences|UserDefaults|\bs3\.|put_object|PutObjectCommand|put_item|\bredis\b|mongodb|dynamodb(?!:)|DynamoDB"),
    ("pipeline", r"pull_request_target|workflow_run|\$\{\{\s*github\.(event|head_ref)|\$\{\{\s*secrets\.|permissions:\s*write-all"
                 r"|\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(ba|z)?sh\b|\b(npm|cargo|twine|gem)\s+(publish|upload|push)\b"
                 r"|docker\s+push|\"(pre|post)?install\"\s*:|uses:\s*[\w./-]+@(?![0-9a-f]{40}\b)"),
    ("ffi", r"\bunsafe\s*(\{|fn\b|impl\b|extern\b)|extern\s+\"C\"|#\[no_mangle\]|\bctypes\.|\bdlopen\(|System\.loadLibrary"),
]
SIGNAL_RES = [(kind, re.compile(p, re.I if kind in {"sql", "auth"} else 0)) for kind, p in SIGNALS]


def catalogs():
    return {p.stem: {r["id"]: r for r in json.loads(p.read_text())["requirements"]} for p in CATALOGS.glob("*.json")}


def csv_path(repo):
    return Path(repo) / "security" / "requirements.csv"


def load(repo):
    path = csv_path(repo)
    if not path.exists():
        sys.exit(f"{path} does not exist; run init first")
    with path.open(newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames != FIELDS:
            sys.exit(f"{path}: header must be {','.join(FIELDS)}")
        return list(reader)


def save(repo, rows):
    path = csv_path(repo)
    path.parent.mkdir(exist_ok=True)
    order = {k: i for i, k in enumerate(sorted(catalogs()))}
    rows.sort(key=lambda r: (order.get(r["standard"], 99), natural(r["id"])))
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, FIELDS, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def natural(s):
    return [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", s)]


def matches(prefix, row):
    standard, _, p = prefix.partition(":")
    i = row["id"]
    return row["standard"] == standard and (not p or i == p or i.startswith(p + ".") or i.startswith(p + "-"))


def revision(repo):
    try:
        sha = subprocess.run(["git", "-C", str(repo), "rev-parse", "--short", "HEAD"], capture_output=True,
                             text=True, check=True).stdout.strip()
        # The security folder being written is not a change to the code being judged.
        dirty = subprocess.run(["git", "-C", str(repo), "status", "--porcelain", "--", ".", ":!security"], capture_output=True,
                               text=True, check=True).stdout.strip()
        return sha + ("+dirty" if dirty else "")
    except (OSError, subprocess.CalledProcessError):
        return datetime.date.today().isoformat()


def init(args):
    cats = catalogs()
    path = csv_path(args.repo)
    rows = load(args.repo) if path.exists() else []
    have = {(r["standard"], r["id"]) for r in rows}
    added = 0
    for sel in args.select:
        standard, _, level = sel.partition(":")
        if standard not in cats:
            sys.exit(f"unknown standard {standard}; known: {', '.join(sorted(cats))}")
        for req in cats[standard].values():
            if req["level"] <= int(level or 3) and (standard, req["id"]) not in have:
                rows.append({"standard": standard, "id": req["id"], "level": str(req["level"]),
                             "status": "unassessed", "evidence": "", "notes": "", "assessed": ""})
                added += 1
    save(args.repo, rows)
    print(f"{path}: {added} requirements added, {len(rows)} in total")


def show(args):
    cats = catalogs()
    for r in load(args.repo):
        if (not args.prefix or any(matches(p, r) for p in args.prefix)) and (not args.status or r["status"] in args.status):
            req = cats.get(r["standard"], {}).get(r["id"], {})
            print(f'{r["standard"]}:{r["id"]}\tL{r["level"]}\t{r["status"]}\t{req.get("section", "?")}\n'
                  f'  {req.get("text", "NOT IN CATALOG")}')
            for k in ("evidence", "notes"):
                if r[k]:
                    print(f"  {k}: {r[k]}")


def set_(args):
    rows = load(args.repo)
    hit = [r for r in rows if any(matches(p, r) for p in args.prefix)]
    if not hit:
        sys.exit("no row matches " + " ".join(args.prefix))
    rev = revision(args.repo)
    for r in hit:
        r["status"] = args.status
        if args.evidence is not None:
            r["evidence"] = args.evidence
        if args.notes is not None:
            r["notes"] = args.notes
        r["assessed"] = rev
    save(args.repo, rows)
    errors = [e for r in hit for e in problems(Path(args.repo), r, catalogs(), accepted_ids(args.repo))]
    print(f"{len(hit)} rows set to {args.status}")
    for e in errors:
        print("  problem: " + e)
    return 1 if errors else 0


def accepted_ids(repo):
    p = Path(repo) / "security" / "accepted-risks.md"
    return p.read_text() if p.exists() else ""


def evidence_items(row):
    return [e.strip() for e in row["evidence"].split(";") if e.strip()]


def problems(repo, r, cats, accepted):
    key = f'{r["standard"]}:{r["id"]}'
    out = []
    if r["id"] not in cats.get(r["standard"], {}):
        out.append(f"{key}: not in the bundled catalog")
    if r["status"] not in STATUSES:
        return out + [f'{key}: status "{r["status"]}" is not one of {", ".join(STATUSES)}']
    if r["status"] in NEEDS_EVIDENCE and not evidence_items(r):
        out.append(f"{key}: {r['status']} needs evidence (path:line)")
    if r["status"] in NEEDS_NOTES and not r["notes"].strip():
        out.append(f"{key}: {r['status']} needs notes saying why")
    if r["status"] == "risk-accepted" and key not in accepted:
        out.append(f"{key}: risk-accepted but not named in security/accepted-risks.md")
    for item in evidence_items(r):
        m = EVIDENCE.match(item)
        if not m:
            out.append(f'{key}: evidence "{item}" is not path:line or path:start-end')
            continue
        f = (repo / m["path"]).resolve()
        if not f.is_relative_to(repo.resolve()) or not f.is_file():
            out.append(f'{key}: evidence file {m["path"]} does not exist in the repository')
            continue
        lines = len(f.read_bytes().splitlines())
        start, end = int(m["start"]), int(m["end"] or m["start"])
        if not 1 <= start <= end <= lines:
            out.append(f"{key}: evidence {item} is outside the file ({lines} lines)")
    return out


def read_csv(path, fields):
    if not path.exists():
        return None
    with path.open(newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames != fields:
            sys.exit(f"{path}: header must be {','.join(fields)}")
        return list(reader)


def write_csv(path, fields, rows):
    path.parent.mkdir(exist_ok=True)
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fields, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def repo_files(repo):
    """Every file a review should account for: Git's tracked and unignored files, else a walk. Not security/."""
    try:
        out = subprocess.run(["git", "-C", str(repo), "ls-files", "-z", "-co", "--exclude-standard"],
                             capture_output=True, check=True).stdout.decode()
        paths = [p for p in out.split("\0") if p]
    except (OSError, subprocess.CalledProcessError):
        paths = []
        for root, dirs, names in os.walk(repo):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            paths += [os.path.relpath(os.path.join(root, n), repo) for n in names]
    return sorted({p for p in paths if not p.startswith("security/")
                   and (repo / p).is_file() and not (repo / p).is_symlink()})


def content(repo, path):
    """The file's bytes and whether it is text."""
    data = (repo / path).read_bytes()
    return data, b"\0" not in data[:8192]


def digest(data):
    return hashlib.sha1(data).hexdigest()[:12]


def under(path, prefixes):
    return any(p in (".", "") or path == p.rstrip("/") or path.startswith(p.rstrip("/") + "/") for p in prefixes)


def files_path(repo):
    return repo / "security" / "files.csv"


def sync_files(repo):
    """files.csv with one row per current file; marks and notes kept, gone files dropped."""
    old = {r["path"]: r for r in read_csv(files_path(repo), FILE_FIELDS) or []}
    rows = []
    for p in repo_files(repo):
        data, text = content(repo, p)
        r = old.get(p) or {"path": p, "status": "unread", "sha": "", "notes": ""}
        r["lines"] = str(len(data.splitlines())) if text else "0"
        if not text and r["status"] == "unread":
            r.update(status="skipped", sha=digest(data), notes="binary")
        rows.append(r)
    write_csv(files_path(repo), FILE_FIELDS, rows)
    return rows


def changed_files(repo, rows):
    return {r["path"] for r in rows if r["status"] != "unread" and r["sha"] != digest(content(repo, r["path"])[0])}


def files(args):
    repo = Path(args.repo)
    rows = sync_files(repo)
    if args.mark:
        if not args.status:
            sys.exit("--mark needs --status")
        if args.status == "skipped" and not args.notes:
            sys.exit("skipped needs --notes saying why")
        hit = [r for r in rows if under(r["path"], args.mark)]
        if not hit:
            sys.exit("no file matches " + " ".join(args.mark))
        for r in hit:
            r.update(status=args.status, sha=digest(content(repo, r["path"])[0]) if args.status != "unread" else "",
                     notes=args.notes if args.notes is not None else r["notes"])
        write_csv(files_path(repo), FILE_FIELDS, rows)
        print(f"{len(hit)} files marked {args.status}")
    changed = changed_files(repo, rows)
    if args.list:
        for r in rows:
            if r["status"] == args.list or (args.list == "changed" and r["path"] in changed):
                print(f'{r["path"]}\t{r["lines"]} lines\t{r["status"]}\t{r["notes"]}')
        return 0
    print(coverage_line(rows))
    by_dir = {}
    for r in rows:
        if r["status"] == "unread":
            d = os.path.dirname(r["path"]) or "."
            n, lines = by_dir.get(d, (0, 0))
            by_dir[d] = (n + 1, lines + int(r["lines"]))
    for d, (n, lines) in sorted(by_dir.items(), key=lambda kv: -kv[1][1]):
        print(f"  unread {d}/: {n} files, {lines} lines")
    for p in sorted(changed):
        print(f"  changed since marked: {p}")
    return 0


def coverage_line(rows):
    total = sum(int(r["lines"]) for r in rows) or 1
    parts = []
    for s in FILE_STATUSES:
        chosen = [r for r in rows if r["status"] == s]
        if chosen:
            lines = sum(int(r["lines"]) for r in chosen)
            parts.append(f"{s} {len(chosen)} ({lines} lines, {100 * lines // total} %)")
    return f"files: {len(rows)}; " + ", ".join(parts)


def inventory_path(repo):
    return repo / "security" / "inventory.csv"


def scan(repo):
    """Every signal line in the repository's code, keyed so that a mark survives the line moving."""
    hits, seen = [], {}
    for p in repo_files(repo):
        if not CODE.search(p):
            continue
        data, text = content(repo, p)
        if not text or len(data) > 2 << 20:
            continue
        for n, line in enumerate(data.decode("utf-8", "replace").splitlines(), 1):
            for kind, rx in SIGNAL_RES:
                if rx.search(line):
                    t = line.strip()[:160]
                    k = (kind, p, t)
                    seen[k] = seen.get(k, 0) + 1
                    hits.append({"kind": kind, "path": p, "line": str(n), "text": t, "occurrence": seen[k]})
    return hits


def inv_key(r, occurrence):
    return (r["kind"], r["path"], r["text"], occurrence)


def keyed(rows):
    out, seen = {}, {}
    for r in rows:
        k = (r["kind"], r["path"], r["text"])
        seen[k] = seen.get(k, 0) + 1
        out[k + (seen[k],)] = r
    return out


def sync_inventory(repo):
    old = keyed(read_csv(inventory_path(repo), INV_FIELDS) or [])
    rows = []
    for h in scan(repo):
        prev = old.get(inv_key(h, h["occurrence"]))
        rows.append({"kind": h["kind"], "path": h["path"], "line": h["line"], "text": h["text"],
                     "status": prev["status"] if prev else "unreviewed", "notes": prev["notes"] if prev else ""})
    write_csv(inventory_path(repo), INV_FIELDS, rows)
    return rows


def inventory(args):
    repo = Path(args.repo)
    rows = sync_inventory(repo)
    if args.mark:
        if not args.status or not (args.kind or args.path):
            sys.exit("--mark needs --status and at least one of --kind and --path")
        if args.status in {"internal", "test"} and not args.notes:
            sys.exit(f"{args.status} needs --notes saying why")
        lo, _, hi = (args.lines or "").partition("-")
        hit = [r for r in rows if (not args.kind or r["kind"] in args.kind) and (not args.path or under(r["path"], args.path))
               and (not args.lines or int(lo) <= int(r["line"]) <= int(hi or lo))]
        if not hit:
            sys.exit("no inventory line matches")
        for r in hit:
            r["status"] = args.status
            if args.notes is not None:
                r["notes"] = args.notes
        write_csv(inventory_path(repo), INV_FIELDS, rows)
        print(f"{len(hit)} inventory lines marked {args.status}")
    want = args.list or "unreviewed"
    tally = {}
    for r in rows:
        tally.setdefault(r["kind"], {}).setdefault(r["status"], 0)
        tally[r["kind"]][r["status"]] += 1
    for kind, counts in sorted(tally.items()):
        print(f"{kind:12} " + "  ".join(f"{s} {counts[s]}" for s in INV_STATUSES if s in counts))
    chosen = [r for r in rows if r["status"] == want]
    for r in chosen[:300]:
        print(f'  {r["kind"]:12} {r["path"]}:{r["line"]}  {r["text"]}' + (f'  [{r["notes"]}]' if r["notes"] else ""))
    if len(chosen) > 300:
        print(f"  ... {len(chosen) - 300} more; narrow with --mark by --path or --kind")
    return 0


def coverage_problems(repo, reqs):
    """Whether the folder accounts for every file and every boundary signal, and evidence rests on read files."""
    out = []
    frows = read_csv(files_path(repo), FILE_FIELDS)
    irows = read_csv(inventory_path(repo), INV_FIELDS)
    if frows is None or irows is None:
        return ["files.csv or inventory.csv is missing; run gap.py files and gap.py inventory"], None
    current = repo_files(repo)
    if sorted(r["path"] for r in frows) != current:
        out.append("files.csv does not list the current files; run gap.py files")
    if set(keyed(irows)) != {inv_key(h, h["occurrence"]) for h in scan(repo)}:
        out.append("inventory.csv does not match the code; run gap.py inventory")
    status = {r["path"]: r["status"] for r in frows}
    unread = [r for r in frows if r["status"] == "unread"]
    if unread:
        out.append(f"{len(unread)} files are unread ({sum(int(r['lines']) for r in unread)} lines); "
                   "read them or mark them skimmed or skipped with a reason (gap.py files --list unread)")
    changed = changed_files(repo, [r for r in frows if (repo / r["path"]).is_file()])
    for p in sorted(changed):
        citing = [f'{r["standard"]}:{r["id"]}' for r in reqs
                  if any(EVIDENCE.match(e) and EVIDENCE.match(e)["path"] == p for e in evidence_items(r))]
        out.append(f"{p} changed since it was marked; reread it, mark it again and reassess "
                   + (", ".join(citing) if citing else "the rows it bears on"))
    for r in frows:
        if r["status"] not in FILE_STATUSES:
            out.append(f'{r["path"]}: status "{r["status"]}" is not one of {", ".join(FILE_STATUSES)}')
        elif r["status"] == "skipped" and not r["notes"].strip():
            out.append(f'{r["path"]}: skipped needs notes saying why')
    profile = repo / "security" / "profile.md"
    named = profile.read_text() if profile.exists() else ""
    pending = [r for r in irows if r["status"] == "unreviewed"]
    if pending:
        out.append(f"{len(pending)} inventory lines are unreviewed (gap.py inventory)")
    for r in irows:
        where = f'{r["kind"]} {r["path"]}:{r["line"]}'
        if r["status"] not in INV_STATUSES:
            out.append(f'{where}: status "{r["status"]}" is not one of {", ".join(INV_STATUSES)}')
        elif r["status"] in {"internal", "test"} and not r["notes"].strip():
            out.append(f"{where}: {r['status']} needs notes saying why")
        elif r["status"] == "boundary" and r["path"] not in named:
            out.append(f"{where}: marked boundary, but profile.md does not name {r['path']}")
    for r in reqs:
        for e in evidence_items(r):
            m = EVIDENCE.match(e)
            if m and status.get(m["path"]) not in {"read", "skimmed", None}:
                out.append(f'{r["standard"]}:{r["id"]}: evidence {m["path"]} is {status[m["path"]]}, not read')
    return out, (frows, irows)


def check(args):
    repo = Path(args.repo)
    rows, cats, accepted = load(repo), catalogs(), accepted_ids(repo)
    errors = []
    seen = set()
    for r in rows:
        key = (r["standard"], r["id"])
        if key in seen:
            errors.append(f"{r['standard']}:{r['id']}: listed twice")
        seen.add(key)
        errors += problems(repo, r, cats, accepted)
    tally = {}
    for r in rows:
        chapter = cats.get(r["standard"], {}).get(r["id"], {}).get("chapter", "?")
        tally.setdefault((r["standard"], chapter), {}).setdefault(r["status"], 0)
        tally[(r["standard"], chapter)][r["status"]] += 1
    for (standard, chapter), counts in sorted(tally.items(), key=lambda kv: (kv[0][0], natural(kv[0][1]))):
        print(f"{standard:6} {chapter[:48]:48} " + "  ".join(f"{s} {counts[s]}" for s in STATUSES if s in counts))
    total = {s: sum(r["status"] == s for r in rows) for s in STATUSES}
    print("total  " + "  ".join(f"{s} {n}" for s, n in total.items() if n))
    found, ledgers = coverage_problems(repo, rows)
    errors += found
    if args.complete and total["unassessed"]:
        errors.append(f'{total["unassessed"]} requirements are unassessed')
    if ledgers:
        frows, irows = ledgers
        print(coverage_line(frows))
        print("inventory: " + ", ".join(f"{s} {sum(r['status'] == s for r in irows)}" for s in INV_STATUSES))
    for e in errors:
        print("problem: " + e)
    return 1 if errors else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init")
    p.add_argument("repo")
    p.add_argument("--select", action="append", required=True, help="standard[:max level]")
    p = sub.add_parser("show")
    p.add_argument("repo")
    p.add_argument("prefix", nargs="*")
    p.add_argument("--status", action="append", choices=STATUSES)
    p = sub.add_parser("set")
    p.add_argument("repo")
    p.add_argument("prefix", nargs="+")
    p.add_argument("--status", required=True, choices=STATUSES)
    p.add_argument("--evidence")
    p.add_argument("--notes")
    p = sub.add_parser("files")
    p.add_argument("repo")
    p.add_argument("--list", choices=FILE_STATUSES + ["changed"])
    p.add_argument("--mark", nargs="+", metavar="PATH")
    p.add_argument("--status", choices=FILE_STATUSES)
    p.add_argument("--notes")
    p = sub.add_parser("inventory")
    p.add_argument("repo")
    p.add_argument("--list", choices=INV_STATUSES)
    p.add_argument("--mark", action="store_true")
    p.add_argument("--kind", action="append", choices=[k for k, _ in SIGNALS])
    p.add_argument("--path", action="append")
    p.add_argument("--lines", help="A-B, with --path")
    p.add_argument("--status", choices=INV_STATUSES)
    p.add_argument("--notes")
    p = sub.add_parser("check")
    p.add_argument("repo")
    p.add_argument("--complete", action="store_true", help="also fail while a requirement is unassessed")
    args = ap.parse_args(argv)
    return {"init": init, "show": show, "set": set_, "files": files, "inventory": inventory,
            "check": check}[args.cmd](args) or 0


if __name__ == "__main__":
    sys.exit(main())
