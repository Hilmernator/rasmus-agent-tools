# Shared SAST procedure

Use Semgrep, locked Bandit/ESLint and checksum-pinned Trivy with the runner at
`../scripts/sast.py` relative to this reference directory. The invoking skill
selects the scope; use the current repository root unless a target was supplied:

```sh
python3 <runner> <repository-root>
python3 <runner> <repository-root> --commit <sha-or-local-ref>
python3 <runner> <repository-root> --diff
```

IaC uses the same SAST IDs, assessment/group renderer and combined security flow.
Read [IaC scope and licensing](iac.md) for infrastructure scans, CDK templates,
Terraform modules, additional paths or Trivy setup.

## Scope semantics

Run the invoking skill's mode immediately; no scope-selection prompt is needed.
Commit mode defaults to HEAD unless the user provides another SHA/ref.
Full scans use working files including uncommitted changes and
eligible untracked files. Commit scans use an isolated local clone of the exact
commit and Semgrep's baseline comparison against its first parent. They report
new Semgrep findings according to its comparison. Bandit and ESLint report every
finding in the changed files, including pre-existing issues; do not label all of
these as introduced by the commit. Trivy scans full eligible IaC context when IaC
candidates change; its findings can also predate the change. Root commits get a full snapshot scan. Merge commits use the
first parent and disclose that choice. Missing/shallow history is incomplete;
fetching is a separate user-approved action. These are focused SAST diff semantics.
The combined `local-security-review commit` instead runs every scanner on a full
selected snapshot, including pre-existing findings; it is not baseline filtering.

Diff mode compares a temporary snapshot of current working files to HEAD,
including eligible untracked files. It captures the combined working-tree state,
not a separate review of the staged index: an unstaged edit can override staged
content. Never describe it as a staged-only pre-commit gate. The user's index,
branch and files stay untouched; the synthetic commit exists only in the
disposable clone. A clean tree produces zero new findings. A repository without
HEAD, unresolved conflicts, or sparse checkout is incomplete, not an automatic
full-repo fallback. Surface excluded submodules/directories from the report.

## Run and inspect

Read [licensing.md](licensing.md) before setup, rule changes, or external use.
The default Semgrep configuration is the locally installed security-audit rule snapshot at
`${XDG_CACHE_HOME:-~/.cache}/rai-security/semgrep/security-audit.yaml`.
Its checksum must match the bundled license policy; changing cached rules requires
review. `--semgrep-config <file-or-directory> --custom-rules-license-reviewed`
overrides it only after the user's custom rules have been license-reviewed.
Do not acknowledge this flag on the user's behalf without evidence of that review.
Inspect the target's languages
and rule configuration; disclose unsupported languages rather than claiming
complete language coverage. If scanner/toolchain/rule prerequisites are missing,
name what is missing and follow the bundled setup workflow, following
[setup-sast](setup-sast.md) only after installation is authorized.
Keep the scan incomplete until prerequisites are resolved; a scan request does
not silently authorize installation. Continue reviewing any available findings.
The suite never downloads rules or dependencies on scan. Metrics and version checks remain disabled;
no findings upload, hosted engine, autofix or credential validation is requested.
AI review uses the current Codex provider, not an offline model.

Exit 1 means findings, not failure; exit 2 means incomplete. Read the entire
projected `report.json`, in chunks if necessary. It retains every returned
scanner result with a scan-local ID, engine, location, original severity, and metadata;
source snippets/messages are deliberately omitted to avoid leaking matched data.
It also records per-engine status, rule source/checksum, errors, scanned paths and skipped paths.
Inline `nosemgrep`, `nosec` and ESLint suppressions are disabled. Bandit runs all
built-in tests at all confidence/severity levels. ESLint enables all bundled
security-plugin rules with a TS/TSX parser, without type-aware project analysis.
Neither new scanner loads target-owned config or runs target dependency scripts.
Bandit/ESLint include tests; exclude dependency/cache directories, symlinks and
files over 1 MiB. An engine with no eligible files is `not-applicable`; missing
tools for applicable files and parser errors are `incomplete`, never a pass.
File ignores still apply: inspect
`.semgrepignore`, `.gitignore`, skipped files and any uninitialized submodules.
On macOS a sandboxed Semgrep may fail to access the certificate store even
offline; request normal tool escalation rather than disabling TLS verification.

Read the projected report and apply
[shared triage](triage.md), especially SAST.
For commit scans inspect source and callers at `report.commit`, using read-only
Git object reads, not today's working files. For full and diff scans verify that source
has not changed since the scan; rerun affected evidence if it has. Read matching
rule definitions from the recorded local configuration. Assess every finding;
retain uncertain or unfinished work explicitly rather than asserting safety.

## Deliver every finding

Save `assessments.json` as an array next to the report. An uncertain entry can be:

```json
[{"id":"SAST-0001","disposition":"needs-review","confidence":"low","assessed_severity":"unknown","evidence":"app.py:12 reaches eval; input provenance has not yet been established.","recommendation":"Trace callers before deciding on remediation."}]
```

Disposition is `confirmed`, `likely`, `false-positive`, `needs-review`, or
`unreviewed`; assessed severity is `critical`, `high`, `medium`, `low`, `info`, or
`unknown`, independent of scanner severity. Confidence is `high`, `medium`, `low`,
or `unknown`. `confirmed`, `likely` and `false-positive` also require nonempty
`evidence_refs`, e.g. `[{"path":"src/client.py","line":42}]`.
Confirmed/likely assessments require `preconditions`: describe the attacker control,
reachability and unresolved assumptions needed for exploitation, or explicitly
state that none remain after verification. `evidence` describes observed behavior,
not hypothetical capabilities. False positives require high confidence and a
nonempty `dismissal_reason` explaining why the reported risk does not apply.
References and nonempty fields are structural checks, not automated proof that
the evidence is correct. If evidence is insufficient, use `needs-review`.
Older assessments may need these fields added after renewed source inspection;
never invent evidence just to satisfy validation.

Assess whether different scanners describe the same underlying issue using the
grouping criteria in [triage.md](triage.md). Save explicit matches in `groups.json`
(an array, `[]` if no matches), for example:

```json
[
  {
    "title": "Possible SSRF through an unchecked redirect",
    "finding_ids": ["SAST-0001", "SAST-0002"],
    "root_cause": "Both findings concern the same missing redirect destination check in _upstream_request; one redirect-validation fix addresses both.",
    "evidence": "src/client.py:42 is the shared fetch call; src/client.py:35 validates only the initial URL.",
    "preconditions": "Requires attacker control of a redirect on an allowed host; this has not been demonstrated.",
    "recommendation": "Validate every redirect destination before fetching it. Establish legitimate CDN destinations first."
  }
]
```

This example is illustrative, not evidence about the scanned repository. Every
explicit group needs at least two assessed IDs. An ID can belong to only one
group; omitted IDs remain separate issues. Unreviewed members and conflicting
dispositions are rejected. A confirmed/likely mixture remains `likely`; group
confidence is the lowest member confidence, severity is the highest assessed
severity unless a member's severity is unknown, in which case it remains unknown.
Resolve disagreements from evidence rather than normalizing assessments to force
a group. IDs are local to this report, not stable cross-scan identifiers.

Run the sibling script:

```sh
python3 <scripts-directory>/render_review.py <report.json> <assessments.json> --groups <groups.json>
```

It creates `review.json` and `review.md`, preserves original scanner findings,
rejects unknown/duplicate IDs, and includes missing assessments as `unreviewed`.
Review schema v2 retains `scan`, per-scanner `findings` and `counts`, and adds
`issues` and `summary`. Grouping changes presentation, not scanner data or status.
The CLI prints separate raw and grouped counts. Omitting `--groups` remains valid
and keeps every candidate separate; no location-based deduplication is performed.
Outputs are exclusive-create: use a fresh scan directory for reruns or updates.

In chat, lead with raw scanner count versus actionable issue groups (confirmed or
likely, not all "confirmed vulnerabilities"), unresolved groups and false positives.
Give one recommendation per issue, ordered by assessed severity, and state observed
behavior separately from exploit preconditions. List the group's **every scanner
ID**, engine, location and assessment; a shared rationale can cover equivalent
members without repeating the recommendation. Then account for every dismissed
and unresolved ID with its rationale, including the concrete reason for dismissals.
Link both reports. Check that the union of IDs in the chat equals the report's
scanner ID set; do not compare grouped counts with raw counts. For large results
paginate across messages without silently
truncating. Explicitly identify remaining unreviewed IDs and incomplete coverage.
Do not claim the review complete while an assessed-finding list is still missing.
Review does not authorize fixes or suppressions.

Prerequisites: `semgrep` on PATH and the explicitly installed locked toolchain
from `../scripts/setup_sast.py --install` (requires uv, npm and a compatible Node).
Never silently install tools during a scan. CLI reference:
https://semgrep.dev/docs/cli-reference
