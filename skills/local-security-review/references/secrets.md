# Secret scanning: local detection, metadata-only review

## License, rules and updates

Use **Gitleaks 8.30.1**, whose [scanner and bundled rules use MIT](https://github.com/gitleaks/gitleaks/blob/v8.30.1/LICENSE).
This permissive license permits commercial use subject to retaining its notices.
The installer retains the release archive and LICENSE and verifies extracted
binary/license bytes against the checksum-pinned archive on subsequent checks.
It reads only named regular archive members, never extracts arbitrary paths or
executes installation scripts. No scanner binaries or vendor rules are bundled
in this plugin. Pins come from the [official release](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1).

The local CLI needs no subscription, account, AWS access or credential-validation
service. This does not install the separately licensed/entitled
[Gitleaks GitHub Action](https://github.com/gitleaks/gitleaks-action#license-change).
Archive integrity is not a full audit of linked dependencies or legal
approval; platform software policy still applies. AI-provider terms are separate.

Rules are part of the binary, not a CVE database. Scans stay offline and do not
update tools implicitly. Maintainers review release changes/licenses/checksums,
change the installer pins, rerun setup and tests, then update the plugin.
[Upstream](https://github.com/gitleaks/gitleaks#readme) currently describes Gitleaks as feature-complete with security-patch
releases and points to Betterleaks for new development. Keep that maintenance
boundary visible; migrating engines is a separate evaluation, not an automatic switch.

## Scope and coverage

`scan.py secrets <repo>` scans current files, including uncommitted and untracked
content and git-ignored files such as `.env`. It is not a staged-only gate.
`--history` is a separate scan of all locally available refs, including historical
introductions of secrets since deleted. It does not substitute for working files.
Shallow history returns incomplete; no remote fetch, submodule initialization or
history rewriting. Commit/diff filters remain SAST-only in this low-level runner.
The combined `security.py --commit` scans full files in the chosen snapshot;
it does not filter new secret findings or scan all history. Its `--release` uses
the deep mode below, while `--diff` keeps ordinary secrets on current working files.

The runner uses a trusted config extending bundled rules, an empty external ignore
file, and disables inline `gitleaks:allow`. It strips GITLEAKS environment overrides.
Built-in rule/path allowlists still apply. Symlinks are not followed; `.git`
internals and binary files are not ordinary working-file scan coverage. Decode
depth is 5; archives are not unpacked. There is no extra file-size cap; large trees
can hit the explicit scanner timeout and return incomplete. Gitleaks JSON has no
scanned-file inventory, so coverage is recorded as unknown rather than fabricated.
Describe relevant excluded paths/rules and unresolved coverage in the review.

Raw scanner output is captured privately, full redaction is requested, and raw
logs/reports are removed. Only allowlisted location/rule/commit metadata survives
with `SECRET-` IDs. Errors remain incomplete, retaining available findings. Error
logs, descriptions, matched values, author names/messages and fingerprints are not
projected. Filenames/commit IDs remain repository metadata; avoid secrets in names.

## Deep pre-release mode

Use `scan-secrets-deep` / `scripts/secrets_deep.py <repository-root>` for working
files **plus** Git history and archives in one report. It reuses the same Gitleaks
setup and adds no dependencies or separately licensed scanner. Matching remains
local; this mode additionally downloads Git objects from GitHub with existing
read access. The ordinary `scan-secrets` command remains offline and unchanged.

The runner makes a private `git clone --mirror --no-hardlinks` and fetches
`refs/heads/*`, `refs/tags/*` and available `refs/pull/*` into a separate namespace
there. It preserves local refs and attempts to unshallow only that mirror.
The target's files, index, config and refs are not modified. Only credential-free
github.com HTTPS/SSH origin URLs are accepted; other hosts and GitHub Enterprise
need a separately reviewed extension. HTTPS can use existing `gh` authentication;
SSH uses the existing agent/default keys and known hosts, without custom SSH
config. Global Git helpers, hooks, rewrites, submodules and lazy object fetching
are disabled. Failed/denied fetches and `--offline` remain incomplete for this
release scope, while preserving available local findings. No credential setup,
token validation or uploads are performed.

Historical scanning inventories unique commit trees, then reads their regular
blobs with native `git cat-file --batch`, without checkout, filters or textconv.
Each unique blob is scanned once in full, rather than only its patch. This covers
deleted files, merge-only content and historical binary archives. Reported path
and commit are one representative occurrence of those exact bytes; the blob ID
identifies the full Git file object, not a credential hash. It is not a list of
every commit/path that ever contained the file. Non-commit refs, unreachable or
deleted GitHub history and reflogs are outside this inventory.

ZIP/TAR and gzip/bzip2/xz containers are recognized by header or filename and
recursed into. Member names stay metadata (`outer.zip!inner.zip!file.env`);
payloads are written under generated names in private temporary directories.
No archive can choose an extraction path. Symlink/special members, unsafe paths,
encrypted/corrupt/recognized unsupported archives and unreadable files produce
gaps, not a clean result. Unknown binary formats/encodings can evade recognition.
Opaque staging names mean built-in path allowlists may differ from ordinary
working-file scans; binary detection, bundled rule allowlists and decode depth 5
still apply. No claim of exhaustive file-level scanner coverage is made.

Default limits: 600 seconds overall, 32 MiB per historical blob/archive input or
expanded member, 512 MiB staged historical bytes, 256 MiB expanded archive bytes,
5 nesting layers, 10,000 archive members, 10,000 commits and 200,000 inventory
entries. Compressed layers count toward expansion budgets too.
ZIP supports stored/deflate/bzip2 members; other compression methods are gaps.
XZ decoder memory is capped at 64 MiB; concatenated streams are reported incomplete.
The time budget is checked between operations; individual Git calls have a 120-second
maximum and their process group is stopped on timeout. Git metadata is
limited to 32 MiB per response; the temporary Git mirror itself can be large.
Limits/errors make coverage incomplete. Explicit `--timeout`, `--max-history-mib`
and `--max-archive-mib` overrides are available for reviewed larger scopes.

The report records per-phase versions/rules/status, fetched ref tips, coverage
counts and gaps. Missing submodule/LFS content is reported, not fetched implicitly.
Only refs currently exposed by GitHub are available: this does not include all
past force-pushed/deleted branches or all historical PR versions. GitHub Actions
logs/artifacts, release assets, issues/comments, other remotes and external storage
are outside scope and require a separate permissioned workflow. Findings are
preserved across phases; AI can group shared remediation without dropping IDs.
An incomplete result or unreviewed candidates must not become release approval.

Implementation references: [Git mirror clones](https://git-scm.com/docs/git-clone),
[blob batch reads](https://git-scm.com/docs/git-cat-file),
[GitHub PR refs](https://docs.github.com/en/pull-requests/how-tos/review-pull-requests/checking-out-pull-requests-locally).

## AI review and all-findings output

Apply [shared secrets triage](triage.md). Never read raw findings or secret-bearing
source lines into the model. Prefer local predicates that return only booleans or
safe metadata (for example, proof that a value is generated by an isolated fixture).
Do not use external credential verification. A matching format is not proof that
a credential is valid; a file named `test` is not proof that it is fake. Historical
findings must be assessed at the recorded commit, not against today's line numbers.

Save `assessments.json` alongside the private `report.json`, for example:

```json
[{"id":"SECRET-0001","disposition":"needs-review","confidence":"low","assessed_severity":"unknown","evidence":"A provider-token pattern was detected. Issuance and exposure are unverified; no secret value was inspected.","recommendation":"Have the owner determine whether the credential is real and rotate/revoke it if exposed."}]
```

Allowed dispositions: `confirmed`, `likely`, `false-positive`, `needs-review`,
`unreviewed`. Confidence: `high`, `medium`, `low`, `unknown`. Assessed severity:
`critical`, `high`, `medium`, `low`, `info`, `unknown`. Confirmed/likely/false-positive
also need real `evidence_refs` with `path` and positive `line`; historical evidence
must name its commit in the safe evidence text. Confirmed/likely require explicit
`preconditions`; false-positive requires high confidence and `dismissal_reason`.
Record the local check's conclusion, never its input secret or secret-bearing lines.

Use `groups.json` only for evidence-backed shared incidents/remediation: each group
has `title`, `finding_ids`, `root_cause`, `evidence`, `preconditions`, `recommendation`.
Do not infer equal credentials from redacted values, same provider or matching rule.
Use `[]` if identity is unknown. Every original finding/commit and dismissal remains
visible; no automatic deduplication or source-value hashes are emitted.

```sh
python3 <scripts-directory>/render_review.py <report.json> <assessments.json> --groups <groups.json>
```

The shared renderer writes `review.json`/`review.md` with every original finding and
explicit unreviewed entries. In chat, recommend fixes per reviewed issue, then
account for every ID, location/commit, disposition and dismissal/uncertainty reason.
Link the reports and distinguish candidate formats from validated live credentials.
Review authorizes no fixes, suppression changes, rotation, credential testing or
history deletion. A plausible exposed credential needs owner-led revocation/rotation;
removing the line alone does not revoke access.
