---
name: local-security-review
description: Check scanner setup, guide missing prerequisites through their setup flows, then run SAST, SCA and secret scanning with one lossless AI review. Use for combined full, working-diff, commit-snapshot or pre-release checks, not automatic fixes.
---

# Combined security review

Use the current repository unless a target was supplied. Resolve bundled scripts
relative to this installed skill, never to consumer-owned scripts. Use Python
3.10+ (the same supported interpreter throughout checks, setup and scans).
If `python3` points to an older system Python, prefer an existing supported
interpreter rather than treating the alias alone as a missing installation.

## Check and prepare

Run `python3 <skill-directory>/scripts/security.py --check` first. It checks all
three toolchains without downloads or a repository scan. For each non-ready
component, read and follow its focused setup flow, including licensing:

- SAST: [setup-sast](references/setup-sast.md).
- SCA: [setup-sca](references/setup-sca.md).
- Secrets: [setup-secrets](references/setup-secrets.md).

The runner may label prerequisites `setup-sast`, `setup-sca`, or `setup-secrets`; these names map to the reference documents above, not separate installed skills.

Enter the needed setup flows automatically rather than making the user invoke
another command. Summarize missing tools/downloads/destinations and request the
necessary installation/network permissions; reuse existing authorization when
applicable. Install only missing components. Integrity/license failures require
resolution, not deleting caches, replacing pins or using unreviewed rules.
After setup require that flow's functional `--verify` succeeds, then recheck all
prerequisites. Already-ready installations need no reinstall or repeated setup
fixtures on every scan; actual scans still detect runtime failures.

If setup is denied or remains blocked, report which scanners have not run and
stop incomplete. Do not silently scan only the available subset. A readiness-only
request stops after the check without setup or scanning. The runner itself never
installs tools; setup remains an explicit, permissioned agent workflow.

## Select scope and run

No scope interview: default to **full**. Map an optional user-supplied mode to:

| Invocation suffix | Runner flag | Scope |
| --- | --- | --- |
| none / `full` | none | All scanners on current working files |
| `diff` | `--diff` | SAST vs HEAD; full current SCA and secret scans |
| `commit` / `commit SHA` | `--commit HEAD` / `--commit SHA` | All scanners on the full selected commit snapshot |
| `release` | `--release` | Full working SAST/SCA, plus deep secrets with GitHub history and archives |

Run `python3 <skill-directory>/scripts/security.py <repository-root> <flags>`.
Full is the recommended default before merge. Diff is a faster development check,
not staged-only and not the whole PR vs its target branch. Commit mode excludes
uncommitted work and includes pre-existing findings; it is not a new-findings-only
filter. It uses an isolated snapshot and does not change the checkout/index.
The bundled `scripts/sast.py --help` documents SAST-only analysis; the combined workflow remains the public entry point.

Read [SAST coverage](references/sast.md), [SCA coverage](references/sca.md),
[secret boundaries](references/secrets.md) and [triage](references/triage.md).
Their standalone commands describe engine behavior; use the combined runner once,
not a second round of focused scans. Inspect languages, lockfiles and exclusions;
compare dependency roots against SCA's actual sources. Zero supported packages or
missing coverage is incomplete, not an automatic not-applicable success.

SAST includes Trivy IaC. Read [IaC scope and licensing](references/iac.md) when
infrastructure or generated CDK templates are present. Full/release mode accepts
explicit repository-relative `--iac-path <path>` inputs, including Git-ignored
templates. Pass them through to `security.py`; commit/diff modes reject these
working-tree additions. Generating templates, Terraform plans or AWS lookups
requires a separate authorised workflow, not automatic scanner setup.

Announce SCA's default advisory database refresh: downloads only, local matching,
no package identifiers/source upload. Release mode also fetches available GitHub
refs into a temporary mirror using existing read access; follow the deep-secret
scope/permission boundaries. Explicit offline requests pass `--offline`; disclose
unchecked SCA freshness and incomplete remote coverage in release mode. Setup
downloads require separate approval even if the subsequent scan is offline.

## One lossless review

The runner retains every SAST-/SCA-/SECRET- candidate in one private `report.json`,
with component reports under `engines`. Runtime failures do not prevent the other
scanners from running; any incomplete component keeps the combined scan incomplete.
Read only projected reports, not raw outputs or secret-bearing lines. For commit
mode, inspect evidence at the recorded SHA, not today's files; snapshot-relative
locations remain usable after the temporary snapshot is removed.

Assess every ID using shared triage. Save `assessments.json` and evidence-backed
`groups.json` beside the report, then run:

```sh
python3 <skill-directory>/scripts/render_review.py <report.json> <assessments.json> --groups <groups.json>
```

This produces one `review.json`/`review.md`: grouped recommendations plus all
original findings, including dismissal/uncertainty reasons. Same line/CWE or
redacted secret marker does not establish identity. Missing assessments remain
unreviewed; no candidate is removed. In chat lead with actionable issues, then
account for every ID, including dismissed/unresolved ones, and every coverage gap.
Link both review artifacts; an attachment/top-N summary alone is not sufficient.

Exit 0 means completed without scanner candidates, 1 means candidates, 2 means
incomplete. None is automatic merge/release approval. Review does not authorize
fixes, suppressions, credential validation/rotation, commits, pushes or deployment.
