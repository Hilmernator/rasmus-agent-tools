# SCA: dependency evidence, not automatic exploitability

The first engine is OSV-Scanner **2.6.0**. One engine already reads JS/TS and Python
lockfiles/SBOMs and matches multiple advisory sources. A second engine is not added
merely to repeat the same database. No account, scanner subscription or hosted
source-code upload is required. The Python wrapper uses only the standard library.

## Licensing (checked 2026-09-18)

- OSV-Scanner is [Apache-2.0](https://github.com/google/osv-scanner/blob/v2.6.0/LICENSE),
  a permissive license allowing commercial use subject to its terms. Setup fetches
  official binaries; the plugin does not redistribute them. Preserve upstream notices.
- Binary SHA-256 pins come from the [official release](https://github.com/google/osv-scanner/releases/tag/v2.6.0).
  Integrity verification is not a complete audit of statically linked dependency
  licenses or SLSA provenance. Those dependencies and host runtimes remain subject
  to platform software approval; there is no claim of an audited binary SBOM.
- Advisory data is not licensed by the scanner's Apache license. The
  [GitHub Advisory Database](https://github.com/github/advisory-database/blob/main/LICENSE.md)
  and [PyPA advisory database](https://github.com/pypa/advisory-database/blob/main/LICENSE)
  use **CC-BY-4.0**, which allows commercial use with attribution obligations when
  sharing adapted/data copies. OSV aggregates sources; don't assume one license
  covers all present/future feeds. Keep advisory IDs/links, source attribution and
  applicable notices when sharing reports or redistributing data. Default setup
  downloads npm/PyPI only; additional ecosystems/feeds require their own review.
- This is a technical selection for internal use, not legal approval. Neither this
  vulnerability scan nor the scanner's license audits the target's dependency licenses.
  Company approval and AI-provider data terms remain separate.

## Coverage and operation

`scan.py sca <repository>` uses working lockfiles/SBOMs, including development/test
dependencies. It does not resolve manifests, install packages, execute build scripts,
or run Go/Rust call analysis. Only lockfile/SBOM extractors are enabled. Repository
vulnerability/package suppressions are overridden; file ignores still apply.

Setup installs in `${XDG_CACHE_HOME:-~/.cache}/rai-security/sca`. Every default scan
uses OSV's `--download-offline-databases` with local advisory matching: the scanner
checks the published database checksum for each scanned ecosystem and downloads
changed/missing archives. No package identifiers or source code are uploaded.
There is no daily TTL; unchanged remote data can reuse the cache without a download.
Setup prepares npm/PyPI; inspect any additional ecosystem's data terms before scanning it.
The report records `advisory_mode` and `database_refresh` (status, successful
`checked_at`, ecosystems). Failed/unverified refresh is incomplete, never a silent
stale-cache success. `--offline` is an explicit user-selected exception: no refresh,
cached data only. Disclose that exception. Cache mtime may be unchanged after a
successful remote check and is not upstream advisory freshness. Successful refresh
means current published OSV data, not all vulnerabilities known to every source.
`setup_sca.py --update-db` remains available for separate npm/PyPI refreshes;
its `--check` and `--verify` remain offline.
`--allow-network` instead queries advisory services with dependency metadata only
after approval. Scanner flags are not an OS-enforced network sandbox.

Inventory every dependency root and compare actual `coverage.sources` and package
counts with its lockfiles/SBOMs. Missing/unreadable/unsupported files, unpinned
requirements, private/Git/path packages, platform markers and unresolved transitive
dependencies are coverage gaps, not clean results. Do not generate lockfiles or
run package managers to fill them without a separate request. A nonempty inventory
does not prove the entire repository was covered; annotate the final review as
incomplete when a required root is missing even if the scanner returned success.
Empty projects return incomplete rather than a misleading clean scan.

Supported formats are defined by [upstream artifact support](https://google.github.io/osv-scanner/supported-languages-and-lockfiles/),
not just the source language. Inspect requirements pins and compare coverage before
claiming Python is covered. Setup tests package-lock v3 and pinned requirements;
it does not prove every lockfile format works. The combined `security.py --commit`
scans all lockfiles in an isolated selected snapshot, not just changed packages.
Its `--diff` keeps SCA on current working lockfiles; there is no SCA baseline filter.

## AI review and lossless grouping

Apply [shared triage](triage.md). Each report finding has a scan-local `SCA-` ID,
original advisory ID, aliases, package/version/ecosystem, source path, affected
ranges/fixed events, original severity, advisory link and timestamps. Advisory
descriptions and source snippets are omitted; consult the linked advisory and
actual lockfile/code to assess applicability. Never equate advisory matching with
a demonstrated runtime exploit. A dev dependency or missing import is not enough
to dismiss it: build/test environments can also be exposed.

Save `assessments.json` alongside `report.json`, one assessment per finding ID:

```json
[{"id":"SCA-0001","disposition":"needs-review","confidence":"low","assessed_severity":"unknown","evidence":"Locked version matches the advisory; vulnerable feature usage has not been traced.","recommendation":"Trace usage and check an unaffected release before recommending an upgrade."}]
```

Allowed dispositions: `confirmed`, `likely`, `false-positive`, `needs-review`,
`unreviewed`. Severity: `critical`, `high`, `medium`, `low`, `info`, `unknown`.
Confidence: `high`, `medium`, `low`, `unknown`. Confirmed/likely/false-positive need
`evidence_refs: [{"path":"package-lock.json","line":12}]` with real evidence
locations, not invented scanner line numbers. Confirmed/likely require explicit
`preconditions`. False-positive requires high confidence and a concrete
`dismissal_reason`. Insufficient reachability evidence stays `needs-review`.

For duplicates, save `groups.json`: an array of objects with `title`, `finding_ids`,
`root_cause`, `evidence`, `preconditions`, `recommendation` (all text except the ID
array). Group only after reviewing all members, verifying shared advisory aliases,
same package/version/occurrence and common remediation. Same package name or CWE
alone is insufficient. Copies in independent lockfiles can require separate fixes.
Use `[]` if identity is uncertain. Every original ID/assessment remains in the report.

```sh
python3 <scripts-directory>/render_review.py <report.json> <assessments.json> --groups <groups.json>
```

The renderer writes exclusive-create `review.json`/`review.md` beside the private
report. Missing assessments stay unreviewed. It checks accounting and structure,
not the truth of AI analysis. In chat, give one recommendation per reviewed issue
with all member IDs, then every dismissed/unresolved ID with its rationale. State
raw finding count, actionable/unresolved issue counts, all coverage gaps, network
mode and cache age. Link both reports. Never silently omit findings or call the
review complete while entries remain unaccounted for. No fixes or suppression edits.

Primary operational references:
[Source scanning](https://google.github.io/osv-scanner/usage/scan-source),
[Offline databases](https://google.github.io/osv-scanner/usage/offline-mode/),
[Configuration override](https://google.github.io/osv-scanner/configuration/).
The pinned release's [archive updater](https://github.com/google/osv-scalibr/blob/3090dbb7aaa2/enricher/vulnmatch/osvlocal/zip.go)
checks remote checksums on refresh, rather than using a daily cache TTL.
