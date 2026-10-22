# Engine coverage

What each engine sees, so you can tell "nothing found" from "not looked at". Gaps are
listed in each engine's `coverage` in `report.json`; mention the ones that matter.

## Modes

- **full**: working files including uncommitted and untracked ones.
- **diff**: SAST compares a temporary snapshot of the working tree with HEAD (staged
  and unstaged together; not a PR-vs-base comparison). Semgrep reports only new
  results; Bandit, ESLint and Trivy report everything in changed files. SCA and
  secrets still scan all working files.
- **commit [SHA]**: an isolated clone of that commit; all engines on the full
  snapshot, including pre-existing issues. Uncommitted work is excluded. Inspect
  evidence at that commit (`git show SHA:path`), not in today's files.
- **release**: full SAST/SCA plus deep secrets (below).
- `--iac-path <dir>` (full/release only) adds Git-ignored generated templates such as
  `cdk.out`. Generating them (`cdk synth`, `terraform plan`) is a separate step.
- `--offline` skips the advisory refresh and the GitHub fetch; say so in the report.

The user's checkout, index and refs are never modified. Reports contain IDs, rules,
locations and metadata only; source snippets, messages and secret values are dropped.

## SAST

- **Semgrep CE** with the registry packs in `assets/semgrep-policy.json` (downloaded
  at setup, content hash recorded) plus collection rules in `assets/semgrep/` (Rust
  path traversal, SQL via `format!`, command injection, permissive CORS, JWT
  validation, header injection, unwrap on request bodies). `nosemgrep` is ignored.
  Semgrep's default ignore list skips `tests/`, `vendor/`, `build/`, `dist/` and
  minified files. A file Semgrep cannot fully parse is counted in
  `coverage.parse_warnings`; its other results remain.
- **Bandit** (Python) and **ESLint + eslint-plugin-security** (JS/TS, no type
  information): every rule at every severity, tests included, `nosec` and inline
  ESLint config ignored. No repository config or dependency is loaded.
- **Trivy** (IaC): Terraform, CloudFormation, Dockerfile, Kubernetes. Terraform files
  that declare non-local modules are skipped (Trivy could download them); use a JSON
  plan for those. Helm charts, raw CDK code and Terraform state are not evaluated.
  Inline `trivy:ignore` makes coverage partial. `unclassified_or_unevaluated_paths`
  lists JSON/YAML that Trivy did not recognize as IaC; that is informational.
- All SAST skips symlinks, files over 1 MiB and dependency/cache directories.

Rust gets Semgrep (registry `p/rust` plus the bundled rules) and SCA; there is no
Clippy or compiler-based analysis because that would build and run project code.

## SCA

OSV-Scanner matches locked versions in lockfiles and SBOMs (including Git-ignored
lockfiles such as an untracked `Cargo.lock`) against local advisory databases.
npm, PyPI and crates.io databases are prepared at setup; other ecosystems download
on first use. Each scan refreshes changed databases first (downloads only; no package
names leave the machine). No dependency resolution, installs or build scripts: a
manifest without a lockfile has unknown versions and is listed in
`coverage.manifests_without_lockfiles`. Repository vulnerability ignores are
overridden. Findings include `fixed_versions` from the advisory.

## Secrets

Gitleaks with its bundled rules scans working files, including untracked and
git-ignored files such as `.env`. Dependency and build output (`node_modules`,
`target`, `.next`, `.venv`, caches) is skipped because generated keys there are
noise. `gitleaks:allow` and repository ignore files are disabled. Archives are not
unpacked in normal modes. Values are redacted; use `scripts/secret_probe.py`.
Gitleaks looks for known token formats and high-entropy values, so hand-written
literals such as `api_key="SOME_PASSWORD"` are often missed; probe config files the
map points to.

**Release mode** adds a private mirror of the GitHub `origin` (branches, tags and
available pull-request refs, using existing `gh`/SSH access; github.com only) and
scans every unique historical blob plus ZIP/TAR/gzip/bzip2/xz contents, within limits
(600 s, 32 MiB per blob, 512 MiB history, 256 MiB expanded archives, 10,000 commits).
Force-pushed or deleted history, CI logs, release assets and other remotes are out of
scope. Limits reached make coverage partial, never a clean result.
