# Set up local SAST

Make the existing SAST commands usable without modifying the consumer repository.
Reuse `../scripts/setup_sast.py`; resolve that path relative
to this reference directory, not the user's working directory. This is a per-user
setup, shared by repositories, not something to repeat in each repository.

## Check first

Read [the license boundary](licensing.md).
Explain briefly that scanners run locally, while later AI triage uses the current
Codex provider. Setup does not scan or upload the user's source, require a scanner
account, or configure AWS/CI.

Run `python3 <setup-script> --check` without a mode-selection interview. It reports
Git, Semgrep, Node compatibility, the locked Bandit/ESLint toolchain and the approved
rule snapshot plus checksum-pinned Trivy. `uv` and `npm` are installation tools, not runtime requirements once
the toolchain exists. `prerequisites-ready` is not a successful functional test.
If everything exists, skip installation/downloads and proceed to verification.

This installer uses POSIX paths (macOS/Linux). Native Windows is not supported by
this plugin's setup; explain the limitation and offer a WSL environment rather than
attempting the POSIX installer in PowerShell. Python 3.10+ must run the scripts.

## Install only what is missing

Summarize the missing components, exact commands, destinations and network activity
before requesting installation/download approval. Reuse an existing authorization
when it already covers these changes; honor tool-level approval requirements.
A scan request alone does not authorize setup. If downloads are declined, report
the missing components and stop without labelling the system ready.

- Reuse existing compatible Git, Node, npm, uv and Semgrep. For missing host tools,
  use the organization's approved installer/package manager. On macOS with
  Homebrew already available, install only missing packages (e.g. `brew install uv`
  or `brew install node@24`); avoid upgrading unrelated packages. A working Node
  version must satisfy the range `^20.19.0 || ^22.13.0 || >=24`. Change PATH only in the
  current tool environment unless persistent shell changes are separately approved.
  Explain any remaining PATH step needed for a new Codex session.
- For a missing Semgrep, prefer `uv tool install 'semgrep==1.176.0'`, the engine
  version exercised by this plugin. Check `uv tool dir --bin` and executable
  discovery afterwards; do not silently replace a different existing install.
  Semgrep's separate dependencies/runtime remain subject to platform software
  policy, not the Bandit/ESLint license inventory. No login, Pro engine or `semgrep ci`.
- For a missing locked toolchain, run `python3 <setup-script> --install` from a
  neutral directory outside the consumer repo. It installs hashed Python wheels
  and locked npm dependencies in the per-user cache, with npm lifecycle scripts
  disabled. Python 3.12 may be downloaded by uv. An existing validated toolchain is
  reused. On integrity/license errors, report the cause; do not delete caches,
  weaken the allowlist or reinstall over an existing receipt automatically.
- For missing rules, first explain the internal-business-use-only SRL boundary,
  then run `python3 <setup-script> --fetch-rules`. This downloads from the policy's
  upstream source, verifies its SHA-256 before saving and never overwrites existing
  rules. It does not send source code. The URL is mutable: if its bytes have changed,
  stop and request a maintainer-reviewed rule/policy update. Do not update the
  checksum, bundle the cached rules, use an unreviewed fallback or acknowledge a
  custom-rule license on the user's behalf merely to make setup pass.

- For missing IaC tooling, read [the IaC license boundary](iac.md).
  Trivy is a separate binary tool: Apache-2.0 engine/MIT checks, with dependencies
  including MPL-2.0; it is not covered by the Bandit/ESLint permissive allowlist.
  Confirm that this tool boundary is acceptable under the user's policy before
  installation. Then run `python3 <setup-script> --install-iac`. It downloads the
  pinned official archive, checks SHA-256 and retains LICENSE outside consumer repos.
  Existing or corrupt caches are never replaced automatically.

## Verify and hand off

Run `python3 <setup-script> --verify`. It checks prerequisites, then exercises all
four actual engines on temporary synthetic Python/TypeScript, Dockerfile and CloudFormation files with the
approved local rules. Fixtures are only analyzed, never executed. No downloads or
consumer-repository scan occur. The runner removes its temporary fixture/report
files. On macOS, Semgrep may require normal tool escalation for certificate-store
access even offline; never disable TLS verification. Other failures remain visible.

Completion requires exit 0 and `status: ready`, with all four engines detecting
the seeded examples. This verifies execution, not exhaustive security coverage.
Report a short ready/missing/failed checklist, versions, license-inventory path and
any PATH or policy blocker. Do not call setup successful if verification is skipped
or a component remains missing. If the user requested only a readiness check, run
`--check`, describe its limits, and make no installation changes.

Resume the already-authorized local-security-review scope after setup. Setup alone does not authorize a repository scan.


Installation references (checked 2026-09-18):
[Semgrep](https://docs.semgrep.dev/getting-started/quickstart),
[uv](https://docs.astral.sh/uv/getting-started/installation/).
