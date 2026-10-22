# License boundary

Technical review dated 2026-09-17 (Semgrep rule packs updated 2026-10-22), for scanning the organization's own repositories
internally. This is not company legal approval or a guarantee of compliance.
Customer scanning, external services, redistribution and changed dependencies or
rules require a new assessment. AI-provider data-handling terms are separate.

## Installed tools, not redistributed tools

The plugin contains our wrappers/configuration and dependency lockfiles, not
third-party binaries, node_modules, Python wheels or Semgrep rule contents.
`setup_sast.py --install` downloads tools into a separate per-user cache, disables
npm lifecycle scripts, installs only hashed Python wheels, checks installed
package license metadata against a conservative allowlist, and records packages,
versions, archive integrity and LICENSE/NOTICE file hashes in
`license-inventory.json`. Preserve the installed notices. Unknown licenses stop
setup; do not bypass the gate or treat an SPDX field as a complete legal audit.
If distributing these packages later, comply with their actual license texts,
including attribution/NOTICE and modification notices where applicable.

Direct pins: Bandit 1.9.4 (Apache-2.0), ESLint 10.10.0 (MIT),
eslint-plugin-security 4.0.1 (Apache-2.0), @typescript-eslint/parser 8.70.0 (MIT),
TypeScript 5.9.3 (Apache-2.0). Dependency versions and npm archive integrity are in
`../assets/toolchain/package-lock.json`; Python versions and distribution hashes
are in `../assets/toolchain/requirements.txt`. Installed transitive licenses are
MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC and BlueOak-1.0.0.
Blue Oak requires recipients of software copies to receive its license text or
license link. The license inventory is local evidence, not a published SBOM or
a claim that external redistribution is already cleared.

The reviewed scope excludes the operating system and preinstalled runtimes
(Node, Python, uv, npm) and Semgrep's transitive installation dependencies; those
remain subject to platform software policy. Semgrep is independently installed,
and its observed version is recorded in every scan.

## IaC scanner

Trivy is a separately downloaded binary, not part of the Bandit/ESLint package
allowlist or inventory. Its [engine](https://github.com/aquasecurity/trivy/blob/v0.74.0/LICENSE)
is Apache-2.0 and its [checks](https://github.com/aquasecurity/trivy-checks/blob/main/LICENSE)
are MIT, but bundled dependencies include MPL-2.0 (HCL). Confirm platform-policy
approval before permanent installation. Do not describe the complete binary as
permissive-only or silently weaken the existing allowlist. Checksum matching is
integrity evidence, not proof of a trustworthy build; keep
[upstream supply-chain advisories](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23)
in the update review. No Trivy GitHub Action, `latest` installer or image is used.

## SCA scanner and advisory data

[OSV-Scanner](https://github.com/google/osv-scanner/blob/v2.6.0/LICENSE) is Apache-2.0.
Advisory data is licensed separately: the GitHub Advisory Database and PyPA
advisory database use CC-BY-4.0 (attribution when sharing adapted data); RustSec is
CC0-1.0. Keep advisory IDs and links when sharing reports. OSV aggregates sources;
do not assume one license covers future feeds.

## Secret scanner

[Gitleaks](https://github.com/gitleaks/gitleaks/blob/v8.30.1/LICENSE) and its bundled
rules are MIT. This does not cover the separately licensed Gitleaks GitHub Action.
Upstream describes Gitleaks as feature-complete with security-patch releases;
migrating to another engine is a separate evaluation.

## Semgrep engine versus rules

Semgrep CE's LGPL-2.1 engine and Semgrep Rules License 1.0 are distinct. SRL permits
own internal business purposes but prohibits distributing rules or making them
available to others as a service. `../assets/semgrep-policy.json` lists the packs;
setup downloads them per user and records each pack's SHA-256 and download time.
Registry URLs are mutable, so content is recorded at download instead of pinned in
advance; a pack that later differs from its record is refused until refreshed.
Preserve upstream notices in the cached rules. Never add the cached YAML to a
plugin, shared image or a service offered to others. The rules in
`../assets/semgrep/` are written for this collection and are not SRL-licensed.

Custom rule configs require explicit license-review acknowledgment; the plugin
does not infer a license from compatibility with Semgrep or Opengrep. Do not
automatically add Trail of Bits AGPL rules or paid/private-use CodeQL. Strong
copyleft is not a ban on commercial use, but is outside this default toolchain's
technical allowlist. No Pro engine, hosted scanner or additional scanner account
is selected.

The legacy `scan.py sast` is a low-level Semgrep diagnostic runner, not the
license-gated multi-engine entrypoint. Normal skills always use `sast.py`.

## Updating

Review the exact new releases and their dependency licenses, regenerate locks,
run setup to create a new content-addressed toolchain, inspect its inventory and
run the test suite. Existing scans never update tools or rules. Keep previous
cache directories until no installed plugin needs them; deletion is manual.

Primary sources:

- [Bandit license](https://github.com/PyCQA/bandit/blob/1.9.4/LICENSE)
- [ESLint license](https://github.com/eslint/eslint/blob/v10.10.0/LICENSE)
- [eslint-plugin-security license](https://github.com/eslint-community/eslint-plugin-security/blob/v4.0.1/LICENSE)
- [TypeScript ESLint license](https://github.com/typescript-eslint/typescript-eslint/blob/v8.70.0/LICENSE)
- [TypeScript license](https://github.com/microsoft/TypeScript/blob/v5.9.3/LICENSE.txt)
- [Blue Oak license](https://blueoakcouncil.org/license/1.0.0)
- [Semgrep engine license](https://github.com/semgrep/semgrep/blob/develop/LICENSE)
- [Semgrep Rules License](https://semgrep.dev/legal/rules-license/)
