# IaC under SAST

`sast.py` includes Trivy 0.74.0 as a fourth engine. Findings keep `SAST-` IDs,
`engine: trivy`, scanner severity and file/line metadata. The existing AI assessment
and grouping flow accounts for every returned finding, including dismissals.
The combined `security.py` runner inherits this engine; no separate skill is needed.

## Inputs and scope

Enabled scanners: CloudFormation, Terraform source/JSON plans, Dockerfile and
Kubernetes manifests. JSON/YAML candidates use Trivy's native recognition; unclassified
or unevaluated paths are listed, not presented as security-verified files. Helm,
Ansible, Azure ARM, Terraform state/binary plans and raw CDK source are not enabled.
Render templates or prepare plans separately when needed; no automatic build/render,
`cdk synth`, `terraform init/plan`, container execution, AWS calls or deployment.

Full scans use Git's tracked + eligible untracked inventory. Dependency/cache paths,
symlinks and files over 1 MiB are excluded; selected input is bounded to 64 MiB.
Git-ignored files are outside the default inventory. Snapshot modes use the exact
snapshot, never today's generated output. IaC changes trigger full eligible IaC
context so cross-file policies can be evaluated; all findings are retained, including
pre-existing issues. This is not a newly-introduced-IaC filter. A clean diff skips IaC.

### AWS CDK and generated templates

Raw CDK TypeScript/Python still gets application SAST; it is not CloudFormation
policy validation. `cdk.json` without explicit synthesized input produces an IaC
coverage gap. For a current, user-authorised synthesis, include only the resulting
local artifacts explicitly, e.g.:

```sh
python3 <scripts>/sast.py /path/to/repo --iac-path infra/cdk.out
python3 <scripts>/security.py /path/to/repo --iac-path infra/cdk.out
```

`--iac-path` is repeatable and repository-relative; it may include Git-ignored
JSON/YAML templates. A specific template file is narrower than its entire directory.
Full/release only: combining this flag with diff/commit is rejected. The scan does
not establish template freshness; verify that artifacts correspond to the intended
source/context and disclose that evidence. Do not edit generated JSON to remediate
a finding: trace it back to the CDK construct. Tracked static templates need no flag.

### Offline boundaries and missing coverage

The wrapper scans private temporary copies, with a neutral configuration, empty
module/cache paths, no scanner environment overrides or forwarded credentials.
It disables telemetry, version checks and rule updates, using embedded checks.
No repo-owned Trivy config, ignore file, custom Rego or plugin is loaded. This is
not an OS sandbox: run untrusted parsers inside the product's normal sandbox.

Trivy's Terraform parser can download modules and has no supported CLI switch in
this version that disables that behavior. Therefore, if a source file mentions
`module` (or has a JSON module key), the wrapper excludes the Terraform source set
and marks it incomplete. This conservative guard can flag comments/local modules;
use a separately prepared JSON plan for that scope. External module contents,
variable/context values and omitted resources are not inferred as verified.

Native inline `trivy:ignore`/`tfsec:ignore` directives are not rewritten. Their
presence makes coverage incomplete, even if the scanner returns no findings.
Scanner exceptions, WARN/ERROR diagnostics (including zero-exit parser failures),
missing expected-file evaluation, bounded-output failures and missing tools also
remain incomplete. Partial findings survive. Raw diagnostics, code snippets,
resource values and messages are discarded; only projected metadata reaches AI.

## Setup

Follow `setup-sast`. `setup_sast.py --check` includes Trivy; `--install-iac`
downloads only the pinned binary archive into the per-user `rai-security/iac`
cache. It validates SHA-256 before extracting the exact regular binary/LICENSE
members and verifies installed bytes against that archive. macOS/Linux arm64/x64
are supported. Existing/corrupt installations are preserved for inspection.
No binary, archive or upstream rules are bundled in this repository.

`setup_sast.py --verify` requires all four engines to detect temporary synthetic
examples. This is execution evidence, not proof that every IaC platform is covered.
The test suite also exercises parser failures and a safe Dockerfile control.

## Licensing and updates

The [Trivy engine](https://github.com/aquasecurity/trivy/blob/v0.74.0/LICENSE)
is Apache-2.0; [Trivy checks](https://github.com/aquasecurity/trivy-checks/blob/main/LICENSE)
are MIT. The bundled dependency chain is **not permissive-only**:
[HCL](https://github.com/hashicorp/hcl/blob/main/LICENSE), for example, is MPL-2.0.
This separately installed binary is outside the Bandit/ESLint package allowlist.
Confirm platform/license-policy acceptance before permanent installation; do not
add MPL to that allowlist or assume company legal approval. Preserve notices and
review distribution obligations separately before repackaging binaries/images.

Pins in `iac.py` refer to the official immutable 0.74.0 release and its
[published checksums](https://github.com/aquasecurity/trivy/releases/tag/v0.74.0).
Review releases, bundled dependencies and rules before updating; scans never fetch
the latest binary/checks automatically. Checksum matching is integrity evidence,
not proof of a trustworthy build. The maintainer-reviewed boundary must include
[upstream supply-chain advisories](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23);
no Trivy GitHub Action, mutable `latest` installer or container image is used here.

Implementation references: [CLI flags](https://trivy.dev/docs/latest/references/configuration/cli/trivy_config/),
[v0.74.0 Terraform parser](https://github.com/aquasecurity/trivy/blob/v0.74.0/pkg/iac/scanners/terraform/parser/parser.go).
