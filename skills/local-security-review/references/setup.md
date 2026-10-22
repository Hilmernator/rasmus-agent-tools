# Setup

Everything installs into the per-user cache `${XDG_CACHE_HOME:-~/.cache}/rasmus-security/`
and is shared by all repositories. Nothing is installed into or run from the scanned
repository. macOS and Linux (arm64/x64); on Windows use WSL.

## One command

```sh
python3 scripts/security.py --check   # read-only: what is missing
python3 scripts/security.py --setup   # install what is missing, then verify all engines
```

`--setup` performs only the missing steps and ends with a functional verification of
every engine on synthetic fixtures. Status `ready` means all engines detected their
seeded examples. Rerun it after fixing a failed step; finished steps are skipped.

What it downloads (tell the user before running it):

| Component | Source | Needs |
| --- | --- | --- |
| Semgrep 1.176.0 | PyPI via `uv tool install` (only if `semgrep` is missing) | uv |
| Bandit, ESLint, security plugin, TS parser | locked, hash-checked wheels and npm packages; npm scripts disabled | uv, npm, Node `^20.19 \|\| ^22.13 \|\| >=24` |
| Semgrep rule packs | `https://semgrep.dev/c/p/<pack>` for each pack in `assets/semgrep-policy.json` | network |
| Trivy 0.74.0 | official GitHub release, SHA-256 pinned | network |
| OSV-Scanner 2.6.0 + npm/PyPI/crates.io advisory databases | official GitHub release (SHA-256 pinned), OSV storage | network, a few hundred MB |
| Gitleaks 8.30.1 | official GitHub release, SHA-256 pinned | network |

## Updating

- Semgrep rules: `python3 scripts/setup_sast.py --refresh-rules` re-downloads every
  pack. The content hash and time are recorded in `packs/manifest.json`; a pack that
  later differs from its record makes SAST refuse to run until refreshed.
- Advisory databases refresh automatically before each SCA scan, or explicitly with
  `python3 scripts/setup_sca.py --update-db`.
- Scanner versions change only by editing the pins in the setup scripts, reviewing
  the release, and rerunning setup and the tests.

## When something fails

- **Checksum or integrity mismatch**: stop and report it. Do not delete the cache,
  edit pins or download from elsewhere to make it pass.
- **License gate in the SAST toolchain** (unknown package license): report the
  package; do not widen the allowlist.
- **Semgrep certificate errors in a macOS sandbox**: request normal tool permissions;
  never disable TLS verification.
- **Missing uv/npm/Node**: install them with the platform's normal package manager
  (for example `brew install uv node`) after the user agrees.

The individual scripts remain available for focused work:
`setup_sast.py --check|--install|--fetch-rules|--install-iac|--verify`,
`setup_sca.py --check|--install|--update-db|--verify`,
`setup_secrets.py --check|--install|--verify`.

Read [licensing](licensing.md) before using these tools outside your own repositories.
