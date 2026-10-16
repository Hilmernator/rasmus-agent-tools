# Set up secret scanning

Read [license and data boundaries](secrets.md).
Resolve `../scripts/setup_secrets.py` relative to this
reference directory. Requires Python 3.10+, macOS/Linux arm64/x64; Windows uses WSL.

1. Run `python3 <setup-script> --check`. This is read-only and offline.
2. If the pinned installation is missing, explain the download/destination and run
   `python3 <setup-script> --install` with authorization. This fetches Gitleaks
   8.30.1 from its official GitHub release, checks the pinned archive SHA-256,
   and installs only the binary, retained archive and MIT license into
   `${XDG_CACHE_HOME:-~/.cache}/rasmus-security/secrets/8.30.1/<platform>`.
   Existing system tools/PATH and consumer files are untouched. Reuse existing
   installation authorization; honor tool-level permissions. A scan-only request
   does not authorize installation. Integrity failures stop setup: preserve the
   cache for inspection instead of bypassing checks or deleting/replacing it.
3. Run `python3 <setup-script> --verify`. It runs the actual scanner offline on
   a generated, never-issued synthetic token and a negative control. It checks
   detection despite an inline suppression and absence of token values from the
   retained report. Temporary fixtures and reports are removed.

Completion requires `status: ready` from `--verify`; `--check` alone establishes
only prerequisites. If the user wants only readiness inspection, stop after
`--check` without downloads and describe that limit. Report version, license path
and missing/failed prerequisites. Never print fixture values or disable TLS.

Resume the already-authorized local-security-review scope after setup. Setup alone does not authorize a repository scan.
There is no CVE database to refresh: rules ship with the pinned Gitleaks binary.
Updates require reviewing a new release/checksums and rerunning setup/tests; scans
do not silently upgrade tools or send credentials for provider verification.
