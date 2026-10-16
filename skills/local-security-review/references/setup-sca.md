# Set up SCA

Read [SCA licensing and scope](sca.md).
Resolve `../scripts/setup_sca.py` relative to this reference
directory, never from consumer-owned scripts. Python 3.10+ and macOS/Linux arm64/amd64
are supported (Windows needs WSL). The wrapper has no third-party Python dependencies.

1. Run `python3 <setup-script> --check`. It does not install or download anything.
2. For a missing pinned binary, run `python3 <setup-script> --install`. It downloads
   official OSV-Scanner 2.6.0 from GitHub, checks the bundled SHA-256 and saves it in
   `${XDG_CACHE_HOME:-~/.cache}/rasmus-security/sca/2.6.0`. No package manager, PATH
   edits or replacement of existing system tools. A changed/corrupt cached binary
   blocks setup; do not delete it or bypass its checksum automatically.
3. For missing databases or a requested refresh, run `python3 <setup-script> --update-db`.
   OSV downloads complete npm and PyPI advisory databases from Google's OSV storage
   into the same SCA cache. This may take several minutes and substantial disk space.
   It scans only synthetic package metadata; no repository content or private package
   identifiers are sent. It refreshes the dedicated cache, not consumer dependencies.
4. Run `python3 <setup-script> --verify` to exercise the actual scanner offline on
   known-vulnerable npm/PyPI fixtures. Fixtures are never installed or executed.

Before network/cache changes, explain commands, destinations and the separate
Apache-2.0 scanner / source-specific advisory-data terms. Use existing setup
authorization where applicable and request required tool permissions. A scan-only
request does not authorize tool installation; normal SCA scans do include database
refreshes by default. For readiness-only requests,
stop after `--check`; `prerequisites-ready` is not a completed functional test.

Finish only with `status: ready` from offline `--verify`, or explicitly report
the failed/missing prerequisite. Exit 2 means incomplete/failed. Record version,
cache paths and database timestamps; timestamps do not prove upstream freshness.
Never disable TLS verification to work around sandbox/network problems.

Resume the already-authorized local-security-review scope after setup. Setup alone does not authorize a repository scan.
