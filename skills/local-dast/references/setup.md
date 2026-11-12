# Setup and provenance

The runner uses Python's standard library and a separately downloaded ZAP archive. It does not install packages, access the network during setup checks, or modify a global scanner installation. Supported execution hosts: macOS and Linux with Python 3.10+ and Java 17+. Windows requires WSL; the runner uses POSIX process-group cancellation and filesystem permissions.

## Download once, outside the repository

Download `ZAP_2.17.0_Crossplatform.zip` from the [official 2.17.0 release](https://github.com/zaproxy/zaproxy/releases/tag/v2.17.0). The release metadata and checksums were inspected on 2026-10-22. Store the archive in a private machine-local tools/cache directory. Example:

```sh
mkdir -p "${XDG_CACHE_HOME:-$HOME/.cache}/rasmus-dast"
curl --fail --location --proto '=https' --proto-redir '=https' \
  https://github.com/zaproxy/zaproxy/releases/download/v2.17.0/ZAP_2.17.0_Crossplatform.zip \
  -o "${XDG_CACHE_HOME:-$HOME/.cache}/rasmus-dast/ZAP_2.17.0_Crossplatform.zip"
```

SHA-256, independently recorded from the release metadata:

```text
94c8f767b1c2e94f0db66b3ae56514d5e3f5a728ee1b6c798e0c8fe2d61fbff0
```

The runner verifies this pin before target requests and again before extraction. It extracts a fresh private runtime and removes it afterwards; the downloaded archive remains available for reuse. No mutable `latest` tag or update operation is used. A checksum is integrity evidence, not a signed-build guarantee.

Pass an absolute path to a Java 17+ executable with `--java`. Use the existing JDK if available. On Homebrew hosts a JDK can be installed but not selected by `/usr/bin/java`; use the actual JDK executable. Java installation and licensing are governed separately by the user's platform policy.

```sh
python3 /absolute/skill/scripts/dast.py --check \
  --zap-archive /absolute/cache/ZAP_2.17.0_Crossplatform.zip \
  --java /absolute/jdk/bin/java
```

The placeholders are intentional: resolve them on the current machine. `--check` does not launch Java, and reports that the runtime itself is not yet verified. Run a known synthetic case to establish actual scanner behavior.

## What has been run

Measured on 2026-11-12 on macOS 26.3.1 with Python 3.13 and Homebrew's OpenJDK 21: the pinned archive passed the check, ZAP imported the recorded traffic of the test server (read cases and write cases with a request body) and reported its passive alerts, and the collection's DAST tests passed with none skipped. The loopback-only `sandbox-exec` profile in the skill was measured the same day: from inside it an outbound HTTPS request failed and a loopback request answered, and a server started inside it answered a client outside it on 127.0.0.1. Remote mode was run the same day against a local TLS server only, with a throw-away certificate: an untrusted certificate stopped the case before any request, a trusted one let it pass, and ZAP read the HTTPS capture. Nothing has been measured on Linux, and no run has been made against a real application or a real deployed environment yet.

## Passive-analysis profile

Only these bundled add-ons are extracted into the ephemeral runtime:

| Add-on | Version |
| --- | --- |
| automation | 0.58.0 |
| callhome (mandatory core dependency; silent mode) | 0.20.0 |
| commonlib | 1.39.0 |
| network | 0.25.0 |
| pscan | 0.6.0 |
| pscanrules | 70 |
| exim | 0.16.0 |
| reports | 0.43.0 |

The archive pin also fixes the core JARs and these add-ons. Their upstream dependency manifests were inspected. Other add-ons, including OAST, active scan rules, browsers and crawlers, are not loaded. Updates and the API are disabled. ZAP's mandatory call-home module is loaded with `-silent`, disabling unsolicited requests including telemetry and update checks. The plan imports recorded HAR responses; it does not replay them or navigate URLs. This configuration is not an OS network sandbox. The collector is the only component intentionally making target requests.

## License boundary

ZAP core and the selected add-on source projects use Apache-2.0. The distribution contains third-party dependencies with their own notices; do not describe the entire ZIP as permissive-only or as already cleared by an employer. This profile does not change the separate source-review toolchain's license allowlist.

Only original wrapper code, instructions and the checksum are shipped with this skill. The ZAP archive is installed separately by the user. Preserve the archive's notices; the runner preserves the selected components and their embedded notices in its private extraction. Before use at work or redistribution, review the exact distribution and JDK against that organization's policy. Do not bundle ZAP, its JARs, add-ons or reports into the plugin. A future version needs new pins, add-on dependency/notice review and a real known-positive/negative integration test.

Primary references:

- [ZAP source and license](https://github.com/zaproxy/zaproxy/tree/v2.17.0)
- [Add-on source and license](https://github.com/zaproxy/zap-extensions)
- [Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/)
- [HAR import](https://www.zaproxy.org/docs/desktop/addons/import-export/automation/)
- [Report generation](https://www.zaproxy.org/docs/desktop/addons/report-generation/automation/)

## Failure handling

Logs remain under the private run directory. A missing report, timeout, unexpected schema, failed archive check or nonzero ZAP exit is incomplete coverage. Do not paste raw logs or HAR into chat. Inspect a narrowly selected diagnostic locally and summarize it without values. Preserve certificate verification; do not bypass TLS validation to download tools.
