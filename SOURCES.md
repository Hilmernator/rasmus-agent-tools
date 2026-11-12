# Sources and local changes

This collection contains vendored source and local adaptations. It does not fetch updates at runtime.

| Component | Source revision | License / status |
| --- | --- | --- |
| TDD, diagnosis, prototype | Installed local copies from mattpocock/skills, captured 2026-10-14; exact installed commit unavailable | [MIT](licenses/pocock.txt) |
| Ponytail | DietrichGebert/ponytail 5.2.0 | [MIT](licenses/ponytail.txt) |
| Doubt-driven development | addyosmani/agent-skills `aeac41d4d005999432bb7312f7ff06383a91d59d` | [MIT](licenses/osmani.txt), adapted |
| Interview me | [addyosmani/agent-skills](https://github.com/addyosmani/agent-skills/blob/main/skills/interview-me/SKILL.md), inspected 2026-10-15 | [MIT](licenses/osmani.txt), adapted for bounded product discovery |
| ASD-STE100 | danyuchn/asd-ste100-skill `3944283c183eea13fe5bd902b572da3b4de8bf44` | [MIT](licenses/asd-ste100.txt), portable frontmatter adaptation |
| Local security review and tests | Stampen Media security plugin `2fc0d6d414d220e920cd7f13ef9953ab1201559f`; installed cache 0.1.0+codex.20260922120756 | User-requested copy; no upstream repository license found. No new license is asserted for this source. |
| Bug review and review contract | Stampen Media code quality plugin `04c64e802ac646b56a0f0b0e10aa151740ba1a53`; installed cache 0.2.0+codex.20261001082644 | User-requested copy; no upstream repository license found. No new license is asserted for this source. |
| Security audit | [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill) `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8`, captured 2026-10-26 | [MIT](skills/security-audit/LICENSE), unchanged upstream skill |
| Security gap analysis | Collection-authored workflow and `gap.py`. Catalogs from [OWASP/ASVS](https://github.com/OWASP/ASVS) v5.0.0 `5cf9b032440be53ce345ab3c130fda46ba1ce7a2`, [OWASP/AISVS](https://github.com/OWASP/AISVS) v1.01 `3ae3af45c363467b8ad823ef79219236e67ca22f`, [OWASP/masvs](https://github.com/OWASP/masvs) v2.1.0 `1de2913fe799137ac4695eabaae633da693070cd`, captured 2026-11-04 | Catalogs: CC BY-SA 4.0, [notice](skills/security-gap-analysis/catalogs/NOTICE.md); requirement text unchanged, reformatted to JSON |
| Blueprint | Collection-authored skill and scripts, moved from Rasmus's animation-engine repository at `20f1ebf`, 2026-11-12. `assets/svg` holds AWS Architecture Icons (service icons at 48 px and group icons, releases named in `assets/svg/catalog.json`). The layout engine (elkjs) and the fonts are npm dependencies and are not committed. | Scripts: collection-authored. Icons: AWS's terms for the Architecture Icons apply; no licence is asserted for them here. |
| Local DAST | Collection-authored skill, HTTP collector, ZAP adapter and tests, 2026-10-22; login sessions, state-changing cases and remote mode added 2026-11-12 | No upstream implementation copied; ZAP is downloaded separately, see below |
| QA only | Original local workflow, inspired by garrytan/gstack report-only QA | No gstack runtime or source copied |
| Code validation | Existing rasmus-agent-tools source | English translation preserving review scope |

## Source links

- https://github.com/mattpocock/skills
- https://github.com/DietrichGebert/ponytail
- https://github.com/addyosmani/agent-skills
- https://github.com/danyuchn/asd-ste100-skill
- https://github.com/garrytan/gstack/blob/main/qa-only/SKILL.md

The Pocock license was retrieved from revision `49dd158d1076134a641b33efb035946536778336`. The vendored skill content comes from the user's installed copies, not that newer revision.

The README lists behavioral adaptations. Security scanner code and tests retain their upstream behavior; cache paths, temporary names, Git ref namespaces, test opt-ins, and package labels now use collection-specific names. The SAST setup hint points to the bundled setup reference. Setup skill bodies moved into `local-security-review/references/` with adjusted paths and handoffs. Their license boundaries remain in effect. Version 0.6.0 rewrote the workflow (investigation, hunt, fix plan), merged the references, added multi-pack Semgrep rules, collection-authored Rust rules, crates.io advisories, one-command setup and `secret_probe.py`; scanner isolation, redaction and integrity checks are unchanged.

Review-bugs and its review contract match the installed Stampen Media code quality source captured on 2026-10-15. The contract is bundled inside the skill, and the broad-review handoff uses this collection's code-validation instead of the upstream review-code skill. No other upstream code quality skills or runtime dependencies are imported. Upstream project branding and repository links were removed at the maintainer's request; source owner, captured revisions, and license status remain recorded above.

## Local DAST runtime

Local DAST uses the separately downloaded [ZAP 2.17.0 cross-platform archive](https://github.com/zaproxy/zaproxy/releases/tag/v2.17.0), SHA-256 `94c8f767b1c2e94f0db66b3ae56514d5e3f5a728ee1b6c798e0c8fe2d61fbff0`, retrieved from upstream release metadata on 2026-10-22. The archive downloaded on 2026-11-12 matched that pin. No archive, upstream source, rules or scan output is bundled. The runner itself uses only Python's standard library. This is not a general redistribution clearance for ZAP or its dependencies, and does not alter the existing source scanner license gates; see [the DAST setup reference](skills/local-dast/references/setup.md).

ASD's official dictionary is not included. The ASD-STE100 skill provides structural rules and a heuristic linter, not certified compliance.

Security-audit includes every file from the pinned upstream `skills/security-audit/` directory without modification. The upstream MIT license is included inside the skill so standalone copies retain the notice. This revision also matches the installed local skill byte for byte; no runtime download or installation hook is added.
