# Sources and local changes

This collection contains vendored source and local adaptations. It does not fetch updates at runtime.

| Component | Source revision | License / status |
| --- | --- | --- |
| TDD, diagnosis, prototype | Installed local copies from mattpocock/skills, captured 2026-10-14; exact installed commit unavailable | [MIT](licenses/pocock.txt) |
| Ponytail | DietrichGebert/ponytail 5.2.0 | [MIT](licenses/ponytail.txt) |
| Doubt-driven development | addyosmani/agent-skills `aeac41d4d005999432bb7312f7ff06383a91d59d` | [MIT](licenses/osmani.txt), adapted |
| Interview me | [addyosmani/agent-skills](https://github.com/addyosmani/agent-skills/blob/main/skills/interview-me/SKILL.md), inspected 2026-10-15 | [MIT](licenses/osmani.txt), adapted for bounded product discovery |
| ASD-STE100 | danyuchn/asd-ste100-skill `3944283c183eea13fe5bd902b572da3b4de8bf44` | [MIT](licenses/asd-ste100.txt), portable frontmatter adaptation |
| Local security review and tests | stampen-media/rai-security-plugin `2fc0d6d414d220e920cd7f13ef9953ab1201559f`; installed cache 0.1.0+codex.20260922120756 | User-requested copy; no upstream repository license found. No new license is asserted for this source. |
| Bug review and review contract | stampen-media/rai-code-quality-plugin `04c64e802ac646b56a0f0b0e10aa151740ba1a53`; installed cache 0.2.0+codex.20261001082644 | User-requested copy; no upstream repository license found. No new license is asserted for this source. |
| QA only | Original local workflow, inspired by garrytan/gstack report-only QA | No gstack runtime or source copied |
| Code validation | Existing rasmus-plugins source | English translation preserving review scope |

## Source links

- https://github.com/mattpocock/skills
- https://github.com/DietrichGebert/ponytail
- https://github.com/addyosmani/agent-skills
- https://github.com/danyuchn/asd-ste100-skill
- https://github.com/garrytan/gstack/blob/main/qa-only/SKILL.md
- https://github.com/stampen-media/rai-security-plugin
- https://github.com/stampen-media/rai-code-quality-plugin

The Pocock license was retrieved from revision `49dd158d1076134a641b33efb035946536778336`. The vendored skill content comes from the user's installed copies, not that newer revision.

The README lists behavioral adaptations. Security scanner code and test files remain unchanged. Setup skill bodies moved into `local-security-review/references/` with adjusted paths and handoffs. Their original setup permissions and license boundaries remain in effect.

Review-bugs and its review contract match the installed RAI code quality source captured on 2026-10-15. The contract is bundled inside the skill, and the broad-review handoff uses this collection's code-validation instead of the upstream review-code skill. No other RAI code quality skills or runtime dependencies are imported.

ASD's official dictionary is not included. The ASD-STE100 skill provides structural rules and a heuristic linter, not certified compliance.
