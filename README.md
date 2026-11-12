# Rasmus Agent Tools

A personal collection for iterative software development: build a small step, test it, inspect the result, and adjust.

All skill instructions and repository documentation are in English. The collection does not require a specification or interview before normal work.

## How I like to work

I work in small, complete steps: build something useful, try it, inspect the result, and adjust. A clear task is enough to start. For a new product, I prefer a short conversation that establishes its purpose and the next experiment, then a living brief that evolves with what we learn.

I want an agent to act like a capable colleague: use the repository and the conversation, make routine reversible decisions, and carry authorized work through implementation and verification. Ask focused questions when missing information changes the outcome or a wrong assumption is costly. Reuse answers I have already given, and make any necessary approval concrete and easy to review.

I prefer the smallest solution that fully works. Reuse existing code and platform features, keep interfaces simple, and avoid speculative abstractions and dependencies. Small changes still need appropriate validation, error handling, security, and accessibility.

Evidence guides the next step: a failing test, a reproducible bug, a working prototype, or an exercised user flow. Use the review that answers the actual uncertainty. Explain the result in plain language: what changed, how it was checked, and what remains uncertain.

## Skills

| Skill | Use it for | Source |
| --- | --- | --- |
| [interview-me](skills/interview-me/SKILL.md) | Clarify product direction and the next experiment | Adapted Osmani workflow |
| [ponytail](skills/ponytail/SKILL.md) | Small, complete changes with limited complexity | Ponytail 5.2.0 |
| [tdd](skills/tdd/SKILL.md) | One behavior and one failing test at a time | Adapted installed Pocock skill |
| [diagnosing-bugs](skills/diagnosing-bugs/SKILL.md) | Reproduce, isolate, fix, and verify a defect | Installed Pocock skill |
| [prototype](skills/prototype/SKILL.md) | Answer a design question with a disposable experiment | Adapted installed Pocock skill |
| [code-validation](skills/code-validation/SKILL.md) | Review an uncommitted diff without edits | Existing custom skill, translated |
| [review-bugs](skills/review-bugs/SKILL.md) | Explore edge cases, failure paths, and recovery without fixes | Adapted code quality plugin; see SOURCES.md |
| [qa-only](skills/qa-only/SKILL.md) | Exercise behavior and report failures without fixes | Local workflow inspired by gstack |
| [doubt-driven-development](skills/doubt-driven-development/SKILL.md) | Independently challenge a difficult claim | Adapted Osmani workflow |
| [local-security-review](skills/local-security-review/SKILL.md) | Local security review: scanners, impact investigation, hunt, fix plan | Adapted security plugin; see SOURCES.md |
| [security-audit](skills/security-audit/SKILL.md) | Source-first security guidance and multi-phase audits with independent verification | Cloudflare; see SOURCES.md |
| [security-gap-analysis](skills/security-gap-analysis/SKILL.md) | Missing controls: gap analysis against the security requirements that fit the product (ASVS, AISVS, MASVS), documented in the repository's `security/` folder | Collection-authored; bundled OWASP catalogs, see SOURCES.md |
| [blueprint](skills/blueprint/SKILL.md) | Draw a codebase's architecture as an HTML page where every box cites the code behind it; sketch, compare and diff architectures | Collection-authored; see SOURCES.md |
| [asd-ste100](skills/asd-ste100/SKILL.md) | Clear technical English with preserved meaning | danyuchn/asd-ste100-skill |

## Daily use

Use interview-me when you need an overall product direction. It produces a living brief with requirements, hypotheses, open questions, and the next experiment. Small clear features can proceed directly to implementation.

Use Ponytail as the coding style. Use TDD for the next behavior and diagnosis when a failure needs investigation. Use a prototype when an experiment can answer an unresolved question.

Run code validation before commit and QA when runtime behavior needs verification. Use review-bugs to probe edge cases, invalid inputs, concurrency, and recovery in an uncommitted diff or selected flow; it reports findings without changing source files. Use doubt-driven development for difficult claims rather than every small edit. Use local-security-review for scanner-backed security reviews and security-audit for source-first guidance or multi-phase audits.

These workflows complement each other. Avoid running several equivalent reviews on the same unchanged artifact.

## Use the collection

Clone [rasmus-agent-tools](https://github.com/Hilmernator/rasmus-agent-tools). Copy the selected complete skill directories into the skill directory supported by your agent. Each skill includes its local references and scripts. Preserve an existing installation until you have compared it.

For Codex, personal skills can live under `~/.agents/skills/<name>`. For Claude Code, they can live under `~/.claude/skills/<name>`. Invoke a skill by its displayed name; Codex supports `$tdd`, and Claude Code supports `/tdd` for these directory names.

The root `plugin.json` describes the portable skills plugin. Compatibility manifests in `.codex-plugin/` and `.claude-plugin/` expose the same collection to those hosts. This repository is the source of truth; no installation, cache replacement, or global configuration change is performed by cloning it. Copy only the selected directories to avoid duplicates with the original plugins.

## Blueprint

Use [blueprint](skills/blueprint/SKILL.md) to see how a repository is built. It keeps the architecture as a model in which every zone, component, connection and flow cites file and lines, refuses a model whose citations do not exist, and draws it as one HTML page under `~/blueprint/`. Run `npm ci --prefix skills/blueprint/scripts` once (Node.js; the layout engine and fonts come from npm and are not committed). Deep mode has the agent in the session read the code. The quick commands send code of the analysed repository to the Claude Code or Codex CLI; the skill's rules say what is sent and what never is.

## Security workflows

Three skills answer three different questions. None replaces another, and none of them tests a running application.

| Question | Skill | It leaves behind |
| --- | --- | --- |
| Which known defect patterns, leaked secrets, vulnerable dependencies and misconfigured infrastructure are in the code, and which of them matter? | `local-security-review` | A fix plan and `review.md` in a private temporary folder |
| Which defects does a careful reader find without scanners? | `security-audit` | A structured report with a coverage ledger |
| Which controls should exist and do not? | `security-gap-analysis` | The repository's `security/` folder |

For a full pass over a repository, run them in this order, each on the result of the one before: `security-gap-analysis` first (its `security/profile.md` and inventory are the map the others start from), then `local-security-review` with `release`, then `security-audit` in full mode when a second, independent reading is worth its cost. Blueprint gives the same map as a picture when that helps. On unchanged code, one run of each is enough.

What no skill here covers: the running application (dynamic testing), what is deployed but not in the repository, container images, dependencies outside npm, PyPI and crates.io, licence compliance of dependencies, and standards that are not bundled (CIS and cloud benchmarks, PCI DSS, ISO 27001, SOC 2, GDPR). No bundled standard covers the build and release pipeline; the gap analysis inventories it and reports what it finds as outside the selection.

Use `local-security-review`. The agent prepares the scanners with one command (`security.py --setup`), scans, maps the target, investigates every finding for reachability and impact (confirming it with a local regression test where practical), hunts for issues scanners miss, and returns a fix plan. Say "fix it" afterwards to apply the plan.

The default scope is full. Optional suffixes are `diff`, `commit [SHA]`, and `release`. Languages: Python, JavaScript/TypeScript and Rust source; npm, PyPI and crates.io dependencies; Terraform, CloudFormation, Dockerfile and Kubernetes; secrets in any file.

Python 3.10+ is required. Setup supports macOS and Linux; Windows requires WSL. The locked ESLint toolchain requires Node `^20.19.0 || ^22.13.0 || >=24`. Scanner binaries, advisory databases, and rule packs remain machine-local and are not committed here.

Review the [scanner licensing boundaries](skills/local-security-review/references/licensing.md) before setup.

Use [security-audit](skills/security-audit/SKILL.md) for source-first security guidance or an explicitly requested full codebase audit. Full audits use reconnaissance, coverage-led hunting, independent validation, and structured reports. The bundled validators use Node.js and have no external dependencies. Target-code execution requires the sandbox controls defined in the skill; if those controls are unavailable, validation remains blocked. Choose the workflow that answers the task rather than running both by default.

Use [security-gap-analysis](skills/security-gap-analysis/SKILL.md) to find controls that are missing rather than bugs in code that exists. It models the product, selects OWASP ASVS 5.0, AISVS 1.0 for LLM, agent, RAG and MCP features, and MASVS 2.1 for mobile apps, then records a status with `file:line` evidence for each requirement in the target repository's `security/` folder. Coverage is checked, not assumed: every file is listed and must be read, skimmed or skipped with a reason, and a fixed-pattern inventory of the ways in (servers, routes and serverless handlers, command lines, IPC, uploads), the effects outside the program (processes, network calls, data stores, model calls), the build and release pipeline, and the dangerous sinks must be placed in the profile or explained. A file that changes reopens itself and the rows that cite it. The requirement catalogs are bundled; `scripts/build_catalogs.py` rebuilds them from the pinned sources.

## Upgrade notes for 0.9.0

Added blueprint, moved here from the animation-engine repository. Its pages now go under `~/blueprint/`; pages made before the move stay where they were written and still open.

Security-gap-analysis finds more kinds of boundary: serverless handlers and event sources, framework route files, command lines and stdin, uploads and archives, data stores, the build and release pipeline, native and unsafe code, and switched-off TLS verification. An existing `security/` folder therefore shows new `unreviewed` inventory lines on its next `gap.py inventory`, and `gap.py check` fails until they are placed. `gap.py check --complete` also fails while a requirement is unassessed. Local-security-review keeps a list of entrypoints and marks each one walked or not walked; its hunt now covers webhooks, uploads, sessions and cryptography, LLM features, desktop IPC and the build pipeline. Security-audit is unchanged.

## Upgrade notes for 0.8.0

Added security-gap-analysis with bundled ASVS 5.0.0, AISVS 1.01 and MASVS 2.1.0 catalogs (CC BY-SA 4.0) and `gap.py`, which keeps `requirements.csv`, the file ledger `files.csv` and the boundary inventory `inventory.csv` consistent and fails `check` while any of them is incomplete or stale.

## Upgrade notes for 0.7.0

Added Cloudflare's security-audit as a separate skill with its complete references, report schema, validators, tests, and MIT license. Its content is unchanged from the pinned upstream revision in SOURCES.md. Local-security-review remains available.

## Upgrade notes for 0.6.0

Security review: Semgrep now uses several registry packs plus bundled Rust rules instead of one checksum-pinned `security-audit` snapshot (that pin no longer matched the mutable registry URL, so setup failed on new machines). Run `security.py --setup` once to download the packs and the crates.io database. Rendering reads `assessments.json`, `groups.json` and `agent_findings.json` from the report folder and may be rerun. Setup and coverage references are merged into `setup.md` and `engines.md`.

## Upgrade notes for 0.5.0

The collection and plugin manifests now use `rasmus-agent-tools`. Update installations that refer to the previous plugin identity. Existing installed copies are not updated by a repository rename.

Security setup now uses `${XDG_CACHE_HOME:-~/.cache}/rasmus-security/`. Existing caches are left intact; run the documented setup checks and approve any needed installation before scanning. Test opt-ins are `AGENT_TOOLS_IAC_TEST_BINARY` and `AGENT_TOOLS_SCA_TEST_NETWORK`. Dependency versions and integrity pins are unchanged.

## Local adaptations

- Interview-me is a short product conversation. It asks one question at a time, uses a bounded question count, and keeps assumptions separate from requirements. It does not require a confidence score or a specification before implementation.

- TDD chooses existing public test boundaries without a mandatory approval interview. It confirms ambiguous behavior and material contract changes when needed.
- TDD allows small refactoring steps after tests pass.
- Prototypes can use a backend script. They retain a minimal check and data-safety boundaries. Branches and issue publication are not automatic.
- Doubt-driven development uses a bounded independent review. Repeated cross-provider prompts and upstream persona dependencies are removed.
- Review-bugs includes its review contract locally and points broad pre-commit reviews to code-validation. Its exploratory, report-only behavior is unchanged.
- QA is a standalone implementation of report-only verification, not the full gstack installation.
- ASD-STE100 uses the danyuchn implementation. Its structural linter does not certify compliance with ASD's licensed dictionary.
- Ponytail's skill is included; the upstream plugin's automatic activation hooks and optional audit commands are not bundled. Invoke Ponytail explicitly.

## Verification

Run the package checks and bundled security regression tests with a supported Python interpreter (Python 3.14 is used below):

```sh
python3 scripts/validate_package.py
python3.14 -m unittest discover -s test -v
python3 skills/asd-ste100/scripts/ste-lint.py --selftest
node --test skills/security-audit/*.test.cjs
npm ci --prefix skills/blueprint/scripts && npm test --prefix skills/blueprint/scripts
```

Security integration tests can skip when real scanners or databases are absent. Unit tests and package checks do not establish live scanner coverage or agent behavior. Real scans must follow the security skill's scope and permissions.

See [SOURCES.md](SOURCES.md) for provenance, adaptation details, and licenses.
