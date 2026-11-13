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
| [local-dast](skills/local-dast/SKILL.md) | Runtime security test of a locally running app, or of a pre-production deployment you name: planned HTTP cases with assertions, login sessions, state-changing cases against a disposable copy, ZAP passive analysis, fix plan | Collection-authored; ZAP downloaded separately, see SOURCES.md |
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

Four skills answer four different questions. Each runs on its own, and none replaces another.

| Question | Skill | It leaves behind |
| --- | --- | --- |
| Which known defect patterns, leaked secrets, vulnerable dependencies and misconfigured infrastructure are in the code, and which of them matter? | `local-security-review` | A fix plan and `review.md` in a private temporary folder; its rows in `security/findings.csv` |
| Which defects does a careful reader find without scanners? | `security-audit` | A structured report with a coverage ledger |
| Which controls should exist and do not? | `security-gap-analysis` | The repository's `security/` folder |
| What does the running application do when one user asks for or changes another's data, and what does its traffic give away? | `local-dast` | A fix plan and `review.md` in a private temporary folder; its rows in `security/findings.csv` |

No skill waits for another. When you do want a full pass over a repository, this order saves work, because each skill can start from what the one before left: `security-gap-analysis` first (its `security/profile.md` and inventory are a map the others can start from), then `local-security-review` with `release`, then `security-audit` in full mode when a second, independent reading is worth its cost, then `local-dast` on a disposable running copy to check at runtime what the source reading claims, and once more against the pre-production deployment before a release. Blueprint gives the same map as a picture when that helps. On unchanged code, one run of each is enough.

Each skill makes its own findings from the code or the running application. What they share is limited to two things. Before the work: the facts in `security/profile.md` and the inventory, which describe the product and not anyone's verdict. After the work: the findings ledger `security/findings.csv`, one row per finding, which `local-security-review` and `local-dast` open only when they deliver, to say whether a finding is new, was seen before, changed, or was decided by you. A label never changes a verdict, and each skill writes only its own rows. The `security/` folder holds seven fixed files and no file per run, and the scripts keep it out of commits through `.git/info/exclude` unless you track it yourself.

What no skill here covers: crawling, browser-driven journeys and active scanning of the running application (`local-dast` sends only the cases its plan lists), what is deployed but not reachable over HTTP (IAM policies, network rules, storage policies; `local-dast` in remote mode tests only what the deployed host answers), container images, dependencies outside npm, PyPI and crates.io, licence compliance of dependencies, and standards that are not bundled (CIS and cloud benchmarks, PCI DSS, ISO 27001, SOC 2, GDPR). No bundled standard covers the build and release pipeline; the gap analysis inventories it and reports what it finds as outside the selection.

Use `local-security-review`. The agent prepares the scanners with one command (`security.py --setup`), scans, maps the target, investigates every finding for reachability and impact (confirming it with a local regression test where practical), hunts for issues scanners miss, and returns a fix plan. Say "fix it" afterwards to apply the plan.

The default scope is full. Optional suffixes are `diff`, `commit [SHA]`, and `release`. Languages: Python, JavaScript/TypeScript and Rust source; npm, PyPI and crates.io dependencies; Terraform, CloudFormation, Dockerfile and Kubernetes; secrets in any file.

Python 3.10+ is required. Setup supports macOS and Linux; Windows requires WSL. The locked ESLint toolchain requires Node `^20.19.0 || ^22.13.0 || >=24`. Scanner binaries, advisory databases, and rule packs remain machine-local and are not committed here.

Review the [scanner licensing boundaries](skills/local-security-review/references/licensing.md) before setup.

Use [security-audit](skills/security-audit/SKILL.md) for source-first security guidance or an explicitly requested full codebase audit. Full audits use reconnaissance, coverage-led hunting, independent validation, and structured reports. The bundled validators use Node.js and have no external dependencies. Target-code execution requires the sandbox controls defined in the skill; if those controls are unavailable, validation remains blocked. Choose the workflow that answers the task rather than running both by default.

Use [security-gap-analysis](skills/security-gap-analysis/SKILL.md) to find controls that are missing rather than bugs in code that exists. It models the product, selects OWASP ASVS 5.0, AISVS 1.0 for LLM, agent, RAG and MCP features, and MASVS 2.1 for mobile apps, then records a status with `file:line` evidence for each requirement in the target repository's `security/` folder. Coverage is checked, not assumed: every file is listed and must be read, skimmed or skipped with a reason, and a fixed-pattern inventory of the ways in (servers, routes and serverless handlers, command lines, IPC, uploads), the effects outside the program (processes, network calls, data stores, model calls), the build and release pipeline, and the dangerous sinks must be placed in the profile or explained. A file that changes reopens itself and the rows that cite it. The requirement catalogs are bundled; `scripts/build_catalogs.py` rebuilds them from the pinned sources.

Use [local-dast](skills/local-dast/SKILL.md) to test a running application. The agent starts a disposable copy on 127.0.0.1 with synthetic data, writes a plan of cases from the code (who may read, list, change and delete what), and `dast.py` sends exactly those requests, checks each response against its assertion and has ZAP read the recorded traffic passively. A case can log in and keep its session, as a cookie or as a token taken from the login's answer, and a plan can hold `POST`, `PUT`, `PATCH` and `DELETE` cases, which run only with `--allow-writes`. A case can also assert on response headers, and the skill lists the cases for an app that takes bearer tokens from an identity provider or serves an MCP endpoint: the tokens that must be refused, and what each identity may list and call. It needs Python 3.10+, Java 17+ and the pinned ZAP archive, downloaded once as [its setup](skills/local-dast/references/setup.md) describes; ZAP is not bundled. It does not crawl, drive a browser or scan actively, and the runner cannot stop the application itself from reaching the network: the skill gives the macOS command that does. In remote mode (`--remote https://<host>`) the same runner tests one pre-production host that you name yourself: HTTPS on port 443 with the certificate verified, the same 50-request budget and pause, read cases unless you say the environment's data may be changed, and test accounts made for that environment. It is for what exists only when deployed, such as a gateway's authorizers, and it never targets production. The wider design, of which this is the first part, is in [the DAST proposal](docs/agent-powered-dast.md).

## Upgrade notes for 0.12.0

local-dast plans can say more. One change alters an existing plan's result: a nested object in `expect_json` is now compared field by field, where it had to equal the answer's object exactly; a plan that relied on exact equality of a nested object passes more easily, so name every field that matters. New optional case fields: `session_token` keeps a token from a login's JSON answer and sends it as `Authorization: Bearer` for that session, `expect_headers` and `forbid_headers` assert on response headers, `same_as` fails a case whose answer differs in status or body from a preceding case's, `take` keeps a value from a JSON answer and fills it into a later case's path or JSON body (an ID the app made up), and a `session` carries the `Mcp-Session-Id` a response sets to its later cases. `review.md` has a new column that names the checks a case failed. security-gap-analysis: `gap.py check --complete` now fails when `security/gaps.md` does not name every `missing`, `partial` and `unverifiable` row, so an existing folder may need its IDs written out; the inventory also finds uploaded-file reads, served files and request-header reads, which appear as new unreviewed lines. In the findings ledger a ZAP candidate is now one row per rule: ZAP names a different sample of cases on each run, so the cases are no longer part of the row's key. A ZAP row written by 0.10.0 or 0.11.0 gets a new fingerprint and its old row stays until you delete that line. An answer sent as `text/event-stream` is read as JSON from its last event. A `POST` whose whole body is one JSON-RPC 2.0 request with the method `initialize`, `ping`, `tools/list`, `resources/list` or `prompts/list` now counts as a read and runs without `--allow-writes`; every other `POST`, `tools/call` included, still needs the flag. The new [tokens and MCP reference](skills/local-dast/references/tokens-and-mcp.md) lists the cases for a JWT authorizer and an MCP endpoint. local-security-review's hunt now asks about writes that copy request fields onto a record and answers that serialise a whole record, and its investigation reference says how to judge a rule that claims a weakness and not a flow, so a weak hash or a cookie without its flags is not dismissed for lack of an exploit.

## Upgrade notes for 0.11.0

Added remote mode to local-dast. `dast.py --remote https://<host>` sends the plan to one pre-production host instead of a loopback port; the plan's `target` must be the same origin, so a plan alone can never choose a remote host. The connection is HTTPS on port 443 with certificate and hostname verified, and a certificate that fails is reported as `tls-certificate-not-verified` with no request sent. `report.json` has a new `target` field (`loopback` or `remote`) and never holds the hostname. The skill's [remote reference](skills/local-dast/references/remote.md) says what the user must state first and lists the authentication and authorization cases. The skill keeps its name. Nothing changes for local runs.

## Upgrade notes for 0.10.0

Added the findings ledger. `ledger.py record`, bundled with local-security-review and local-dast, keeps `security/findings.csv` in the reviewed repository and labels each finding of a run as new, seen before, changed or decided by you; `ledger.py decide` stores your own decision, which later runs show and never overwrite. The fingerprint follows the flagged text, not its line number, so a finding keeps its row when code above it moves; a renamed file gives new rows. Nothing of a secret is stored. A commit review is not recorded, only a complete full scan removes rows, and local-dast rows are never removed by a run.

`gap.py` now adds `security/` to `.git/info/exclude` when the folder is neither tracked nor already ignored, and `gap.py check` fails when `security/` holds a file that is not one of its seven. Move such a file out of the folder.

## Upgrade notes for 0.9.0

Added blueprint, moved here from the animation-engine repository. Its pages now go under `~/blueprint/`; pages made before the move stay where they were written and still open.

Added local-dast. It needs a ZAP archive and a Java runtime that the collection does not install; without them it runs only with `--http-only` and reports ZAP coverage as incomplete.

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

Security integration tests can skip when real scanners or databases are absent. For the DAST tests that run ZAP, set `AGENT_TOOLS_DAST_ZAP_ARCHIVE` to the pinned ZIP and `AGENT_TOOLS_DAST_JAVA` to an absolute Java executable path; without both they skip. The DAST tests start a server on a loopback port, which a host sandbox may have to permit; the remote-mode tests use the same server behind a throw-away certificate made with `openssl`, send nothing off the machine, and skip without an `openssl` binary. Unit tests and package checks do not establish live scanner coverage or agent behavior. Real scans must follow the security skill's scope and permissions.

See [SOURCES.md](SOURCES.md) for provenance, adaptation details, and licenses.
