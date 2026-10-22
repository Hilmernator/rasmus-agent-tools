# Investigate a finding

A scanner hit is a lead, not a verdict. For each candidate answer five questions,
with file:line evidence:

1. **What does the rule or advisory actually claim?** Read the rule (Semgrep packs
   are in `~/.cache/rasmus-security/semgrep/packs/`, bundled rules in
   `assets/semgrep/`) or the advisory link. Know the precise dangerous behavior.
2. **Where does the data come from?** Trace from the sink back to its sources
   across files: request params/body/headers, CLI args, files, env, database, other
   services. Note every validation, normalization and type conversion on the way.
3. **Who can reach it?** Use `context.md`: unauthenticated internet user, logged-in
   user, another tenant, local user, CI/build, the developer only. Test code and
   one-off scripts usually have no attacker; say so explicitly rather than assuming.
4. **What do existing controls stop?** Auth middleware, allowlists, framework
   escaping, parameterized APIs, canonicalize-and-check, size limits. Check that the
   control covers this exact path, at the sink, for every variant (absolute paths,
   encodings, redirects, alternative content types).
5. **What is the concrete impact?** Name the capability and the asset, for example
   "files outside `uploads/` that the service account can read become readable", not
   "path traversal risk". Describe the missing control and its consequence; there is
   no need to write out attack payloads.

## Confirm with a regression test

Write evidence the way a defensive engineer would: which input reaches which sink,
which check is missing, and a test that shows it. A test that fails today and passes
after the fix turns `likely` into `confirmed` and doubles as the fix's verification.
Prefer, in order: extending an existing test, a new unit test that calls the
function with a boundary input (for example a relative path that leaves the base
directory) and asserts it is rejected, or a check against a locally started
instance. Work in a temporary copy of the repository outside it (`cp -R`, or
`git clone --local` plus copied uncommitted files) with synthetic data, so the user's
tree, build output and data stay untouched. Never touch external hosts, real
credentials, or user data. Record the test and its result in `proof`. If proving
needs builds, services or time out of proportion, keep `likely` and say why. If a
build needs dependencies that are not cached locally, ask the user once whether
fetching them for the temporary copy is fine; otherwise prove at function level
(a small test file that includes only the vulnerable module; a minimal stub for a
third-party dependency is fine if it does not change the logic under test) or keep
`likely`. Reusing dependencies the project already installed is fine when you copy
them (an existing `node_modules`, or the project's virtualenv interpreter run with
`-I` against the copied tree); never symlink into the user's tree. Check early whether
an offline build works, and note when you use existing build output that is older
than the source.

## Verdicts

| Disposition | Use when |
| --- | --- |
| `confirmed` | You traced or proved a reachable, exploitable flow. |
| `likely` | The dangerous flow is plausible and nothing stops it, but a link is unproven (state which). |
| `false-positive` | You can name the guard, constant input or unreachable code that rules it out (high confidence only). |
| `needs-review` | Evidence is insufficient either way. Say exactly what would settle it. |

"Intentional", "in tests" or "validated" alone is not a dismissal: name the guard or
show the input is constant/synthetic.

Severity is your assessment, not the scanner's:

- **critical**: unauthenticated remote code execution, full data or credential
  compromise, auth bypass for admin.
- **high**: arbitrary file read/write/delete, SQL/command injection, auth bypass or
  cross-tenant access, live credential committed to git.
- **medium**: needs authentication or notable preconditions; limited data exposure;
  stored XSS; SSRF to internal metadata without credentials.
- **low**: hardening and defense in depth (permissive CORS without credentials, missing
  headers, panics that kill one request).
- **info**: no security impact in this context.

Rate the impact if the preconditions hold, then lower one level when exploitation
first needs another compromise (for example code execution on the host). A flow you
confirmed through a non-default exposure (a port bound to localhost) is still
`confirmed`; put the exposure in `preconditions` and let severity reflect it.

## Engine-specific shortcuts

**SCA.** Each finding carries the advisory `summary`, `fixed_versions` and, when the
same advisory appears under another database ID, `duplicate_of` (assess duplicates in
one `ids` entry with their original). Full advisory records are in the local
databases under `~/.cache/rasmus-security/sca/databases/`. Check the locked version
in the lockfile, whether it is runtime, build or dev, and for multi-environment
lockfiles (for example `uv.lock` resolution markers) which entry is actually used.

- Reachable or plausibly reachable at runtime: `likely`/`confirmed`, severity from
  the advisory and your trace. Spend tracing effort only when the upgrade is major or
  no fix exists.
- Cheap fix (patch/minor) but the vulnerable feature is not used: `likely` at `info`
  severity; it belongs in the routine update item, not a separate fix.
- Dev or build tooling that only processes developer-owned files: `false-positive`
  with that as the reason. Tooling that processes untrusted input (CI on pull
  requests, uploaded files) stays actionable.
- Unmaintained crate or package notices without a fix: `info`, recommend migration.
- An entry that is not installed in any supported environment: `false-positive`.

Group by root cause and fix: all advisories for one package version in one lockfile
form one issue; routine upgrades that one command fixes (`cargo update`,
`uv lock --upgrade`, `npm update`) may form one "update dependencies" issue across
packages in that lockfile, as long as every member is actionable.

**Secrets.** Run `scripts/secret_probe.py <report.json> SECRET-0001 ...` (add
`--history` to learn whether the value was ever committed). It returns only
booleans: placeholder, env reference, entropy, test path, tracked or ignored, and a
hint. Committed real-looking credentials: `confirmed`, rotate, and remove from
history if the repo is shared. Real values only in a git-ignored local file: `low`,
keep them out of git. Placeholders and env references: `false-positive` with the
probe result as evidence.

**IaC.** Check the resource and its policies, network paths and parameters. A missing
property is not proof of exposure; an assumed account-wide guard is not proof of
safety. For CDK, fix the construct, not the generated template.

**Noise classes.** Rules like Bandit `B101` (assert), ESLint
`detect-object-injection` or `detect-non-literal-fs-filename` in CLI tools are often
noise. Open enough instances to be sure the same reasoning holds, then assess the
whole class in one `ids` entry. Split out any instance where the input differs.

## Files

`assessments.json`: an array. Required: `id` (or `ids`), `disposition`,
`confidence` (`high|medium|low|unknown`), `assessed_severity`
(`critical|high|medium|low|info|unknown`), `evidence`, `recommendation`.
`confirmed`/`likely`/`false-positive` also need `evidence_refs`
(`[{"path": "src/a.rs", "line": 12}]`); `confirmed`/`likely` need `preconditions`
(attacker position and remaining assumptions, or "none"); `false-positive` needs
`dismissal_reason`. Optional: `proof`, `verify` (how to check the fix, ideally a test
name or command).

```json
[
  {"id": "SAST-0004", "disposition": "confirmed", "confidence": "high", "assessed_severity": "high",
   "evidence": "GET /get/:alias/*path passes path unchanged to PathBuf::join and fs::read_to_string; '..' segments and absolute paths escape uploads/.",
   "evidence_refs": [{"path": "src/handlers/read.rs", "line": 11}, {"path": "src/utils/file.rs", "line": 9}],
   "preconditions": "None: the route is unauthenticated and bound to localhost:3001; any local process or a browser via CORS can call it.",
   "proof": "Unit test rejects_paths_outside_base fails: read_drop accepts a path that resolves outside uploads/.",
   "recommendation": "Reject absolute paths and '..' components, canonicalize the joined path and require it to start with the canonical uploads/<alias> directory.",
   "verify": "cargo test rejects_paths_outside_base fails before and passes after the fix."},
  {"ids": ["SAST-0010", "SAST-0011", "SAST-0012"], "disposition": "false-positive", "confidence": "high",
   "assessed_severity": "info", "evidence": "All three are assert statements in pytest files.",
   "evidence_refs": [{"path": "tests/test_api.py", "line": 8}],
   "dismissal_reason": "Asserts only run in the test suite; production code does not rely on them.",
   "recommendation": "No change."}
]
```

`groups.json` (optional): `[{"title", "finding_ids": [two or more], "root_cause",
"evidence", "preconditions", "recommendation", "verify"?}]`. A group's `evidence`
replaces the members' text in the fix plan, so write the impact there; member proofs
are listed under it. A multi-ID `ids` assessment already renders as one issue, so
group only when members have separate assessments. Group only signals with
the same root cause and the same fix; members must not mix actionable and dismissed
verdicts.

`agent_findings.json` (from the hunt): `[{"id": "AGENT-0001", "title", "rule"
(category such as "idor"), "path", "line", "cwe"?}]`, each with an assessment entry.
