# Hunt for what scanners miss

Scanners match patterns in one file. Real incidents usually come from missing
authorization, logic errors and data flowing across files. Spend a bounded effort:
the entrypoints an attacker can reach first, then the most sensitive capabilities.

## Walk each reachable entrypoint

From `context.md`, list routes, handlers, server actions, RPC methods, queue
consumers, CLI commands, file importers and webhooks. For each one ask:

- **Who may call it, and is that enforced?** Missing authentication; authorization
  checked in the UI but not the handler; object IDs from the request used without an
  ownership check (IDOR); tenant ID taken from the client; admin routes reachable by
  normal users.
- **Where does each input end up?** Filesystem paths, SQL/NoSQL queries, shell
  commands, HTML/templates, outgoing URLs (SSRF, redirects), deserializers, regexes,
  response headers, log lines.
- **What can repeated or malformed calls do?** Unbounded body/upload sizes, missing
  rate limits on login/OTP/reset, panics or exceptions that crash the process,
  allocations sized by client input, race conditions on balances or quotas.
- **What does it reveal?** Stack traces, internal paths, user enumeration, tokens in
  URLs or logs, verbose errors.

## Check configuration once

CORS (any origin, credentials), CSRF on cookie-authenticated state changes, cookie
flags, debug modes, default or hardcoded credentials, secrets in client bundles
(`NEXT_PUBLIC_`, `VITE_`), JWT verification (decode without verify, `none`, weak
secret), TLS verification disabled, permissive IAM or public buckets, containers
running as root with mounted sockets.

Also look for copies outside the normal tree: ignored backups, database dumps, bare
or nested Git repositories, exported data. Scanners skip or never see them; list them
as coverage gaps and probe secrets in them with `secret_probe.py --file`.

## Language traps

- **Rust**: `unsafe` blocks (check invariants), `PathBuf::join` with absolute or `..`
  input, `unwrap`/`expect`/indexing on client data (one request kills a task or the
  process), `as` casts and arithmetic that overflow in release builds, lengths from
  input used for allocation, TOCTOU between check and file use.
- **JavaScript/TypeScript**: prototype pollution through merges, `dangerouslySetInnerHTML`
  and `innerHTML`, `eval`/`Function`, Next.js route handlers and server actions without
  auth checks, open redirects through `next`/`returnTo`, `child_process` with template
  strings.
- **Python**: `pickle`/`yaml.load`/`marshal`, `subprocess` with `shell=True`, SQL built
  with f-strings, `requests` with `verify=False`, Flask/Django debug and raw SQL,
  `tarfile`/`zipfile` extraction without path checks.

## Recording

Record only issues with a concrete location and a plausible attacker. Each gets an
`AGENT-` entry in `agent_findings.json` and an assessment held to the same standard as
scanner findings, including a local proof when feasible. Ideas you could not
substantiate go in as `needs-review` with what is missing, not as confirmed issues.
If a scanner already flagged the same root cause, assess it on that ID instead of
duplicating it.
