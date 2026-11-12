# Hunt for what scanners miss

Scanners match patterns in one file. Real incidents usually come from missing authorization, logic errors and data flowing across files. Work the Entrypoints list in `context.md` in this order: what an attacker can reach without an account, then what any signed-in user can reach, then the most sensitive capabilities behind them. Mark each one `walked` or `not walked` with the reason as you go.

## Walk each reachable entrypoint

For each route, handler, server action, RPC method, queue consumer, CLI command, file importer, webhook, IPC channel and workflow trigger on the list, ask:

- **Who may call it, and is that enforced?** Missing authentication; authorization checked in the UI but not the handler; object IDs from the request used without an ownership check (IDOR); tenant ID taken from the client; admin routes reachable by normal users.
- **Where does each input end up?** Filesystem paths, SQL/NoSQL queries, shell commands, HTML/templates, outgoing URLs (SSRF, redirects), deserializers, regexes, response headers, log lines, a model prompt.
- **What can repeated or malformed calls do?** Unbounded body/upload sizes, missing rate limits on login/OTP/reset, panics or exceptions that crash the process, allocations sized by client input, race conditions on balances or quotas.
- **What does it reveal?** Stack traces, internal paths, user enumeration, tokens in URLs or logs, verbose errors.

## Entrypoints with their own questions

Read the part that fits what the list holds.

- **Webhooks and callbacks**: is the sender's signature verified before the body is parsed, with a constant-time comparison and a check against replay? Is the event trusted for more than it proves (an amount, an account ID)?
- **Uploads, imports and archives**: are size, type and count limited before the file is read? Is the stored name chosen by the server? Does extraction refuse entries that leave the target folder or expand without limit? Is a parsed file (image, video, document, project file) handed to a native decoder without limits?
- **Sessions, tokens and cryptography**: are tokens random from a secure source, long enough, expiring, and invalidated on logout and password change? Are passwords hashed with a password hash? Are comparisons of secrets constant-time? Is a key, salt or IV fixed in code? Are reset and invitation links single-use and bound to the account?
- **LLM and agent features**: which untrusted text reaches a prompt (user input, documents, web pages, tool results)? Where does model output go, and is it treated as untrusted there (HTML, SQL, shell, file paths, tool arguments)? Which tools can the model call, with whose permissions, and does a person approve the destructive ones? Can one user's data reach another user's context through memory, a cache or a shared index? Is spend bounded per user?
- **Desktop apps, local servers and IPC**: does a local port bind to every interface or only loopback, and does anything authenticate the caller? Can a web page in a browser on the same machine call it (origin check, CORS)? Do custom URL schemes, file associations and messages from a webview reach privileged code without validation? Are files written with predictable names in shared temporary folders?
- **Build and release**: can a pull request from outside run a workflow with secrets or write permission? Are actions, base images and downloaded tools pinned to a digest and verified? Do install or build scripts fetch and run code from the network? Can the published artefact be tied to the commit it came from? Is a long-lived credential used where a short-lived one would do?

## Check configuration once

CORS (any origin, credentials), CSRF on cookie-authenticated state changes, cookie flags, debug modes, default or hardcoded credentials, secrets in client bundles (`NEXT_PUBLIC_`, `VITE_`), JWT verification (decode without verify, `none`, weak secret), TLS verification disabled, permissive IAM or public buckets, containers running as root with mounted sockets.

Also look for copies outside the normal tree: ignored backups, database dumps, bare or nested Git repositories, exported data. Scanners skip or never see them; list them as coverage gaps and probe secrets in them with `secret_probe.py --file`.

## Language traps

The scanners cover these three languages best, so their traps are listed. In any other language, the four questions above still find the same classes of issue; say in the coverage gaps that no engine read that code.

- **Rust**: `unsafe` blocks (check invariants), `PathBuf::join` with absolute or `..` input, `unwrap`/`expect`/indexing on client data (one request kills a task or the process), `as` casts and arithmetic that overflow in release builds, lengths from input used for allocation, TOCTOU between check and file use.
- **JavaScript/TypeScript**: prototype pollution through merges, `dangerouslySetInnerHTML` and `innerHTML`, `eval`/`Function`, Next.js route handlers and server actions without auth checks, open redirects through `next`/`returnTo`, `child_process` with template strings.
- **Python**: `pickle`/`yaml.load`/`marshal`, `subprocess` with `shell=True`, SQL built with f-strings, `requests` with `verify=False`, Flask/Django debug and raw SQL, `tarfile`/`zipfile` extraction without path checks.

## Recording

Record only issues with a concrete location and a plausible attacker. Each gets an `AGENT-` entry in `agent_findings.json` and an assessment held to the same standard as scanner findings, including a local proof when feasible. Ideas you could not substantiate go in as `needs-review` with what is missing, not as confirmed issues. If a scanner already flagged the same root cause, assess it on that ID instead of duplicating it.
