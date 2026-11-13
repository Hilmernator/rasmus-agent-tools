# Request plans and evidence

The agent writes a plan after reading the relevant handlers. The plan is data; it cannot contain commands, launch hooks or external URLs. The one exception is the `target` of a [remote run](remote.md), which must equal the origin given to `--remote`. Keep it in a private temporary directory outside the target repo. Use synthetic IDs and expected values.

```json
{
  "target": "http://127.0.0.1:48173",
  "cases": [
    {"id": "anonymous-health", "path": "/health", "expect_status": [200]},
    {
      "id": "peer-identity",
      "path": "/api/me",
      "headers_env": {"Authorization": "DAST_PEER_AUTH"},
      "expect_status": [200],
      "expect_json": {"id": "synthetic-peer"}
    },
    {
      "id": "peer-cannot-read-owner-document",
      "path": "/api/documents/synthetic-owner-document",
      "headers_env": {"Authorization": "DAST_PEER_AUTH"},
      "requires": ["peer-identity"],
      "expect_status": [403, 404]
    }
  ]
}
```

Use the app's actual routes and policy. Add an owner identity and allowed-read control, and verify the fixture exists; otherwise a missing object can make an authorization test pass for the wrong reason. Each access case can depend on both the owner's successful read and the peer's identity check. For tests with a 200 response, assert concrete synthetic fields with `expect_json`.

Only `target` and `cases` are accepted at the top level. Cases require unique lowercase `id`, origin-relative ASCII `path`, and a nonempty array of expected status codes. Optional fields:

- `headers_env`: header names mapped to `DAST_` environment variable names. Supply complete header values via the process environment without printing them. Values must belong to disposable test accounts. Missing/invalid values reject the whole plan before the first request. Transport headers cannot be overridden.
- `expect_json`: a nonempty object of fields the answer must hold. A nested object is compared field by field, so `{"data": {"admin": false}}` passes when the answer's `data` has other fields as well; every other value, a list included, must be equal with the same type. An answer sent as `text/event-stream` (MCP's streamable HTTP) is read as the data of its last event that has any. Returned values are never projected.
- `requires`: IDs of preceding cases that must pass without a coverage gap. Failed identity checks therefore prevent dependent access tests from running.
- `expect_text` and `forbid_text`: 1 to 20 short strings that the response body must contain, or must not contain. Use synthetic canaries (a fixture's title, another user's document ID): `forbid_text` is how a list or search case proves that the peer does not see the owner's rows. Only the boolean result is projected, one for the whole list: put two texts in separate cases when it matters which of them was found.
- `expect_headers` and `forbid_headers`: 1 to 10 response header names, each mapped to a short text. `expect_headers` passes when the header is present and its value contains the text; `forbid_headers` passes when no such header contains it. An empty text means the header itself: present, or absent. Names and texts compare without regard to case. Use them for what an answer must announce (`{"WWW-Authenticate": "resource_metadata"}` on a 401) or must not serve (`{"Access-Control-Allow-Origin": "*"}`). Only the boolean result is projected.
- `session`: a lowercase label. The cookies a response sets are kept in memory under that label and sent with every later case that names it. A login case and the cases of that identity share one label. An `Mcp-Session-Id` header in a response is kept and sent on the same way. Cookie values and session IDs reach only the private HAR.
- `session_token`: on a case with a `session`, the field names that lead to a token in the JSON answer, such as `["data", "auth_token"]`. The token is kept in memory under the session's label and sent as `Authorization: Bearer <token>` with every later case of that session; a case's own `Authorization` from `headers_env` wins. The case fails its `token` check when the answer holds no token there, or one that could not stand in a header. The token reaches only the private HAR.

- `same_as`: the ID of one preceding case. The case passes its `same` check when its answer has the same status and the same body, byte for byte, as that case's answer. Use it for two answers that must not differ: a failed sign-in for an account that exists and for one that does not. An answer that carries a timestamp or a request ID never compares equal; assert on its text instead.
- `take`: 1 to 4 new names, each mapped to the field names and list positions that lead to a value in the case's JSON answer, such as `{"doc": ["data", "id"]}`. A later case uses the value by writing `{doc}` in its `path`, or as a whole JSON value in its `json` (there it keeps its type, so a number stays a number). Use it for an ID the app makes up: the owner creates an object, and the peer asks for it by the taken ID. A value is taken only when it is a whole number or a short text of letters, digits, `.`, `_`, `~` and `-` that does not start with a dot, so it can fill one path segment and nothing else. The case fails its `taken` check otherwise, and every case that names the value is `not-run` with the gap `value-not-taken`. Taken values reach only later requests and the private HAR.

```json
{"id": "owner-creates-document", "path": "/api/documents", "method": "POST", "session": "owner", "requires": ["owner-login"],
 "json": {"title": "synthetic-owner-title"}, "expect_status": [201], "take": {"doc": ["data", "id"]}},
{"id": "peer-cannot-read-created-document", "path": "/api/documents/{doc}", "session": "peer", "requires": ["peer-login"],
 "expect_status": [403, 404], "forbid_text": ["synthetic-owner-title"]}
```

Each row of `report.json` carries `body_sha256`, the hash of the answer's body, which is what `same_as` compares.

## State-changing cases

A case that changes state is accepted only when the runner is started with `--allow-writes`; without it a plan that holds one is refused before the first request.

One kind of `POST` counts as a read and needs no flag: a case whose whole `json` body is a single JSON-RPC 2.0 request with the method `initialize`, `ping`, `tools/list`, `resources/list` or `prompts/list`, and no `json_env`. That is how an MCP endpoint is asked what it offers. `tools/call` and every other method change state as far as the runner knows, and need the flag. The rule goes by the method's name, so inspect the handler first when the endpoint is not an MCP server, as for a `GET`.

- `method`: `POST`, `PUT`, `PATCH` or `DELETE`. The default is `GET`.
- `json`: a nonempty object sent as the `application/json` request body.
- `json_env`: top-level body fields whose values come from `DAST_` environment variables, for a test account's password. The same rules as `headers_env` apply.

```json
{"id": "peer-login", "path": "/login", "method": "POST", "session": "peer", "session_token": ["data", "auth_token"],
 "json": {"email": "peer@test.invalid"}, "json_env": {"password": "DAST_PEER_PASSWORD"},
 "expect_status": [200]},
{"id": "peer-cannot-delete-owner-document", "path": "/api/documents/synthetic-owner-document",
 "method": "DELETE", "session": "peer", "requires": ["owner-reads-document", "peer-login"],
 "expect_status": [403, 404]},
{"id": "owner-still-reads-document", "path": "/api/documents/synthetic-owner-document",
 "session": "owner", "requires": ["owner-login"], "expect_status": [200],
 "expect_text": ["synthetic-owner-document"]}
```

The example leaves out the owner's login and the owner's control read that its `requires` name. The login here answers with a token in its JSON; an app that sets a cookie needs no `session_token`, and its login may answer 303. A write's status proves little in either direction: a route can refuse and still have changed the object, or answer 204 to the peer and have changed only the peer's own record. Follow each peer write with a read by the owner that shows the object unchanged, and judge by that read. A write changes the instance, so a second run meets a different state; reset the fixtures first. A request body is at most 64 KiB.

A token lives as long as the app says. Put an identity's cases directly after its login when tokens are short-lived: each request is followed by a pause of half a second, so a plan of 50 cases takes at least 25 seconds.

Form-encoded bodies and multipart uploads are not supported. A login that needs one (an OAuth token endpoint takes a form) is done outside the runner: mint the token with the app's own script in the disposable copy, or in remote mode have the user sign the test account in, and pass the header through `headers_env`.

A redirect is never followed. When the case lists the 3xx status as expected (a login that answers 303), the case passes and the report marks the redirect; an unexpected redirect is a failed assertion and a coverage gap.

Limits are 50 requests, 60 seconds for capture, at most 5 seconds per request, one MiB per response, and at least 0.5 seconds between completed requests. ZAP has an additional 120-second process limit. These are bounded request observations, not a crawler. There is no automatic retry, redirect following, DNS (except to resolve the one host of a remote run), environment proxy use or browser execution, and no cookie is kept outside a named `session`. A new run is a new budget; do not repeatedly rerun an inconclusive plan to evade it.

Run with the pinned archive, or explicitly use `--http-only` if ZAP is unavailable. The latter still evaluates cases but produces an incomplete result. Neither mode starts or stops the app, and its data changes only through the write cases the plan lists.

## Output

`report.json` and `review.md` contain case labels, methods, status codes, assertion booleans, hashes and numeric ZAP rule metadata. `review.md` names the checks a case failed (`status`, `json`, `absent`, `taken`), so a failed case says which expectation did not hold. No response bodies, header values, raw URLs, alert descriptions or evidence strings are copied into these projections. IDs must themselves be non-sensitive labels. All ZAP alerts remain unreviewed until the agent assesses them.

ZAP instance URLs are mapped to `observed_cases` labels by method and URL, never printed. If multiple identities sent the same method to the same URL, `ambiguous_instances` records that the report cannot attribute the alert to one identity. `unmapped_instances` preserves missing associations. Use individual follow-up cases to resolve these; do not infer an offending identity from a shared URL. The original plan connects labels to routes.

The `private/` subdirectory contains the exact plan, HAR, ZAP plan, raw scanner report, log and ZAP session data. These are sensitive even when test accounts were used. Directories are private and files are restricted when run through the CLI. Do not publish them or add them to Git. They are retained for local investigation; deletion of the run directory is the retention boundary.

Map any assertion failure to source, the expected policy and reproducible behavior before calling it a vulnerability. Unexpected redirects, response limits, connection failures, unmet prerequisites and absent ZAP analysis remain explicit coverage gaps. A successful health request does not establish coverage of the rest of the app.
