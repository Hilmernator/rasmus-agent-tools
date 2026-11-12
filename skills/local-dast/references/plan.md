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
- `expect_json`: a nonempty subset of expected top-level JSON fields. Values are compared including their top-level types. Returned values are never projected.
- `requires`: IDs of preceding cases that must pass without a coverage gap. Failed identity checks therefore prevent dependent access tests from running.
- `expect_text` and `forbid_text`: 1 to 20 short strings that the response body must contain, or must not contain. Use synthetic canaries (a fixture's title, another user's document ID): `forbid_text` is how a list or search case proves that the peer does not see the owner's rows. Only the boolean result is projected.
- `session`: a lowercase label. The cookies a response sets are kept in memory under that label and sent with every later case that names it. A login case and the cases of that identity share one label. Cookie values reach only the private HAR.

## State-changing cases

These fields are accepted only when the runner is started with `--allow-writes`; without it a plan that holds one is refused before the first request.

- `method`: `POST`, `PUT`, `PATCH` or `DELETE`. The default is `GET`.
- `json`: a nonempty object sent as the `application/json` request body.
- `json_env`: top-level body fields whose values come from `DAST_` environment variables, for a test account's password. The same rules as `headers_env` apply.

```json
{"id": "peer-login", "path": "/login", "method": "POST", "session": "peer",
 "json": {"email": "peer@test.invalid"}, "json_env": {"password": "DAST_PEER_PASSWORD"},
 "expect_status": [200, 303]},
{"id": "peer-cannot-delete-owner-document", "path": "/api/documents/synthetic-owner-document",
 "method": "DELETE", "session": "peer", "requires": ["owner-reads-document", "peer-login"],
 "expect_status": [403, 404]},
{"id": "owner-still-reads-document", "path": "/api/documents/synthetic-owner-document",
 "session": "owner", "requires": ["owner-login"], "expect_status": [200],
 "expect_text": ["synthetic-owner-document"]}
```

The example leaves out the owner's login and the owner's control read that its `requires` name. A denied write proves little by its status alone: follow it with a read by the owner that shows the object unchanged. A write changes the instance, so a second run meets a different state; reset the fixtures first. A request body is at most 64 KiB. Form-encoded bodies, multipart uploads and tokens returned in a response body are not supported: for those, mint the token with the app's own script in the disposable copy and pass it through `headers_env`.

A redirect is never followed. When the case lists the 3xx status as expected (a login that answers 303), the case passes and the report marks the redirect; an unexpected redirect is a failed assertion and a coverage gap.

Limits are 50 requests, 60 seconds for capture, at most 5 seconds per request, one MiB per response, and at least 0.5 seconds between completed requests. ZAP has an additional 120-second process limit. These are bounded request observations, not a crawler. There is no automatic retry, redirect following, DNS (except to resolve the one host of a remote run), environment proxy use or browser execution, and no cookie is kept outside a named `session`. A new run is a new budget; do not repeatedly rerun an inconclusive plan to evade it.

Run with the pinned archive, or explicitly use `--http-only` if ZAP is unavailable. The latter still evaluates cases but produces an incomplete result. Neither mode starts or stops the app, and its data changes only through the write cases the plan lists.

## Output

`report.json` and `review.md` contain case labels, methods, status codes, assertion booleans, hashes and numeric ZAP rule metadata. No response bodies, header values, raw URLs, alert descriptions or evidence strings are copied into these projections. IDs must themselves be non-sensitive labels. All ZAP alerts remain unreviewed until the agent assesses them.

ZAP instance URLs are mapped to `observed_cases` labels by method and URL, never printed. If multiple identities sent the same method to the same URL, `ambiguous_instances` records that the report cannot attribute the alert to one identity. `unmapped_instances` preserves missing associations. Use individual follow-up cases to resolve these; do not infer an offending identity from a shared URL. The original plan connects labels to routes.

The `private/` subdirectory contains the exact plan, HAR, ZAP plan, raw scanner report, log and ZAP session data. These are sensitive even when test accounts were used. Directories are private and files are restricted when run through the CLI. Do not publish them or add them to Git. They are retained for local investigation; deletion of the run directory is the retention boundary.

Map any assertion failure to source, the expected policy and reproducible behavior before calling it a vulnerability. Unexpected redirects, response limits, connection failures, unmet prerequisites and absent ZAP analysis remain explicit coverage gaps. A successful health request does not establish coverage of the rest of the app.
