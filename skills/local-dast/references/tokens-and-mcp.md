# Bearer tokens and MCP endpoints

Read this at step 4 when the app accepts bearer tokens that an identity provider issues (an OAuth authorization server, checked by the app itself or by a gateway's JWT authorizer), or when it serves an MCP endpoint over HTTP. The cases work on a local instance and in [remote mode](remote.md). A deployed gateway's authorizer exists only when deployed, so its cases belong to the remote run.

The questions come from the MCP authorization specification and its security best practices (version 2025-11-25): a server refuses a token that was not issued for it, answers 401 to an invalid or expired token and 403 to one without the scope, and tells an anonymous caller where its metadata is.

## Tokens that must be refused

Beside each identity's valid access token, these cases need tokens the endpoint must refuse. A plan cannot make them. The user, or their script, issues each one from the test identity provider and adds it to the identity file as a `DAST_` variable, the same way as the identities:

- an expired access token of a test account;
- an access token issued for another app client or audience of the same provider;
- an ID token of a test account, when the endpoint expects access tokens;
- an access token without the scope the route or tool needs.

A malformed token needs no issuer: `DAST_BROKEN_AUTH='Bearer not-a-token'`.

Each token the user cannot issue is a coverage gap in the delivery, with the question it would have answered.

## Cases

| Question | Case | Passes when |
| --- | --- | --- |
| Is the endpoint closed to the anonymous, and does it say where to sign in? | The protected route, or a `tools/list`, with no credential | 401. For an MCP server also `expect_headers` `{"WWW-Authenticate": "resource_metadata"}`, or the metadata case below passes |
| Is a broken or an expired token refused? | The malformed token; the expired token | 401 |
| Is a token made for something else refused? | The other client's or audience's token; the ID token | 401 or 403, and `forbid_text` finds no fixture value |
| Does a token without the scope stop there? | The token without the scope | 403; an MCP server should add `expect_headers` `{"WWW-Authenticate": "insufficient_scope"}` |
| Does the metadata name the right provider? | `GET` the metadata path with no credential: `/.well-known/oauth-protected-resource` followed by the endpoint's path (`/.well-known/oauth-protected-resource/mcp` for `/mcp`), or without it. Take the one the code serves; when the code is not at hand write both, and the one that answers 404 is no finding when the other passes | 200, and `expect_text` holds the issuer the user named for the test provider |
| Does each identity see only its own tools? | `tools/list` for each identity; its own tool in `expect_text` is the control | `forbid_text` finds no tool that belongs to another identity or role |
| Is a session tied to its identity? | On a server with sessions: a `tools/list` with the owner's `session` and the peer's `Authorization` | 400, 401, 403 or 404, and `forbid_text` finds no tool name |
| Can one identity use a tool on another's object? | Needs `--allow-writes`: a `tools/call` by the peer on the owner's object, with a tool the user has said is safe to call; the owner's own call is the control | The answer is an error and `forbid_text` finds none of the owner's values |

A tool call that is refused often answers 200 with the refusal in the body. Assert on the body: `"expect_json": {"result": {"isError": true}}` for a tool error, or the `code` of the JSON-RPC `error` object, as the server's code decides.

```json
{"id": "anonymous-cannot-list-tools", "path": "/mcp", "method": "POST",
 "headers_env": {"Accept": "DAST_MCP_ACCEPT"},
 "json": {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
 "expect_status": [401], "expect_headers": {"WWW-Authenticate": "resource_metadata"}},
{"id": "user-a-initialize", "path": "/mcp", "method": "POST", "session": "user-a",
 "headers_env": {"Accept": "DAST_MCP_ACCEPT", "Authorization": "DAST_USER_A_AUTH"},
 "json": {"jsonrpc": "2.0", "id": 2, "method": "initialize",
          "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "local-dast", "version": "1"}}},
 "expect_status": [200]},
{"id": "user-a-lists-own-tools", "path": "/mcp", "method": "POST", "session": "user-a", "requires": ["user-a-initialize"],
 "headers_env": {"Accept": "DAST_MCP_ACCEPT", "Authorization": "DAST_USER_A_AUTH"},
 "json": {"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
 "expect_status": [200], "expect_text": ["notes___read"], "forbid_text": ["admin___"]}
```

An MCP request carries an `Accept` header that names both `application/json` and `text/event-stream` (a server can answer 406 to one that names only the first), and often an `MCP-Protocol-Version` header. A plan sets a header only through `headers_env`, so put both in the identity file as `DAST_` variables, with the values the server's documentation gives: `DAST_MCP_ACCEPT='application/json, text/event-stream'`. The runner reads an event-stream answer by itself. A stream the server leaves open after its answer ends at the request limit as `incomplete`: report it as a coverage gap.

A server that keeps sessions answers `initialize` with an `Mcp-Session-Id` header and refuses a later request without it: a `tools/list` with a valid token that answers 400 is the sign. Give each identity an `initialize` case with a `session` label, as in the example, and name that label on the identity's later cases; the runner sends the ID on with them, as it does a cookie. A server without sessions (a gateway usually has none) answers the `tools/list` directly: leave the `initialize` case and the labels out.

Done when the anonymous case, the malformed-token case and each identity's control exist, and every token on the list above has its case or is named as a gap.

## What these cases leave out

- A token in the query string. The case would write a token into the plan; read the handler instead.
- Whether the gateway hands the caller's token on to the service behind it. That is in the gateway's configuration and the infrastructure code, and belongs to local-security-review.
- The service behind a gateway. It is another host: a second run, with that host named by the user.
- The identity provider's own endpoints (hosted sign-in, the token endpoint). They belong to the provider; its policy decides what may be tested, and guessing passwords or flooding is never part of this skill.
- Whether a session ID can be guessed, lockout and rate limits.
