---
name: review-bugs
description: Hunt bugs by exploring unusual states, invalid inputs, failure paths and recovery behavior in a repository or selected flow. Reproduce or trace defects and recommend fixes without editing code.
---

# Bug exploration

Read and follow the [review contract](references/review-contract.md).
Default scope: the current project; a supplied failure or flow narrows the search.

1. Map relevant states and transitions, invariants and external boundaries.
   Select failure scenarios grounded in reachable code: empty/malformed inputs,
   missing resources, partial writes, timeouts, retries, repeated requests,
   cancellation, concurrency or stale state where applicable.
2. Trace scenarios through all relevant callers. Exercise promising cases using
   existing tests or small temporary reproductions within authorized execution.
   Examine recovery and cleanup as well as the initial failure.
3. For each candidate, establish prerequisites and a concrete causal path. Check
   existing guards and tests that could disprove it. Keep unsupported suspicions
   separate from confirmed defects; do not require a quota of findings.
4. Report findings, attempted scenarios and remaining gaps. Suggest a fix at the
   shared root cause and a regression scenario in words; leave source untouched.

Prefer deeper investigation of reachable failures over a generic checklist of
hypothetical problems. This is exploratory bug hunting; use `code-validation` for a
broad pre-commit review that also covers maintainability.
