---
name: qa-only
description: Exercise a feature and report reproducible failures without fixing code. Use for functional verification, acceptance checks, or report-only QA of a browser, API, CLI, or background job.
---

# QA Only

A standalone workflow inspired by gstack's report-only QA. It uses the tools available in the current host and has no gstack runtime dependency.

1. Read the request, relevant repository instructions, and changed behavior. Identify the expected result from the user's examples, contracts, and existing documentation. Ask only when a missing expectation prevents a meaningful check.
2. Choose a representative normal flow, a relevant boundary case, and a failure or recovery case. Scale the checks to the change. State assumptions briefly and proceed with reversible local checks.
3. Inspect commands and fixtures before execution. Use a disposable local environment or test account. Follow existing authorization for network calls and state changes. Request permission before destructive actions, purchases, messages, production changes, or credential use outside scope.
4. Run the real entry point. For a UI, use the available browser tool and inspect visible behavior, console errors, and failed network requests. For an API, CLI, or job, use controlled inputs and verify outputs and side effects. A successful build or `--help` does not establish that the flow works.
5. Record commands or actions, input conditions, expected results, actual results, and evidence. Redact secrets. If a check fails, reproduce it where practical and identify the smallest triggering sequence. Do not fix code or alter tests to make the result pass.
6. Report findings by impact with reproduction steps and evidence locations. Separate product defects from environment failures and untested flows. State what passed, what failed, and what remains unknown.

Use existing test tools. Installation and changes to shared data require authorization. If a required environment or tool is unavailable, report the missing check instead of substituting static inspection and claiming runtime success.

Leave application files, the Git index, and existing artifacts unchanged. Store requested reports separately. Remove only temporary fixtures created by this run when safe and authorized.
