---
name: architecture-review
description: Review technical architecture and teaching accuracy in saved Animation Engine diagrams, or apply review findings when explicitly asked. Use for correctness checks, misleading explanations, protocol and request flows, and fixing architecture-review findings. Not a repository code review or an audit of deployed infrastructure.
---

# Review or repair an animation's architecture

Work from the Animation Engine repository root. Read `AGENTS.md`, `docs/technical-review.md` and `docs/scene-format.md`. Use English unless another language is explicitly requested. The review method in `docs/technical-review.md` is also passed to the LLM launched by the studio's **Architecture review** button; keep that shared method authoritative.

## Choose the operation and saved revision

- A request to review, verify, explain findings or suggest improvements is review-only. Do not change the animation.
- A request to fix or apply findings authorizes targeted scene corrections. Preserve unrelated content, theme, IDs and intended duration. Optional design improvements are separate from correctness fixes; apply them only when included in the request.
- Use `npm run --silent engine -- library list` to identify the project. Retrieve it with `library get <id> --out .cache/<unique>.scene.json`; record revision N. If a specific historical revision is requested, retrieve it explicitly with `--revision N`. Ask only when the target or a material architecture choice cannot be determined from context.

## Review

1. Run `review prepare <id> --revision N --out .cache/<unique>.review.json`. This creates an unverified template and returns the exact scene; it does not call a model or establish correctness.
2. Follow the shared review method. Research and open primary sources, check the entire scene and every step, including text and visual message direction. Record configuration assumptions, acceptable simplifications, concrete corrections and optional improvements. Missing evidence stays `unverified`; a plausible diagram is not proof of a working deployment.
3. Fill the template, keeping its project ID, revision and scene hash. Save it with `review save <id> <report.json> --revision N`, then run `review check <id> --revision N`. A nonzero result for unresolved errors or uncertainty is a valid review outcome, not a reason to relabel the findings.
4. Deliver the status, most consequential findings, supporting sources and the studio link `http://127.0.0.1:<port>/?animation=<id>`. The report is stored in `reviews/<id>.r<N>.review.json`. Do not export a new video for review-only requests.

## Apply findings when requested

1. Retrieve the current scene and `review get <id> --revision N`. Use findings for that exact revision; if the review is missing or stale, review the current content first. Read the reasoning and sources rather than mechanically copying proposed wording. A missing fact may require a question or a narrower claim, not an invented architecture.
2. Correct the working scene's captions, roles, messages, directions or sequence as needed. Respect scene text limits and preserve unaffected content. Keep the target duration where possible without making text unreadable. Routine repairs change scene data, not renderer code or history files. Read `docs/animation-library.md` for revision operations.
3. Validate the draft and inspect representative frames, including changed message flows. Save a new revision with `library save <id> <scene.json> --expected-revision N --note "Correct architecture review findings"`. On conflict, reload and reapply only the intended changes; never overwrite newer work.
4. Review the resulting revision R afresh. Reuse still-current sources when appropriate, but assess all final wording and flows, including newly introduced claims. Do not transfer the old report's hash or mark findings resolved without checking the correction. Allow up to three repair/review attempts; preserve the draft and identify remaining uncertainty if it cannot be resolved.
5. Once `review check <id> --revision R` passes, export with `render @<id> --revision R --require-review --out output/<id>/rR/video.mp4`. Report what changed, remaining caveats, the new revision and preview/video links. Previous scene revisions remain available.

## How the button differs from a skill invocation

The skill is instructions for the agent handling this conversation. It does not launch a model by itself. The studio button calls a local server endpoint which launches `codex exec`, supplies the saved scene and shared review method, and validates/stores its JSON response. That separate run uses the local Codex sign-in, live web research and a read-only sandbox. It returns feedback only. Repairs currently run through this skill in the coding agent; there is no automatic repair button.
