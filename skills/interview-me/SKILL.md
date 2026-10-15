---
name: interview-me
description: Clarify a product's purpose and first useful step through a short interview. Use when the user asks for a product interview, discovery conversation, or overall product direction. Clear small features can proceed directly to implementation.
---

# Interview Me

Adapted from Addy Osmani for iterative product discovery. Establish enough direction to build and learn. Keep implementation choices open until evidence makes them necessary.

## Interview

1. Read the existing product brief and relevant conversation first. State your current understanding in one sentence. Reuse answers already available.
2. Ask one focused question at a time. Attach a tentative interpretation that the user can correct. Wait for their answer before the next question. Treat disagreement as useful evidence.
3. Focus on the intended user, their problem, a representative use case, the desired outcome, important constraints, and what is outside the first version. Ask about motivation or timing when it changes priorities. Turn vague goals into examples.
4. Match the depth to the work. For a new product, aim for four to six questions about its direction. For a small feature, ask zero to three necessary questions. Respect a shorter limit or a request to stop. Continue a deeper interview only when the user asks for it.
5. If the user needs to try something before answering, record an open question and propose a small experiment. Keep exploring other independent questions. Investigate technical facts yourself with authorized read-only tools.
6. End once the next useful step is clear or the question limit is reached. Summarize the current understanding and invite corrections. Accept clear natural-language agreement and delegated reversible choices. Preserve unresolved assumptions explicitly.

## Product overview

Return a short overview containing:

- User, problem, and intended outcome.
- A representative user flow and a way to evaluate success.
- Requirements the user has established, including safety and data constraints.
- Scope of the first version and exclusions.
- Current hypotheses and open questions, labeled separately from requirements.
- The next small experiment or working increment, with the evidence it should produce.

Use this as a living brief. Update hypotheses when tests or user feedback change the evidence. Ask before changing an established requirement when that change is outside the user's authorization.

Return the overview in chat unless saving it is requested or already authorized. If the repository has a product document, update that document rather than creating a competing specification. Follow the user's existing authorization for implementation; an interview alone does not authorize unrelated code changes or publication.

## Completion

The overview identifies the next step and distinguishes established requirements from assumptions. Unknowns remain visible. A formal specification, architecture diagram, confidence percentage, and exhaustive technical decision tree are optional and are not prerequisites for normal work.
