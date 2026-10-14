---
name: code-validation
description: Review uncommitted changes before commit without changing code. Use for pre-commit review, code validation, or finding defects in staged, unstaged, and relevant new files.
---

# Code Validation

Find concrete defects before commit. Inspect contracts, normal use, and relevant edge cases even when the user reports success. An untested path alone is not proof of a defect.

## Scope

- Analyze only. Preserve code, tests, configuration, the index, and working files. Do not commit, stash, reset, format, or apply fixes.
- Describe fixes in words. Return the report in chat unless the user requests a file.
- Review the requested repository and diff. Read callers, types, and tests as needed to assess impact. Keep repository-wide audits separate.
- Write in English unless the user requests another language.

## Gather evidence

1. Read applicable repository instructions. Use `git rev-parse --show-toplevel` to locate the repository. If needed, locate the intended repository or ask for its path. Do not initialize Git.
2. Read `git status --short --untracked-files=all`, `git diff --no-ext-diff --no-textconv`, and `git diff --cached --no-ext-diff --no-textconv`. Include staged and unstaged changes unless the user limits scope.
3. Inspect relevant untracked source files without staging them. Account for renames, deletions, and conflicts. Avoid generated files, binaries, and secret values; disclose material coverage gaps.
4. If a file has staged and unstaged edits, distinguish both versions. Use `git show :path` when the index version affects a finding. The next commit may not include the working copy.
5. Follow changed imports, contracts, data models, and callers until each suspected issue is supported or dismissed. Cite the version and lines actually inspected.

If there are no changes, say so. If the diff is too large or files are unavailable, report coverage and gaps without claiming a complete review.

## Review priorities

1. **Blocking failures:** crashes, import failures, broken contracts, runtime errors, and incompatible data models.
2. **Unexpected behavior:** logic defects, edge cases, incorrect defaults, silent failures, and missing error handling.
3. **Maintainability:** duplication, unnecessary complexity, misleading names, and excessive responsibility. Report concrete costs rather than style preferences.
4. **Performance:** repeated expensive work, large-file handling, and blocking operations that affect actual use. State the triggering workload. Separate measurements from hypotheses.

This order guides inspection. Severity follows impact; a performance defect can block normal use.

## Verification

- Report issues introduced or exposed by the change with a concrete failure scenario. Check surrounding safeguards before reporting.
- Separate confirmed defects, questions, and uncertainty.
- Static analysis is the default. Run existing relevant checks only after establishing that they will not change working files, the index, snapshots, databases, or external systems. Install nothing and use no auto-fix mode.
- State exactly which checks ran. A clean review is not proof that all behavior is correct.

## Report

Lead with findings ordered by severity. Each finding includes:

- Severity and a concrete title: critical, high, medium, or low.
- File and short line reference. Identify staged or working-copy evidence when relevant. Mark references to deleted code as the old version.
- Trigger, observed or traced failure, and impact.
- A short proposed correction in words.

Group findings with the same root cause. Follow with open questions, inspected scope, checks, and material limitations.

If no critical issues were found, state: **No critical issues were identified in the reviewed changes.** If there are no findings, say so without inventing improvements.
