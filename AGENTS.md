# Rasmus Agent Tools

Maintain this repository as the source of truth for the personal skill collection.

- Write instructions and documentation in English. Preserve precise technical terms and safety conditions.
- Prefer small working steps with concrete verification. Ask questions when the answer is necessary or a wrong assumption is costly.
- Inspect the diff before editing. Preserve unrelated changes.
- Keep each skill self-contained. References and scripts must resolve relative to the installed skill directory.
- Expose `local-security-review` for scanner-backed reviews and `security-audit` for source-first audits. Keep setup workflows as internal references and preserve all scanner safety, redaction, integrity, and license checks.
- Preserve source notices and document upstream versions and adaptations in SOURCES.md.
- Never commit scanner caches, downloaded rule sets, advisory databases, credentials, or scan reports.
- Run the README verification commands after package changes. State skips separately from passing tests.
- Changes to plugin manifests must retain the collection identity and keep the skill inventory accurate.
