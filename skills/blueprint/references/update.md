# Keep a page in step with its code

The page embeds its whole model, so the HTML file is the state: `check`, `render`, `sketch --from` and `diff` read a page as well as a model file. `blueprint stamp` records a hash of every cited span and of every file in the ledger, and the commit. After that, `blueprint check <page>.html --repo <repo> --complete` names every citation whose code changed, every ledger file that changed, and every new file or signal nobody has read. A page is in step when that check passes.

## Deep

Run the check. Read what it lists and update the model. Then stamp and render again (SKILL.md, steps 5 to 8). `blueprint stamp <page>.html --repo <repo>` stamps a page in place.

## Quick

`blueprint update <page>.html --repo <repo> [--since REF]` has the analyst correct the model from what no longer holds and from the git change since the stamped commit (or `--since`). It writes the page and the model again and stamps them, and keeps the old model as `.model.bak.json`. Untracked new files are not in the git change, so run `check --complete` afterwards: it names them.

## A page kept in the repository

Only Rasmus decides to keep a page in the analysed repository (for example `docs/architecture.html`), so that each branch carries its own architecture. When he has, `diff` reads it as `main:docs/architecture.html`.
