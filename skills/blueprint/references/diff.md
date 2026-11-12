# Diff a branch

The diff page marks every part as added, changed or removed against a base page. A changed part shows the words that changed in its text and the patch of each file it cites. The Changes tab lists every changed file, with the files that no component cites last.

## Quick

`blueprint diff <base>.html --repo <repo> --head-ref <branch> --out <out>/<repo>-diff-<branch>.html` makes the branch's page from the branch's files in git and draws the diff. It leaves the repository's working tree alone, and the branch need not be checked out. The base ref is the commit the base page was stamped at, unless `--base-ref` names one. The branch's page stays as `<out>.head.html`.

## Deep, when the branch is large or the diff matters

1. Have a stamped page of the base (usually `main`).
2. Take the head's code into the output folder: `mkdir <out>/<branch>-src && git -C <repo> archive <branch> | tar -x -C <out>/<branch>-src`.
3. Copy the base model to `<out>/<repo>-<branch>.model.json` and run `blueprint check <out>/<repo>-<branch>.model.json --repo <out>/<branch>-src --complete`. It names what the branch moved or changed and the files it added. Read them and update the model to what the branch builds. Then check, stamp and render it with `--repo <out>/<branch>-src`.
4. Run `blueprint diff <base>.html <repo>-<branch>.html --repo <repo> --base-ref main --head-ref <branch> --out <out>/<repo>-diff-<branch>.html`.

## Either way

QA the diff page as in SKILL.md step 7. Report the counts, the parts that changed, and the changed files that no component cites: a large change there is a part the diagram misses.

To read the page with Rasmus: the What changed card lists every added, changed and removed part, and "Only changes" (or C) fades everything else.
