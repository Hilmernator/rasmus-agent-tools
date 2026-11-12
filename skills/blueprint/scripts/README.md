# Blueprint

The architecture of a codebase, or of one feature in it, as one HTML page: drawn the way AWS, Azure and Google draw reference architectures, in Rasmus Hilmersson's design system, with the code behind every box and arrow.

```sh
npm ci        # once, in this folder
node cli.mjs build ~/code/some-repo --complete                        # the whole system, every file accounted for
node cli.mjs build ~/code/some-repo --feature "sign in with Auth0"    # one feature, end to end
node cli.mjs view ~/blueprint/some-repo.html --repo ~/code/some-repo --feature "document ingestion"   # add a feature view
node qa.mjs ~/blueprint/some-repo.html                           # check it in a browser
node cli.mjs check ~/blueprint/some-repo.html --repo ~/code/some-repo --complete   # every file accounted for, nothing drifted
node cli.mjs cover ~/blueprint/some-repo.html --repo ~/code/some-repo   # read what the page has not accounted for, and add it
node cli.mjs show ~/blueprint/some-repo.html orders-api          # a part as text, for the assistant that discusses the page
node cli.mjs note ~/blueprint/some-repo.html "Keep the session cookie?" --status open --refs web-client   # keep the discussion on the page
node cli.mjs trace ~/code/some-repo auth0 --in ~/blueprint/some-repo.html   # every file that names a thing, and who imports those
node cli.mjs sketch "move sign-in behind an identity adapter" --from ~/blueprint/some-repo.html   # a proposal over what is built
node cli.mjs sketch "replace Auth0" --from ~/blueprint/some-repo.html --repo ~/code/some-repo --trace auth0 --options 3 --research research.md   # three options built on what was read, and a page that compares them
node cli.mjs update ~/blueprint/some-repo.html --repo ~/code/some-repo   # bring a page up to date with the code
node cli.mjs diff ~/blueprint/some-repo.html --repo ~/code/some-repo --head-ref feature   # what a branch changes, in one command
node cli.mjs diff main.html feature.html --repo ~/code/some-repo --base-ref main --head-ref feature   # the same from two pages
```

Or ask Claude Code to "blueprint" a repository; the `blueprint` skill ([SKILL.md](../SKILL.md)) has the agent read the code itself, which goes deeper than `build`.

## The page

A large system reads in parts. The analysis divides it into **areas** by what each part is for (ingestion, retrieval, the agent, the API, the web client, identity, operations), lettered A, B, C, in the order data or a request moves through them. The views along the top of the diagram:

- **Overview**: each area as one box with its components' icons, and one arrow for all connections between two areas. Click a box to open the area.
- **Whole system**: every component, the areas drawn as labelled groups inside the zones where they run.
- **One view per area**: its components, with what it talks to faded around it.
- **Feature views**: a feature followed through the code in more detail, with components the system view leaves out. Ask for one with `blueprint view`, or ask Claude Code for a feature view of a blueprinted repository.

- **Architecture.** Components with their official AWS icons (or a line icon in the design system's style), grouped in zones for where they run: AWS Cloud, account, region, VPC and subnets with AWS's group icons, third-party SaaS, the user's device, local processes, trust boundaries. Connections are labelled with what crosses them; requests, events, identity and deployment look different. Pan, zoom, click anything.
- **Flows.** Numbered steps on the diagram, as in a reference architecture, with the step list beside it. Every step has an explanation for someone new to the system or the technique: what happens, why it is done this way and what would go wrong without it. It opens with the step, in the inspector and, presenting, under the caption with E. Step with ← and →, play with Space; in a large diagram the view follows the step. Every component, connection and step has a link of its own (`#node=…`, `#flow=…&step=3`).
- **Inspector.** A component's responsibility, security notes, what it calls and what calls it, and the cited lines of code, highlighted, with a link to them on GitHub at the analysed commit.
- **Sequence.** The selected flow as a sequence diagram, with what happens in each step written out beside it.
- **Inventory.** First what the analysis did not cite: the code modules and infrastructure files no box or arrow rests on, largest first, so a gap in the page shows. The header says how many modules it cites. Then what the scanner read from the code without any model: languages, manifests and dependencies, infrastructure resources, routes, SDK clients, model APIs, identity, outgoing hosts, environment variables, programs started, and a module import graph.
- **Evidence.** Every citation by file.

- **Ask about this.** The button or A copies a message for a coding assistant that names the page, the selected component, connection or flow step, and the command that reads it (`blueprint show`). The reader pastes it and adds a question, so "this one" means the same thing to both.
- **Discussion.** A card in the panel with the questions still open, the decisions and what was dropped, each linked to its parts, and the sources that were read for the page. `blueprint note` writes them into the page.
- **Coverage.** Under the title the page says "Complete coverage" or "Partial coverage: N places not accounted for", and the Inventory tab opens with the list.

- **Present.** The button or P puts the diagram full screen. → steps through the flows one after the other, the camera on each step and the step written large at the bottom; Escape leaves.

The page uses the whole screen, from a phone to an ultrawide monitor: the diagram and the evidence spread out on a wide screen. Below 2000 px the panel with flows and the inspector is a drawer over the diagram, so the diagram keeps the width; "Follow a flow…" stays in the diagram's corner. Touch screens pinch to zoom and pan with two fingers. When the overview is too small to read, the page says how to zoom in. `node screens.mjs PAGE.html` measures a page on eleven screens, from a phone to 5120 × 1440, and writes a screenshot of each. Dark and light themes follow the reader's setting and can be switched; AWS icons can be shown in AWS's colours or quietly in the theme's. Fonts and icons are embedded: the page works offline and prints.

## How it is made

1. **Scan** (`scan.mjs`): the facts above, each with file and line. No model.
2. **Analyse** (`analyze.mjs`): the brief, the facts and the most telling code (up to 220 kB, chosen from the scan; for a feature, its highest-ranked files first) go to Claude Code (`claude -p --tools ""`) or Codex (`--sandbox read-only`). The model writes the architecture as JSON and touches nothing.
3. **Write plainly** (`style.mjs`): every text is in English and in the structural rules of Simplified Technical English (ASD-STE100): one idea per sentence, active voice, simple tenses, no semicolons or phrasal verbs, one name for one thing. When the asd-ste100 skill is installed, its linter checks the model's prose and one more round asks for a rewrite of the sentences it flags; the rewrite is kept only if the architecture and every citation are unchanged and it breaks fewer rules. `blueprint lint MODEL.json` runs the same check.
4. **Check** (`model.mjs`): every reference must resolve, every citation must name a file of the repository and lines that exist, every component must be connected. The problems go back to the model, up to three rounds. A page is never drawn from a model that fails.
5. **Lay out** (`layout.mjs`): ELK's layered algorithm with nested zones and right-angled edges, in both directions, keeping the one that shows largest. Edge labels are placed afterwards where they cover nothing.
6. **Render** (`render.mjs`, `page.css`, `page.js`): the page, with the diagrams drawn as SVG on the server so it reads without scripts.

## Coverage, plans and diffs

- **Coverage.** `check --complete` holds a model to the whole repository, the way the security-gap-analysis skill holds its files.csv: every file is cited or in the model's `coverage` ledger (read, skimmed or skipped, with a reason). Every way in and out that has a name (a route, a listener, a program started, an outgoing host) is cited at a line it stands on, or its file is marked read with the reason: a file cited for one route does not hide the next. Every file with another architecture signal is cited or read. The scanner decides what exists; the model only says what it means. `cover` has the analyst read what is left, 220 kB a round, and add it to the model or to the ledger; it sends the listed files to the analyst CLI, which in a git repository never includes a git-ignored file. A page drawn with its repository states whether its coverage is complete or partial.
  The entry-point ledger follows Cloudflare's security-audit skill (MIT), which counts coverage in entry surfaces and sinks and not in files; no code is taken from it. The line rule stops at the four named kinds: measured on 2026-11-12 on the saved whole-system models, of the SDK, data, identity, model API and entry signals in cited files a citation spans 16 of 42 in aws-serverless-shopping-cart@66a863f and 89 of 249 in bedrock-chat@14e17cc, because the scanner finds the import and a model cites the call. On the first of those, `cover` read 37 files in one round (2 min 33 s) and added 1 component, 3 connections and 23 ledger entries (it also wrote 5 findings, which Blueprint no longer keeps), after which `check --complete` passed.
- **Traces.** `trace` finds every file that names a term ("auth0"), in code, settings, tests and documents, and every file that imports one of those (JavaScript, TypeScript and Python; one hop). A model that carries `"trace": ["auth0"]` must cite or mark read every file that names the term, and at least skim every importer, or `check --complete` refuses it. The scanner also reads routes and entry points of NestJS, tRPC, Spring, ASP.NET, Rails, Laravel, GraphQL and gRPC, schedulers, queues, and the variables and hosts in settings files. A real `.env` is never read, and a value in a settings file is never shown.
- **Stamps.** `stamp` records a hash of every cited span and ledger file, and the commit. `check` then names every citation whose code changed since, so a page that has drifted from its code says so. `update` has the analyst correct the model from what no longer holds and the git change since the stamp.
- **Plans.** Parts can be `planned`, `changed` (with `plan`) or `removed`, and a model can carry a `proposal` with problem, approach, pros, cons and migration steps. Planned parts need no evidence. `sketch` asks Claude Code or Codex for one, from a page, from the code or from a blank page; `--options N` asks for N that differ in kind, and `compare` sets proposals side by side on one page with a recommendation. `--research FILE` gives the analyst what an assistant read on the web, with the addresses; the analyst itself has every tool off, so the code it reads cannot leave through it, and a source that is not in the file is refused. A model keeps its `sources` and its `discussion` (open, decided, dropped), and the page shows them.
- **Diffs.** `diff` merges two pages or models into one page with every part marked added, changed or removed, the words that changed in its text, and, given a repository and two refs, the patch under every component and a Changes tab with the files no component cites. A card lists every change, "Only changes" fades the rest, and an area that holds a change is marked in the overview. Given one page and a branch, `diff` makes the branch's page itself from the branch's files in git. A page is its own state: every command reads a page as well as a model file, and `REF:PATH` reads a page kept in the repository.

What Blueprint does not do: it does not review security or code (findings were removed on 2026-11-12: Rasmus uses it for architecture, and security reviews have their own skills), it does not prove that what the code describes is deployed, read live configuration, or follow calls into other repositories. Those go in the page's unknowns. Complete coverage means that every file and every named way in and out has an owner or a reason; it does not mean that a second reader has checked the reasons.

## Files

`cli.mjs` commands, `scan.mjs` facts, `diff.mjs` diffs and git changes, `analyze.mjs` brief and model calls, `model.mjs` schema and evidence check, `layout.mjs` ELK and label placement, `icons.mjs` AWS and line icons, `render.mjs` the page, `page.css`/`page.js` its style and behaviour, `qa.mjs` the browser check, `screens.mjs` the screen sizes, `test/` the tests (`npm test`).

Design tokens are `tokens.json`, read by `rh.mjs` (`node rh.mjs --sync` copies them again from Rasmus's design system). AWS icons are in `../assets/svg` (the 48 px service icons and the group icons, provenance in its catalog) under the AWS Architecture Icons terms. Without `--out`, a new page goes to `~/blueprint`. ELK is EPL-2.0; Hanken Grotesk, Newsreader and JetBrains Mono are under the SIL Open Font License.
