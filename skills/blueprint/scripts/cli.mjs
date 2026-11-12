#!/usr/bin/env node
// blueprint: evidence-backed architecture pages of a codebase or one feature. See README.md.
import {writeFileSync, mkdirSync, readFileSync, existsSync, rmSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import path from 'node:path';
import {homedir} from 'node:os';
import {scan, trace} from './scan.mjs';
import {brief, analyze, addView, sketch, options, recommend, update, cover, traceText} from './analyze.mjs';
import {check, readModel, readPage, pageWith, showText, noted, coverageProblems, stamp} from './model.mjs';
import {diffModels, gitChanges, owners} from './diff.mjs';
import {render, comparePage} from './render.mjs';
import {lint, describe} from './style.mjs';

const USAGE = `blueprint: architecture of a codebase, or one feature of it, as one HTML page

  blueprint build <repo> [--feature "TEXT"] [--trace "a,b"] [--complete] [--out FILE.html] [--ai claude|codex] [--model NAME]
      scan, analyse with Claude Code (or Codex) with all tools off, check every citation, render.
      Writes FILE.html and, beside it, FILE.model.json and FILE.facts.json. --trace: the analysis reads every
      file that names a term first, and check --complete then refuses a model that leaves one out.
      --complete: then blueprint cover, so the page accounts for every file of the repository.
  blueprint cover <page.html|model.json> --repo <repo> [--rounds N] [--ai claude|codex]
      the analyst reads every file the model has not accounted for, a budget of code at a time, and says what
      each adds: evidence for a part, a new part, or nothing, with the reason. Every round is checked against
      the code. The model and the page are written again and stamped, the old model kept as .model.bak.json.
      Exit 1 while check --complete still names a file: run it again.
  blueprint show <page.html> [ID…]
      the page as text, for the assistant that discusses it: the whole page in short, or the parts named, each
      with its connections, flow steps, what was said about it and the code it cites.
  blueprint note <page.html> "TITLE" [--detail TEXT] [--status open|decided|dropped] [--refs id,id] [--url URL]
      keeps a line of the discussion on the page: a question still open, a decision, something dropped. A note
      with a title the page has replaces it. With --url: a source that was read for the page. The page is
      changed in place, with no repository and no analyst, and the model beside it follows.
  blueprint trace <repo> TERM… [--in page.html|model.json]
      where the code names the terms ("auth0"), in code, settings, tests and documents, and the files that
      import those. With --in, which components of that model each file belongs to.
  blueprint scan <repo> [--feature "TEXT"] [--out facts.json]
      what the code says without a model: languages, manifests, infrastructure, routes, SDKs, imports.
  blueprint brief <repo> [--feature "TEXT"] [--no-excerpts]
      the instructions and facts an analyst gets; an agent that reads the code itself uses --no-excerpts.
  blueprint check <model.json|page.html> --repo <repo> [--complete]
      every reference resolves and every citation names lines that exist, and no stamped citation changed.
      --complete: also every file is cited or in the coverage ledger, every route, listener, program started
      and outgoing host is cited at its line or its file is marked read with the reason, and every file with
      another architecture signal is cited or marked read. Exit 1 with the problems.
  blueprint stamp <model.json|page.html> --repo <repo>
      records a hash of every cited span and ledger file, and the commit, so check names what changes later.
      A page is written again with its stamp.
  blueprint update <page.html|model.json> --repo <repo> [--since REF] [--ai claude|codex]
      brings a page up to date with code that changed after it was stamped: the analyst gets the model, what
      check says no longer holds, the git change since the stamp and the changed files, and corrects the
      model. The model and the page are written again and stamped, the old model kept as .model.bak.json.
  blueprint sketch "IDEA" [--from model.json|page.html] [--repo <repo>] [--trace "a,b"] [--options N]
                   [--research FILE] [--out FILE.html] [--ai claude|codex]
      the architecture an idea gives, as a proposal: planned, changed and removed parts over what is built,
      with pros, cons and migration steps. Without --from it starts from the code, or from a blank page.
      --from a proposal revises it. --trace (with --repo): the analyst gets every file that names a term,
      and the traced files the plan leaves out are counted here and listed on the page's Inventory tab.
      --options N: N architectures that differ in kind, each on its own page, and one page that compares them.
      --research FILE: what was read about how others solve this, with the addresses. The analyst builds on
      it and names its sources on the page. It has no web access: a source not in the file is refused.
  blueprint compare <page> <page> [<page>…] [--out FILE.html] [--recommend] [--ai claude|codex]
      proposals side by side: diagram, plan, for and against, steps. --recommend asks which to choose.
  blueprint diff <base> [<head>] [--repo <repo> --base-ref REF --head-ref REF] [--out FILE.html]
      one page of what the head adds, changes and removes against the base. base and head are pages or models,
      or REF:PATH for a page kept in the repository. With the refs, every component shows the code that changed
      under it, and a Changes tab lists every changed file.
      Without <head>: the page of --head-ref is made first, by blueprint update of the base against that
      branch's files. --base-ref is then the commit the base was stamped at, unless given.
  blueprint view <page.html|model.json> --repo <repo> --feature "TEXT" [--ai claude|codex]
      adds a feature view to a page: the feature followed through the code in more detail, with its own
      flows. The model and the page are written again, the old model kept as .model.bak.json.
  blueprint lint <model.json>
      the writing against ASD-STE100's structural rules, with the asd-ste100 skill's linter.
  blueprint render <model.json> --repo <repo> [--facts facts.json] [--out FILE.html] [--analyst NAME]
      the page, from a model that passes check.

  Without --out, a new page goes to ~/blueprint.
`;

// Where a page goes when --out does not say: outside every repository, so the analysed one is never written to.
const PAGES = path.join(homedir(), 'blueprint');

function flag(args, name) {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}

function slug(text) {
  return text.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 48);
}

/** The words after `from` up to the first flag. */
function words(args, from) {
  const end = args.findIndex((a, i) => i >= from && a.startsWith('--'));
  return args.slice(from, end < 0 ? undefined : end);
}

const terms = (args) => (flag(args, '--trace') ?? '').split(',').map((t) => t.trim()).filter(Boolean);
const short = (ref) => (/^[0-9a-f]{40}$/.test(ref ?? '') ? ref.slice(0, 7) : ref);

function write(file, text) {
  mkdirSync(path.dirname(path.resolve(file)), {recursive: true});
  writeFileSync(file, text);
}

async function main(args) {
  const [cmd, target] = args;
  const feature = flag(args, '--feature') ?? null;
  const say = (m) => process.stderr.write(`blueprint: ${m}\n`);
  switch (cmd) {
    case 'scan': {
      if (!target) throw new Error(USAGE);
      const facts = scan(target, {feature});
      const out = flag(args, '--out');
      if (out) { write(out, JSON.stringify(facts, null, 2)); say(`facts written to ${out}`); } else console.log(JSON.stringify(facts, null, 2));
      return 0;
    }
    case 'brief': {
      if (!target) throw new Error(USAGE);
      const facts = scan(target, {feature});
      if (terms(args).length) facts.trace = trace(target, terms(args));
      console.log(brief(facts, {feature, withExcerpts: !args.includes('--no-excerpts')}));
      return 0;
    }
    case 'trace': {
      const list = words(args, 2);
      if (!target || !list.length) throw new Error(USAGE);
      const found = trace(target, list);
      const within = flag(args, '--in');
      console.log(traceText(found, within ? readModel(within) : null));
      return found.files.length ? 0 : 1;
    }
    case 'check': {
      const repo = flag(args, '--repo');
      if (!target || !repo) throw new Error(USAGE);
      const model = readModel(target);
      const issues = check(model, {repoRoot: path.resolve(repo)});
      const complete = args.includes('--complete') ? coverageProblems(model, path.resolve(repo)) : [];
      const plan = [...model.nodes, ...model.edges].filter((x) => ['planned', 'changed', 'removed'].includes(x.status));
      if (plan.length) say(`${plan.length} parts are still a plan: ${plan.slice(0, 8).map((x) => `${x.id} (${x.status})`).join(', ')}${plan.length > 8 ? ', …' : ''}`);
      if (issues.length || complete.length) {
        console.log([...issues, ...complete].join('\n'));
        if (complete.length) say(`coverage: ${complete.length} problems; read what is listed, then cite it or add it to the model's "coverage" ledger`);
        return 1;
      }
      say(`the model holds: every reference resolves and every citation exists${args.includes('--complete') ? ', and every file is accounted for' : ''}`);
      return 0;
    }
    case 'stamp': {
      const repo = flag(args, '--repo');
      if (!target || !repo) throw new Error(USAGE);
      const root = path.resolve(repo);
      const page = readPage(target);
      if (page.diff) throw new Error(`${target} is a diff of two architectures, not the state of one: stamp its head`);
      const model = page.model;
      const issues = check(model, {repoRoot: root});
      if (issues.length) { console.log(issues.join('\n')); say('not stamped: fix the model first (blueprint update asks an analyst to)'); return 1; }
      stamp(model, root);
      const at = model.stamped.commit?.slice(0, 12) ?? 'a folder that is not a git repository';
      if (!target.endsWith('.html')) {
        write(target, JSON.stringify(model, null, 2));
        say(`stamped at ${at}; render the page again so it carries the stamp`);
        return 0;
      }
      // The page is the state: it is written again with the stamp, and the model beside it follows.
      const beside = target.replace(/\.html$/, '.model.json');
      if (existsSync(beside)) write(beside, JSON.stringify(model, null, 2));
      write(target, await render(model, {facts: scan(root, {feature: model.scope?.feature ?? null}), repoRoot: root, analyst: model.analyst ?? null}));
      say(`stamped at ${at}: ${target}`);
      return 0;
    }
    case 'update': {
      const repo = flag(args, '--repo');
      if (!target || !repo) throw new Error(USAGE);
      const root = path.resolve(repo);
      const base = target.replace(/(\.model)?\.(json|html)$/, '');
      const model = readModel(existsSync(`${base}.model.json`) ? `${base}.model.json` : target);
      const since = flag(args, '--since') ?? model.stamped?.commit;
      let changes = null;
      if (since) {
        try { changes = gitChanges(root, since, null); } catch (e) { say(`git shows no change from ${short(since)} (${e.message.split('\n')[0]}); going by the citations alone`); }
      } else say('the model carries no stamp, so new files are not known: only citations that no longer hold are corrected. Pass --since REF to give the change.');
      const next = await update(model, {repoRoot: root, changes, ai: flag(args, '--ai') ?? 'claude', model: flag(args, '--model') ?? null, say});
      stamp(next, root);
      write(`${base}.model.bak.json`, JSON.stringify(model, null, 2));
      write(`${base}.model.json`, JSON.stringify(next, null, 2));
      write(`${base}.html`, await render(next, {facts: scan(root, {feature: next.scope?.feature ?? null}), repoRoot: root, analyst: next.analyst ?? null}));
      const {counts} = diffModels(model, next);
      say(`up to date with ${next.stamped.commit?.slice(0, 12) ?? 'the folder'}: +${counts.added} added, ${counts.changed} changed, -${counts.removed} removed. ${base}.html (the model before it: ${base}.model.bak.json)`);
      return 0;
    }
    case 'cover': {
      const repo = flag(args, '--repo');
      if (!target || !repo) throw new Error(USAGE);
      const root = path.resolve(repo);
      const base = target.replace(/(\.model)?\.(json|html)$/, '');
      const model = readModel(existsSync(`${base}.model.json`) ? `${base}.model.json` : target);
      const drift = check(model, {repoRoot: root});
      if (drift.length) { console.log(drift.join('\n')); say('not covered: the model no longer holds against this code. Run blueprint update first.'); return 1; }
      const next = await cover(model, {repoRoot: root, rounds: Number(flag(args, '--rounds') ?? 12), ai: flag(args, '--ai') ?? 'claude', model: flag(args, '--model') ?? null, say});
      if (next === model) return 0;
      stamp(next, root);
      write(`${base}.model.bak.json`, JSON.stringify(model, null, 2));
      write(`${base}.model.json`, JSON.stringify(next, null, 2));
      write(`${base}.html`, await render(next, {facts: scan(root, {feature: next.scope?.feature ?? null}), repoRoot: root, analyst: next.analyst ?? null}));
      const {counts} = diffModels(model, next);
      const left = coverageProblems(next, root);
      say(`${left.length ? `${left.length} coverage problems are left (blueprint check --complete lists them)` : 'every file is accounted for'}: +${counts.added} added, ${counts.changed} changed. ${base}.html (the model before it: ${base}.model.bak.json)`);
      return left.length ? 1 : 0;
    }
    case 'show': {
      if (!target) throw new Error(USAGE);
      console.log(showText(readPage(target), words(args, 2)));
      return 0;
    }
    case 'note': {
      const title = args[2];
      if (!target || !title || title.startsWith('--')) throw new Error(USAGE);
      const entry = {title, detail: flag(args, '--detail') ?? null, status: flag(args, '--status') ?? 'open', refs: (flag(args, '--refs') ?? '').split(',').map((r) => r.trim()).filter(Boolean), url: flag(args, '--url') ?? null};
      const base = target.replace(/(\.model)?\.(json|html)$/, '');
      // The page and the model beside it each get the note: one of them may hold an edit the other has not seen.
      const files = [`${base}.html`, `${base}.model.json`].filter((f) => existsSync(f));
      if (!files.length) throw new Error(`${target}: no such page`);
      const next = files.map((f) => {
        const page = readPage(f);
        const model = noted(page.model, entry);
        return {f, model, text: f.endsWith('.html') ? pageWith(readFileSync(f, 'utf8'), {...page, model}) : JSON.stringify(model, null, 2)};
      });
      const issues = check(next[0].model).filter((p) => /^(discussion|sources)\[/.test(p));
      if (issues.length) { console.log(issues.join('\n')); say('not noted'); return 1; }
      for (const n of next) write(n.f, n.text);
      say(`${entry.url ? 'source' : entry.status} noted on ${files[0]}: ${title}`);
      return 0;
    }
    case 'sketch': {
      if (!target) throw new Error(USAGE);
      const repo = flag(args, '--repo');
      const from = flag(args, '--from');
      const base = from ? readPage(from) : null;
      const facts = repo ? scan(repo) : null;
      const out = flag(args, '--out') ?? path.join(PAGES, `sketch-${slug(target)}.html`);
      const name = out.replace(/\.html$/, '');
      const ai = flag(args, '--ai') ?? 'claude';
      const analyst = ai === 'codex' ? 'Codex' : 'Claude';
      const traced = terms(args);
      if (traced.length && !repo) throw new Error('--trace needs --repo: the terms are looked for in the code');
      const read = flag(args, '--research');
      // ponytail: the research is cut at 60 kB; a digest of it by the assistant when one topic needs more.
      const research = read ? readFileSync(read, 'utf8').slice(0, 60_000) : null;
      const how = {base: base?.model ?? null, facts: base ? null : facts, repoRoot: repo ? path.resolve(repo) : null, traced: traced.length ? trace(repo, traced) : null, research, ai, model: flag(args, '--model') ?? null, say};
      if (how.traced) say(`${how.traced.files.length} files name ${traced.join(', ')}; ${how.traced.dependents.length} more import one of those`);
      const page = async (model, file) => {
        model.analyst ??= analyst;
        model.repo ??= base?.repo;
        if (traced.length) model.trace = traced;
        write(file.replace(/\.html$/, '.model.json'), JSON.stringify(model, null, 2));
        write(file, await render(model, {facts, repoRoot: how.repoRoot, excerpts: repo ? null : base?.excerpts ?? {}, analyst: model.analyst}));
        // A quick sketch sees the lines that name a term, not every file whole: what it leaves out is said, not hidden.
        const left = traced.length ? coverageProblems(model, how.repoRoot).filter((p) => /the model traces/.test(p)).map((p) => p.split(':')[0]) : [];
        if (left.length) say(`${path.basename(file)}: the plan leaves out ${left.length} of the ${how.traced.files.length + how.traced.dependents.length} traced files (${left.slice(0, 4).join(', ')}${left.length > 4 ? ', …' : ''}); the Inventory tab and check --complete list them`);
      };
      const n = Number(flag(args, '--options') ?? 1);
      if (n >= 2) {
        const list = await options(target, n, how);
        const entries = [];
        for (const [i, o] of list.entries()) {
          await page(o.model, `${name}-${i + 1}.html`);
          entries.push({model: o.model, href: `${path.basename(name)}-${i + 1}.html`});
        }
        const text = await recommend(list.map((o) => o.model), {idea: target, ai, model: how.model}).catch((e) => { say(`no recommendation: ${e.message.split('\n')[0]}`); return null; });
        write(out, await comparePage(entries, {idea: target, recommendation: text, analyst}));
        say(`${list.length} proposals, compared in ${out}`);
        return 0;
      }
      const model = await sketch(target, how);
      await page(model, out);
      say(`sketch written to ${out}`);
      return 0;
    }
    case 'compare': {
      const pages = words(args, 1);
      if (pages.length < 2) throw new Error(USAGE);
      const out = flag(args, '--out') ?? path.join(PAGES, `compare-${slug(path.basename(pages[0]).replace(/(\.model)?\.(json|html)$/, ''))}.html`);
      const entries = pages.map((p) => ({model: readModel(p), href: path.relative(path.dirname(path.resolve(out)), path.resolve(p.replace(/\.model\.json$/, '.html')))}));
      const ai = flag(args, '--ai') ?? 'claude';
      const text = args.includes('--recommend') ? await recommend(entries.map((e) => e.model), {ai, model: flag(args, '--model') ?? null}) : null;
      write(out, await comparePage(entries, {recommendation: text, analyst: text ? (ai === 'codex' ? 'Codex' : 'Claude') : null}));
      say(`${entries.length} proposals compared in ${out}`);
      return 0;
    }
    case 'diff': {
      const head = args[2] && !args[2].startsWith('--') ? args[2] : null;
      const repo = flag(args, '--repo');
      const headRef = flag(args, '--head-ref');
      if (!target || (!head && !(repo && headRef))) throw new Error(USAGE);
      const a = readPage(target, {repo});
      const baseRef = flag(args, '--base-ref') ?? (head ? undefined : a.model.stamped?.commit);
      const label = (src, ref) => short(ref) ?? path.basename(src).replace(/(\.model)?\.(json|html)$/, '');
      const labels = {base: {label: label(target, baseRef)}, head: {label: label(head ?? '', headRef)}};
      const out = flag(args, '--out') ?? path.join(PAGES, `diff-${slug(labels.base.label)}-${slug(labels.head.label)}.html`);
      let b;
      if (head) b = readPage(head, {repo});
      else {
        // No page of the branch yet: the base is brought up to date with the branch's files. They are copied out of
        // git into the output folder, so the repository is only read and its working tree stays as it is.
        if (!baseRef) throw new Error(`${target} carries no stamp, so the commit it describes is not known: pass --base-ref, or run blueprint stamp on it at that commit`);
        const root = path.resolve(repo);
        const between = gitChanges(root, baseRef, headRef);
        const tree = path.resolve(path.dirname(out), `.tree-${slug(headRef)}`);
        const name = out.replace(/\.html$/, '.head');
        rmSync(tree, {recursive: true, force: true});
        mkdirSync(tree, {recursive: true});
        try {
          execFileSync('sh', ['-c', 'git -C "$1" archive "$2" | tar -x -C "$3"', 'sh', root, headRef, tree]);
          // Its own repository, so the files are listed by its own .gitignore and not by the one around the output folder.
          execFileSync('git', ['-C', tree, 'init', '-q']);
          const next = await update(a.model, {repoRoot: tree, changes: between, ai: flag(args, '--ai') ?? 'claude', model: flag(args, '--model') ?? null, say});
          stamp(next, tree);
          next.stamped.commit = between.headCommit;
          const facts = scan(tree);
          facts.repo = {...facts.repo, name: a.repo?.name ?? path.basename(root), remote: a.repo?.remote ?? null, commit: between.headCommit, branch: headRef, dirty: false};
          write(`${name}.model.json`, JSON.stringify(next, null, 2));
          write(`${name}.html`, await render(next, {facts, repoRoot: tree, analyst: next.analyst ?? null}));
          say(`the architecture at ${headRef}: ${name}.html`);
          b = readPage(`${name}.html`);
        } finally {
          rmSync(tree, {recursive: true, force: true});
        }
      }
      const {model, counts} = diffModels(a.model, b.model);
      const changes = repo && baseRef && headRef ? owners(model, gitChanges(path.resolve(repo), baseRef, headRef)) : null;
      const repoInfo = b.repo ?? a.repo ?? {};
      const diff = {...labels, counts, changes, repo: changes ? {...repoInfo, commit: changes.headCommit} : repoInfo};
      model.title = `${b.model.title}: ${diff.base.label} → ${diff.head.label}`;
      write(out, await render(model, {excerpts: {...a.excerpts, ...b.excerpts}, diff, analyst: b.model.analyst ?? null}));
      say(`+${counts.added} added, ${counts.changed} changed, -${counts.removed} removed${changes ? `; ${changes.files.length} files changed, ${changes.files.filter((f) => !f.owners.length).length} of them in no component` : ''}: ${out}`);
      return 0;
    }
    case 'view': {
      const repo = flag(args, '--repo');
      if (!target || !repo || !feature) throw new Error(USAGE);
      const base = target.replace(/(\.model)?\.(json|html)$/, '');
      const model = readModel(`${base}.model.json`);
      const facts = scan(repo, {feature});
      const merged = await addView(model, facts, {feature, ai: flag(args, '--ai') ?? 'claude', model: flag(args, '--model') ?? null, say});
      write(`${base}.model.bak.json`, JSON.stringify(model, null, 2));
      write(`${base}.model.json`, JSON.stringify(merged, null, 2));
      const allFacts = existsSync(`${base}.facts.json`) ? JSON.parse(readFileSync(`${base}.facts.json`, 'utf8')) : scan(repo);
      write(`${base}.html`, await render(merged, {facts: allFacts, repoRoot: path.resolve(repo), analyst: merged.analyst ?? null}));
      say(`view "${merged.views.at(-1).title}" added: ${base}.html`);
      return 0;
    }
    case 'lint': {
      if (!target) throw new Error(USAGE);
      const result = lint(readModel(target));
      if (!result) throw new Error('the asd-ste100 skill is not installed: set BLUEPRINT_STE_LINT to its scripts/ste-lint.py');
      console.log(`${result.words} words: ${result.hard.length} rule breaks, ${result.advisory.length} advisories`);
      if (result.hard.length || result.advisory.length) console.log(describe(result));
      return result.hard.length ? 1 : 0;
    }
    case 'render': {
      const repo = flag(args, '--repo');
      if (!target || !repo) throw new Error(USAGE);
      const model = readModel(target);
      const issues = check(model, {repoRoot: path.resolve(repo)});
      if (issues.length) { console.log(issues.join('\n')); say('not rendered: fix the model first (blueprint check)'); return 1; }
      const factsFile = flag(args, '--facts');
      const facts = factsFile ? JSON.parse(readFileSync(factsFile, 'utf8')) : scan(repo, {feature: model.scope?.feature ?? null});
      const out = flag(args, '--out') ?? target.replace(/(\.model)?\.(json|html)$/, '') + '.html';
      write(out, await render(model, {facts, repoRoot: path.resolve(repo), analyst: flag(args, '--analyst') ?? model.analyst ?? null}));
      say(`page written to ${out}`);
      return 0;
    }
    case 'build': {
      if (!target || !existsSync(target)) throw new Error(USAGE);
      const ai = flag(args, '--ai') ?? 'claude';
      const facts = scan(target, {feature});
      say(`scanned ${facts.repo.name}: ${facts.files} files, ${facts.infra.length} infrastructure resources, ${facts.signals.length} signals`);
      const traced = terms(args);
      if (traced.length) {
        facts.trace = trace(target, traced);
        say(`${facts.trace.files.length} files name ${traced.join(', ')}; ${facts.trace.dependents.length} more import one of those`);
      }
      const out = flag(args, '--out') ?? path.join(PAGES, `${slug(facts.repo.name)}${feature ? `-${slug(feature)}` : ''}.html`);
      const base = out.replace(/\.html$/, '');
      write(`${base}.facts.json`, JSON.stringify(facts, null, 2));
      let model = await analyze(facts, {feature, ai, model: flag(args, '--model') ?? null, say});
      model.analyst ??= ai === 'codex' ? 'Codex' : 'Claude';
      if (traced.length) model.trace = traced;
      if (args.includes('--complete')) {
        // The first model is kept before the reading starts: when the reading stops, blueprint cover continues from it.
        write(`${base}.model.json`, JSON.stringify(model, null, 2));
        model = stamp(await cover(model, {repoRoot: facts.repo.root, rounds: Number(flag(args, '--rounds') ?? 12), ai, model: flag(args, '--model') ?? null, say}), facts.repo.root);
      }
      write(`${base}.model.json`, JSON.stringify(model, null, 2));
      write(out, await render(model, {facts, repoRoot: facts.repo.root, analyst: model.analyst}));
      say(`page written to ${out}`);
      return 0;
    }
    default:
      console.log(USAGE);
      return cmd ? 1 : 0;
  }
}

main(process.argv.slice(2)).then((code) => process.exit(code), (e) => { process.stderr.write(`blueprint: ${e.message}\n`); process.exit(1); });
