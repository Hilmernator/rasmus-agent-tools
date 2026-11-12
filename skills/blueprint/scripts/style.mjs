// Every text on a page is written in English, in the structural rules of Simplified Technical English (ASD-STE100):
// one idea per sentence, active voice, simple tenses, no semicolons, no phrasal verbs, verbs rather than nouns made
// from them, one name for one thing. The asd-ste100 skill's linter checks them; Blueprint runs it when it is
// installed and sends what it finds back to the analyst. It never flags hedges: "may" and "the code does not show"
// are content.
import {spawnSync} from 'node:child_process';
import {existsSync} from 'node:fs';
import {homedir} from 'node:os';
import path from 'node:path';

/** The linter's path, or null when the skill is not installed. */
export function linter() {
  const home = homedir();
  return [
    process.env.BLUEPRINT_STE_LINT,
    path.join(home, '.claude/skills/asd-ste100/scripts/ste-lint.py'),
    path.join(home, '.claude/rasmus-agent-tools/skills/asd-ste100/scripts/ste-lint.py'),
    path.join(home, '.codex/skills/asd-ste100/scripts/ste-lint.py'),
  ].find((p) => p && existsSync(p)) ?? null;
}

/** The prose of a model, each text with where it is. Labels are names, not sentences, and are left out. */
export function texts(model) {
  const out = [{where: 'summary', text: model.summary}];
  for (const n of model.nodes ?? []) {
    out.push({where: `nodes "${n.id}".responsibility`, text: n.responsibility});
    if (n.security) out.push({where: `nodes "${n.id}".security`, text: n.security});
  }
  for (const e of model.edges ?? []) if (e.detail) out.push({where: `edges "${e.id}".detail`, text: e.detail});
  for (const f of model.flows ?? []) {
    if (f.summary) out.push({where: `flows "${f.id}".summary`, text: f.summary});
    (f.steps ?? []).forEach((s, i) => out.push({where: `flows "${f.id}".steps[${i}].text`, text: s.text}));
  }
  for (const [k, list] of [['assumptions', model.assumptions], ['unknowns', model.unknowns]]) (list ?? []).forEach((t, i) => out.push({where: `${k}[${i}]`, text: t}));
  return out.filter((t) => typeof t.text === 'string' && t.text.trim());
}

/** Lints the model's prose. `hard` are the rules a rewrite must fix; `advisory` (passive voice, compound tenses)
 * are fixed where the actor is known. Null when the linter is not installed. */
export function lint(model) {
  const script = linter();
  if (!script) return null;
  const list = texts(model);
  // One text per line, so a finding's line says which text it is in.
  const input = list.map((t) => t.text.replace(/\s+/g, ' ').trim()).join('\n');
  const run = spawnSync('python3', [script, '--json'], {input, encoding: 'utf8'});
  let report;
  try { report = JSON.parse(run.stdout); } catch { return null; }
  const found = report.violations.map((v) => ({where: list[v.line - 1]?.where ?? `line ${v.line}`, rule: v.rule, match: v.match, message: v.message, hard: v.level === 'advisory-free'}));
  return {words: report.words, hard: found.filter((f) => f.hard), advisory: found.filter((f) => !f.hard)};
}

/** The findings as lines an analyst can act on. */
export function describe(result) {
  return [...result.hard, ...result.advisory].map((f) => `- ${f.where}: ${f.rule}${f.match ? ` ("${f.match}")` : ''}. ${f.message}`).join('\n');
}
