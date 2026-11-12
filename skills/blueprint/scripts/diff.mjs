// Two architectures as one: what a branch, or a proposal, adds, changes and removes. diffModels() merges a base and a
// head model into one the page draws, every part marked by its change; gitChanges() reads the code changes between two
// git revisions, so the page shows beside each component the lines that changed under it.
import {execFileSync} from 'node:child_process';

// The fields that make a part different. Evidence counts by the files it cites: lines move with every edit.
const FIELDS = {
  zones: ['label', 'kind', 'parent', 'note'],
  nodes: ['label', 'kind', 'zone', 'service', 'tech', 'responsibility', 'security', 'status', 'plan'],
  edges: ['from', 'to', 'label', 'kind', 'protocol', 'detail', 'status', 'plan'],
  flows: ['title', 'summary', 'steps'],
};

const files = (x) => [...new Set((x.evidence ?? []).map((ev) => ev.path))].sort().join('\n');
const same = (a, b) => JSON.stringify(a ?? null) === JSON.stringify(b ?? null);

function changed(kind, a, b) {
  const out = FIELDS[kind].filter((f) => !same(kind === 'flows' && f === 'steps' ? a.steps?.map((s) => [s.edge, s.text]) : a[f], kind === 'flows' && f === 'steps' ? b.steps?.map((s) => [s.edge, s.text]) : b[f]));
  if (kind !== 'zones' && files(a) !== files(b)) out.push('evidence');
  return out;
}

/** One model with every part of `base` and `head`, each marked change: added, removed, changed (with `changed`, the
 * fields that differ, and `before`, the base's version) or nothing when it is the same. Removed parts keep the base's
 * place: their zone, their edges. */
export function diffModels(base, head) {
  const merged = {...head, scope: head.scope ?? base.scope};
  const counts = {added: 0, removed: 0, changed: 0};
  for (const kind of Object.keys(FIELDS)) {
    const before = new Map((base[kind] ?? []).map((x) => [x.id, x]));
    const after = new Map((head[kind] ?? []).map((x) => [x.id, x]));
    const list = [];
    for (const x of head[kind] ?? []) {
      const b = before.get(x.id);
      if (!b) { list.push({...x, change: 'added'}); if (kind !== 'zones') counts.added += 1; continue; }
      const fields = changed(kind, b, x);
      if (fields.length) { list.push({...x, change: 'changed', changed: fields, before: b}); if (kind !== 'zones') counts.changed += 1; } else list.push(x);
    }
    // A removed part goes back where it stood, so the diagram reads in the base's order.
    for (const x of base[kind] ?? []) {
      if (after.has(x.id)) continue;
      const i = (base[kind] ?? []).indexOf(x);
      const prev = (base[kind] ?? []).slice(0, i).reverse().find((y) => after.has(y.id));
      const at = prev ? list.findIndex((y) => y.id === prev.id) + 1 : 0;
      list.splice(at, 0, {...x, change: 'removed'});
      if (kind !== 'zones') counts.removed += 1;
    }
    merged[kind] = list;
  }
  // A view shows what it showed in either: a removed detail component stays in the view that named it.
  const headViews = new Set((head.views ?? []).map((v) => v.id));
  merged.views = [...(head.views ?? []).map((v) => ({...v, nodes: [...new Set([...v.nodes, ...((base.views ?? []).find((w) => w.id === v.id)?.nodes ?? [])])]})), ...(base.views ?? []).filter((v) => !headViews.has(v.id))];
  return {model: merged, counts};
}

/** The code changes from `base` to `head` in `repo`: one entry per file with its status, lines added and removed, and
 * the patch. `base...head` is what the head branch did since it left the base, as a pull request shows it. With no
 * head, the change from `base` to the files as they are now, uncommitted edits too.
 * ponytail: a new file git does not track yet is not in that change; git add -N it, or commit. */
export function gitChanges(repo, base, head) {
  const git = (args) => execFileSync('git', ['-C', repo, ...args], {maxBuffer: 512 * 1024 * 1024}).toString();
  const range = head ? `${base}...${head}` : base;
  const stats = new Map(git(['diff', '--numstat', '-M', range]).split('\n').filter(Boolean).map((l) => {
    const [a, d, ...rest] = l.split('\t');
    return [rest.join('\t').replace(/^.*=> /, '').replace(/[{}]/g, ''), {adds: Number(a) || 0, dels: Number(d) || 0, binary: a === '-'}];
  }));
  const out = [];
  for (const chunk of git(['diff', '--no-color', '-M', '-U3', range]).split(/^(?=diff --git )/m).filter(Boolean)) {
    const header = /^diff --git a\/(.+?) b\/(.+)$/m.exec(chunk);
    if (!header) continue;
    const path = header[2];
    const status = /^new file mode/m.test(chunk) ? 'added' : /^deleted file mode/m.test(chunk) ? 'deleted' : /^rename from/m.test(chunk) ? 'renamed' : 'modified';
    const lines = chunk.split('\n');
    const start = lines.findIndex((l) => l.startsWith('@@'));
    // ponytail: a patch is cut at 1500 lines per file; the page links to the whole file at the head commit for the rest.
    const body = start < 0 ? [] : lines.slice(start);
    out.push({path, from: header[1] !== path ? header[1] : undefined, status, ...(stats.get(path) ?? {adds: 0, dels: 0}), patch: body.slice(0, 1500).join('\n'), cut: body.length > 1500});
  }
  return {base, head, baseCommit: git(['rev-parse', base]).trim(), headCommit: git(['rev-parse', head ?? 'HEAD']).trim(), files: out};
}

/** For every changed file, the parts of the merged model that cite it: the components and connections it belongs to. A
 * changed file no part cites is a change the architecture does not show. */
export function owners(model, changes) {
  const byFile = new Map();
  for (const x of [...model.nodes, ...model.edges]) {
    for (const p of new Set([...(x.evidence ?? []), ...(x.before?.evidence ?? [])].map((ev) => ev.path))) {
      const l = byFile.get(p) ?? [];
      l.push(x.id);
      byFile.set(p, l);
    }
  }
  for (const f of changes.files) f.owners = [...new Set([...(byFile.get(f.path) ?? []), ...(f.from ? byFile.get(f.from) ?? [] : [])])];
  return changes;
}

