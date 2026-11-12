// The architecture model: what an analysis writes and the page draws. check() is the boundary: every reference must
// resolve, and every piece of evidence must name a file of the repository and lines that exist, so a page never shows a
// component or a step that the code was not read for. Its messages name the object, the field and the problem, so an
// agent can fix them.
import {readFileSync, existsSync, statSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import path from 'node:path';
import {listFiles, readText, signalsOf, trace} from './scan.mjs';

export const NODE_KINDS = ['user', 'client', 'web', 'mobile', 'cli', 'cdn', 'dns', 'firewall', 'gateway', 'loadbalancer', 'service', 'function', 'container', 'worker', 'scheduler', 'workflow', 'queue', 'stream', 'topic', 'database', 'cache', 'storage', 'search', 'identity', 'secret', 'key', 'llm', 'agent', 'tool', 'external', 'monitoring', 'pipeline', 'module', 'library', 'file', 'device', 'process'];
// Zones say where things run, except "area": a part of the system by what it is for (ingestion, retrieval, the agent,
// the API), which the overview draws as one box and which has a view of its own.
export const ZONE_KINDS = ['area', 'aws-cloud', 'account', 'region', 'vpc', 'public-subnet', 'private-subnet', 'cloud', 'saas', 'on-prem', 'device', 'client', 'runtime', 'process', 'trust-boundary', 'group'];
export const EDGE_KINDS = ['sync', 'async', 'data', 'auth', 'deploy', 'control'];
// What a part is in a plan: built (the default: the code shows it), planned (to be built: no evidence yet), changed
// (built, and the plan changes it: "plan" says how), removed (built, and the plan takes it away).
export const STATUSES = ['built', 'planned', 'changed', 'removed'];
// How much of a file the analysis looked at, recorded in the model's coverage ledger.
export const COVERAGE = ['read', 'skimmed', 'skipped'];
// What the reader and the assistant said over the page: a question still open, something decided, something dropped.
export const TALK = ['open', 'decided', 'dropped'];
const ID = /^[a-z][a-z0-9-]{0,63}$/;

function problems() {
  const list = [];
  const add = (where, message) => list.push(`${where}: ${message}`);
  return {list, add};
}

/** What a page or a model file holds: {model, excerpts?, repo?}. A page embeds its model, so the page alone is the
 * state. `source` is a file, or REF:PATH read from git in `repo` (a page kept in the repository, at a branch). */
export function readPage(source, {repo = null} = {}) {
  let text;
  if (existsSync(source)) text = readFileSync(source, 'utf8');
  else if (repo && /^[^:]+:.+/.test(source)) text = execFileSync('git', ['-C', repo, 'show', source], {maxBuffer: 256 * 1024 * 1024}).toString();
  else throw new Error(`${source}: no such file`);
  if (/^\s*</.test(text)) {
    const m = /<script type="application\/json" id="data">([\s\S]*?)<\/script>/.exec(text);
    if (!m) throw new Error(`${source}: a page with no embedded model`);
    return dropFindings(JSON.parse(m[1]));
  }
  try { return dropFindings({model: JSON.parse(text)}); } catch (e) { throw new Error(`${source}: not JSON: ${e.message}`); }
}

// Blueprint draws architecture only (decided 2026-11-12). A page made before then forgets its findings when it is read.
function dropFindings(data) {
  if (data?.model) delete data.model.findings;
  return data;
}

/** The text of a page with other data in it: the page is the state, so a note on it needs no new drawing. */
export function pageWith(text, data) {
  const at = /(<script type="application\/json" id="data">)[\s\S]*?(<\/script>)/;
  if (!at.test(text)) throw new Error('a page with no embedded model');
  return text.replace(at, (_, open, close) => open + JSON.stringify(data).replace(/</g, '\\u003c') + close);
}

/** Reads a model from a model file or a page, or throws with where the JSON is broken. */
export function readModel(source, options) {
  return readPage(source, options).model;
}

const sha = (text) => createHash('sha1').update(text).digest('hex').slice(0, 12);

/** The text a citation points at: its lines, or the whole file. */
function cited(repoRoot, ev, cache = new Map()) {
  if (!cache.has(ev.path)) cache.set(ev.path, readFileSync(path.join(repoRoot, ev.path), 'utf8'));
  const text = cache.get(ev.path);
  return ev.lines ? text.split('\n').slice(ev.lines[0] - 1, ev.lines[1]).join('\n') : text;
}

export function allEvidence(model) {
  return [...(model.nodes ?? []), ...(model.edges ?? []), ...(model.flows ?? []).flatMap((f) => f.steps ?? [])].flatMap((x) => x.evidence ?? []);
}

/** The components and connections that cite each file: path to their ids. */
export function citers(model) {
  const by = new Map();
  for (const x of [...model.nodes, ...model.edges]) {
    for (const p of new Set((x.evidence ?? []).map((ev) => ev.path))) by.set(p, [...(by.get(p) ?? []), x.id]);
  }
  return by;
}

function checkEvidence(list, where, evidence, repoRoot, lineCounts, {required}) {
  if (evidence === undefined || evidence === null) {
    if (required) list.add(where, 'evidence is required: at least one {path, lines:[start,end], why} that shows it in the code');
    return;
  }
  if (!Array.isArray(evidence)) return list.add(`${where}.evidence`, 'must be a list');
  if (required && evidence.length === 0) list.add(where, 'evidence is empty; cite the file and lines that show it');
  evidence.forEach((ev, i) => {
    const at = `${where}.evidence[${i}]`;
    if (!ev || typeof ev.path !== 'string' || !ev.path) return list.add(at, 'path is required, relative to the repository root');
    if (path.isAbsolute(ev.path) || ev.path.split('/').includes('..')) return list.add(at, `path "${ev.path}" must be relative to the repository and stay inside it`);
    if (repoRoot) {
      const full = path.join(repoRoot, ev.path);
      if (!existsSync(full) || !statSync(full).isFile()) return list.add(at, `"${ev.path}" is not a file of the repository`);
      if (ev.lines !== undefined) {
        if (!Array.isArray(ev.lines) || ev.lines.length !== 2 || !ev.lines.every(Number.isInteger) || ev.lines[0] < 1 || ev.lines[1] < ev.lines[0]) {
          return list.add(at, 'lines must be [start, end], 1-based, start <= end');
        }
        if (!lineCounts.has(ev.path)) lineCounts.set(ev.path, readFileSync(full, 'utf8').split('\n').length);
        const n = lineCounts.get(ev.path);
        if (ev.lines[1] > n) list.add(at, `lines ${ev.lines[0]}-${ev.lines[1]} run past the end of "${ev.path}", which has ${n} lines`);
        if (ev.lines[1] - ev.lines[0] > 400) list.add(at, `lines ${ev.lines[0]}-${ev.lines[1]} span more than 400 lines; cite the part that shows it`);
      }
      // A stamped citation whose code changed: the model may no longer say what the code does.
      if (ev.sha && (!ev.lines || ev.lines[1] <= lineCounts.get(ev.path)) && sha(cited(repoRoot, ev)) !== ev.sha) {
        list.add(at, `the code at ${ev.path}${ev.lines ? `:${ev.lines[0]}-${ev.lines[1]}` : ''} changed since the model was stamped; read it again, correct the model and run blueprint stamp`);
      }
    }
    if (ev.why !== undefined && typeof ev.why !== 'string') list.add(at, 'why must be text');
  });
}

/** Checks a model against the schema and, with `repoRoot`, its evidence against the repository. Returns the list of
 * problems; empty when the model can be drawn. */
export function check(model, {repoRoot = null} = {}) {
  const p = problems();
  const lineCounts = new Map();
  if (!model || typeof model !== 'object') return ['model: must be a JSON object'];
  for (const field of ['title', 'summary']) if (typeof model[field] !== 'string' || !model[field].trim()) p.add('model', `${field} is required text`);
  if (!model.scope || !['system', 'feature'].includes(model.scope.kind)) p.add('model.scope', 'kind must be "system" or "feature"');
  if (model.scope?.kind === 'feature' && !model.scope.feature) p.add('model.scope', 'feature names the feature traced');
  const ids = new Map();
  const claim = (id, where) => {
    if (typeof id !== 'string' || !ID.test(id)) return p.add(where, `id "${id}" must be lowercase letters, digits and hyphens, starting with a letter`);
    if (ids.has(id)) return p.add(where, `id "${id}" is also used by ${ids.get(id)}`);
    ids.set(id, where);
  };
  // A planned part has no code yet; every other part must show where it is in the code.
  const needs = (x) => (x?.status ?? 'built') !== 'planned';
  const statusOf = (x, at) => {
    if (x?.status !== undefined && !STATUSES.includes(x.status)) p.add(at, `status "${x.status}" is not one of ${STATUSES.join(', ')}`);
    if (x?.status === 'changed' && (typeof x.plan !== 'string' || !x.plan)) p.add(at, 'a changed part needs "plan": one sentence on how the plan changes it');
  };
  const zones = Array.isArray(model.zones) ? model.zones : [];
  const nodes = Array.isArray(model.nodes) ? model.nodes : [];
  const edges = Array.isArray(model.edges) ? model.edges : [];
  const flows = Array.isArray(model.flows) ? model.flows : [];
  if (!Array.isArray(model.nodes) || nodes.length === 0) p.add('model', 'nodes must list at least one component');
  zones.forEach((z, i) => {
    const at = `zones[${i}]${z?.id ? ` "${z.id}"` : ''}`;
    claim(z?.id, at);
    if (typeof z?.label !== 'string' || !z.label) p.add(at, 'label is required');
    if (!ZONE_KINDS.includes(z?.kind)) p.add(at, `kind "${z?.kind}" is not one of ${ZONE_KINDS.join(', ')}`);
  });
  const zoneIds = new Set(zones.map((z) => z?.id));
  zones.forEach((z, i) => {
    if (z?.parent === undefined || z?.parent === null) return;
    if (!zoneIds.has(z.parent)) p.add(`zones[${i}] "${z.id}"`, `parent "${z.parent}" is not a zone`);
    // A zone may not contain itself, however deep.
    const seen = new Set([z.id]);
    let up = z.parent;
    while (up) {
      if (seen.has(up)) { p.add(`zones[${i}] "${z.id}"`, 'zones contain each other in a circle'); break; }
      seen.add(up);
      up = zones.find((x) => x.id === up)?.parent;
    }
  });
  nodes.forEach((n, i) => {
    const at = `nodes[${i}]${n?.id ? ` "${n.id}"` : ''}`;
    claim(n?.id, at);
    if (typeof n?.label !== 'string' || !n.label) p.add(at, 'label is required');
    if (!NODE_KINDS.includes(n?.kind)) p.add(at, `kind "${n?.kind}" is not one of ${NODE_KINDS.join(', ')}`);
    if (n?.zone !== undefined && n?.zone !== null && !zoneIds.has(n.zone)) p.add(at, `zone "${n.zone}" is not a zone`);
    if (typeof n?.responsibility !== 'string' || !n.responsibility) p.add(at, 'responsibility is required: one sentence on what it does here');
    // People and outside services are known from how the code reaches them, so their evidence is the calling code.
    statusOf(n, at);
    checkEvidence(p, at, n?.evidence, repoRoot, lineCounts, {required: !['user'].includes(n?.kind) && needs(n)});
  });
  const nodeIds = new Set(nodes.map((n) => n?.id));
  edges.forEach((e, i) => {
    const at = `edges[${i}]${e?.id ? ` "${e.id}"` : ''}`;
    claim(e?.id, at);
    if (!nodeIds.has(e?.from)) p.add(at, `from "${e?.from}" is not a node`);
    if (!nodeIds.has(e?.to)) p.add(at, `to "${e?.to}" is not a node`);
    if (e?.from === e?.to) p.add(at, 'from and to are the same node');
    if (e?.kind !== undefined && !EDGE_KINDS.includes(e.kind)) p.add(at, `kind "${e.kind}" is not one of ${EDGE_KINDS.join(', ')}`);
    if (typeof e?.label !== 'string' || !e.label) p.add(at, 'label is required: what goes across, in a few words');
    statusOf(e, at);
    checkEvidence(p, at, e?.evidence, repoRoot, lineCounts, {required: needs(e)});
    for (const end of [e?.from, e?.to]) {
      if (nodes.find((x) => x?.id === end)?.status === 'planned' && needs(e)) p.add(at, `connects "${end}", which is planned, so it is planned too: set "status": "planned"`);
    }
  });
  const edgeIds = new Set(edges.map((e) => e?.id));
  flows.forEach((f, i) => {
    const at = `flows[${i}]${f?.id ? ` "${f.id}"` : ''}`;
    claim(f?.id, at);
    if (typeof f?.title !== 'string' || !f.title) p.add(at, 'title is required');
    if (!Array.isArray(f?.steps) || f.steps.length === 0) return p.add(at, 'steps must list at least one step');
    f.steps.forEach((s, j) => {
      const st = `${at}.steps[${j}]`;
      if (!edgeIds.has(s?.edge)) p.add(st, `edge "${s?.edge}" is not an edge; a step follows one edge of the diagram`);
      if (typeof s?.text !== 'string' || !s.text) p.add(st, 'text is required: what happens in this step');
      if (s?.explain !== undefined && (typeof s.explain !== 'string' || !s.explain.trim())) p.add(st, 'explain must be text: what happens and why, for someone new to it');
      checkEvidence(p, st, s?.evidence, repoRoot, lineCounts, {required: false});
    });
  });
  const flowIds = new Set(flows.map((f) => f?.id));
  (Array.isArray(model.views) ? model.views : []).forEach((v, i) => {
    const at = `views[${i}]${v?.id ? ` "${v.id}"` : ''}`;
    claim(v?.id, at);
    if (typeof v?.title !== 'string' || !v.title) p.add(at, 'title is required');
    if (!Array.isArray(v?.nodes) || v.nodes.length < 2) p.add(at, 'nodes must list at least two components to show');
    for (const id of v?.nodes ?? []) if (!nodeIds.has(id)) p.add(at, `nodes "${id}" is not a node`);
    for (const id of v?.flows ?? []) {
      if (!flowIds.has(id)) { p.add(at, `flows "${id}" is not a flow`); continue; }
      const shown = new Set(v.nodes ?? []);
      for (const s of flows.find((f) => f.id === id).steps) {
        const e = edges.find((x) => x?.id === s?.edge);
        if (e && (!shown.has(e.from) || !shown.has(e.to))) p.add(at, `flow "${id}" steps over edge "${e.id}", whose ends are not both in the view`);
      }
    }
  });
  // A detailed component is shown only in the views that name it, so it must be in one.
  const inView = new Set((model.views ?? []).flatMap((v) => v?.nodes ?? []));
  nodes.forEach((n, i) => { if (n?.detail && !inView.has(n.id)) p.add(`nodes[${i}] "${n.id}"`, 'is detail but in no view; add it to a view or drop "detail"'); });
  if (model.coverage !== undefined && !Array.isArray(model.coverage)) p.add('model', 'coverage must be a list of {path, status, why}');
  (Array.isArray(model.coverage) ? model.coverage : []).forEach((c, i) => {
    const at = `coverage[${i}]${c?.path ? ` "${c.path}"` : ''}`;
    if (typeof c?.path !== 'string' || !c.path || path.isAbsolute(c.path) || c.path.split('/').includes('..')) return p.add(at, 'path is a file or folder relative to the repository, or "."');
    if (!COVERAGE.includes(c.status)) p.add(at, `status "${c.status}" is not one of ${COVERAGE.join(', ')}`);
    if (c.status !== 'read' && (typeof c.why !== 'string' || !c.why)) p.add(at, `${c.status} needs "why": what was looked for, or why it is left out`);
    if (!repoRoot || c.path === '.') return;
    const full = path.join(repoRoot, c.path);
    if (!existsSync(full)) return p.add(at, `"${c.path}" is not in the repository`);
    if (c.sha && statSync(full).isFile() && sha(readFileSync(full, 'utf8')) !== c.sha) p.add(at, `"${c.path}" changed since it was marked ${c.status}; read it again, update the model and run blueprint stamp`);
  });
  if (model.trace !== undefined && (!Array.isArray(model.trace) || !model.trace.every((t) => typeof t === 'string' && t.trim().length >= 3))) p.add('model', 'trace must be a list of terms of three letters or more, e.g. ["auth0"]');
  // The discussion over the page, and what was read outside the code. A source is a link a reader may follow, so it
  // is a web address and nothing else.
  for (const field of ['discussion', 'sources']) if (model[field] !== undefined && !Array.isArray(model[field])) p.add('model', `${field} must be a list`);
  (Array.isArray(model.discussion) ? model.discussion : []).forEach((d, i) => {
    const at = `discussion[${i}]`;
    if (typeof d?.title !== 'string' || !d.title.trim()) p.add(at, 'title is required: the question or what was decided, in one sentence');
    if (!TALK.includes(d?.status)) p.add(at, `status "${d?.status}" is not one of ${TALK.join(', ')}`);
    for (const ref of d?.refs ?? []) if (!ids.has(ref)) p.add(at, `refs "${ref}" is not a part of the model`);
  });
  (Array.isArray(model.sources) ? model.sources : []).forEach((s, i) => {
    if (typeof s?.title !== 'string' || !s.title.trim()) p.add(`sources[${i}]`, 'title is required');
    if (typeof s?.url !== 'string' || !/^https?:\/\/\S+$/.test(s.url)) p.add(`sources[${i}]`, `url "${s?.url}" must be an http or https address`);
  });
  for (const field of ['assumptions', 'unknowns']) {
    if (model[field] !== undefined && (!Array.isArray(model[field]) || !model[field].every((x) => typeof x === 'string'))) p.add('model', `${field} must be a list of text`);
  }
  // Every node should take part: a component with no connection is usually one the analysis forgot to wire.
  const linked = new Set(edges.flatMap((e) => [e?.from, e?.to]));
  if (nodes.length > 1) nodes.forEach((n, i) => { if (n?.id && !linked.has(n.id)) p.add(`nodes[${i}] "${n.id}"`, 'has no edge; connect it or leave it out'); });
  return p.list;
}

/** The source lines each piece of evidence cites, keyed "path:start-end", for the page to show. Long spans are cut
 * to their first 60 lines. */
export function excerpts(model, repoRoot) {
  const out = {};
  const cache = new Map();
  for (const ev of allEvidence(model)) {
    if (!ev.lines) continue;
    const key = `${ev.path}:${ev.lines[0]}-${ev.lines[1]}`;
    if (out[key]) continue;
    if (!cache.has(ev.path)) cache.set(ev.path, readFileSync(path.join(repoRoot, ev.path), 'utf8').split('\n'));
    const lines = cache.get(ev.path);
    const end = Math.min(ev.lines[1], ev.lines[0] + 59);
    out[key] = {path: ev.path, start: ev.lines[0], end: ev.lines[1], text: lines.slice(ev.lines[0] - 1, end).join('\n'), cut: end < ev.lines[1]};
  }
  return out;
}

/** A page as text for the assistant that discusses it with its reader. With no ids: the whole page in short. With ids:
 * each part with its connections, the flow steps through it, what was said about it, and the code it cites,
 * so an answer about a part starts from what the page claims and the lines that back it. */
export function showText(page, ids = []) {
  const m = page.model;
  const all = new Map(['zones', 'nodes', 'edges', 'flows'].flatMap((list) => (m[list] ?? []).map((x) => [x.id, {...x, list}])));
  const name = (id) => all.get(id)?.label ?? all.get(id)?.title ?? id;
  const mark = (x) => (x.status && x.status !== 'built' ? ` [${x.status}${x.plan ? `: ${x.plan}` : ''}]` : '');
  const edge = (e) => `- ${e.id}: ${name(e.from)} -> ${name(e.to)}: ${e.label}${e.protocol ? ` (${e.protocol})` : ''}${mark(e)}`;
  const said = (list) => list.map((d) => `- (${d.status}) ${d.title}${d.detail ? `\n  ${d.detail}` : ''}${d.refs?.length ? `\n  about: ${d.refs.join(', ')}` : ''}`);
  const block = (title, lines) => (lines.length ? [`\n## ${title}`, ...lines] : []);
  if (!ids.length) {
    const p = m.proposal;
    const plan = [...m.nodes, ...m.edges].filter((x) => x.status && x.status !== 'built');
    const zoned = new Map();
    for (const n of m.nodes) zoned.set(n.zone ?? '', [...(zoned.get(n.zone ?? '') ?? []), n]);
    return [
      `# ${m.title}`, m.summary,
      m.stamped ? `Checked against the code at ${m.stamped.commit?.slice(0, 12) ?? 'a folder with no commit'} (${m.stamped.at.slice(0, 10)}).` : 'Not stamped: nothing says which code this page was checked against.',
      ...(p ? [`\n## Proposal: ${p.approach}`, p.problem, ...(p.pros ?? []).map((x) => `+ ${x}`), ...(p.cons ?? []).map((x) => `- ${x}`), ...(p.migration ?? []).map((x, i) => `${i + 1}. ${x}`)] : []),
      ...block('The plan against what is built', plan.map((x) => `- ${x.id}: ${x.label}${mark(x)}`)),
      ...block('Discussion', said(m.discussion ?? [])),
      ...block('Read for it', (m.sources ?? []).map((s) => `- ${s.title}: ${s.url}${s.note ? `\n  ${s.note}` : ''}`)),
      ...[...zoned.entries()].flatMap(([zone, nodes]) => [`\n## ${zone ? `${name(zone)} (${zone})` : 'Parts'}`, ...(all.get(zone)?.note ? [all.get(zone).note] : []), ...nodes.map((n) => `- ${n.id}: ${n.label} (${[n.kind, n.service, n.tech].filter(Boolean).join(', ')}): ${n.responsibility ?? ''}${mark(n)}`)]),
      ...block('Connections', m.edges.map(edge)),
      ...block('Flows', (m.flows ?? []).map((f) => `- ${f.id}: ${f.title} (${f.steps.length} steps): ${f.summary ?? ''}${mark(f)}`)),
      ...block('Not known', [...(m.unknowns ?? []), ...(m.assumptions ?? []).map((a) => `assumed: ${a}`)].map((x) => `- ${x}`)),
      '\nRead one part with the code it cites: blueprint show PAGE ID [ID…]',
    ].join('\n');
  }
  const code = (x) => (x.evidence ?? []).flatMap((ev) => {
    const ex = ev.lines && page.excerpts?.[`${ev.path}:${ev.lines[0]}-${ev.lines[1]}`];
    return [`\n${ev.path}${ev.lines ? `:${ev.lines[0]}-${ev.lines[1]}` : ''}: ${ev.why ?? ''}`, ...(ex ? [ex.text.split('\n').map((l, i) => `${String(ex.start + i).padStart(5)}| ${l}`).join('\n') + (ex.cut ? '\n     … the page keeps the first 60 lines' : '')] : [])];
  });
  return ids.map((id) => {
    const x = all.get(id);
    if (!x) throw new Error(`the page has no part "${id}"; its parts: ${[...all.keys()].join(', ')}`);
    const about = (list) => (list ?? []).filter((y) => y.refs?.includes(id));
    const edges = x.list === 'nodes' ? m.edges.filter((e) => e.from === id || e.to === id) : x.list === 'edges' ? [x] : [];
    const steps = (m.flows ?? []).flatMap((f) => f.steps.map((s, i) => ({f, s, i})).filter(({s}) => edges.some((e) => e.id === s.edge)).map(({f, s, i}) => `- ${f.title}, step ${i + 1}: ${s.text}`));
    const head = {
      zones: () => [`# ${x.label} (${id}): ${x.kind}${mark(x)}`, x.note, ...m.nodes.filter((n) => n.zone === id).map((n) => `- ${n.id}: ${n.label}`)],
      nodes: () => [`# ${x.label} (${id}): ${[x.kind, x.service, x.tech].filter(Boolean).join(', ')}${mark(x)}`, x.responsibility, x.security && `Security: ${x.security}`, x.zone && `In: ${name(x.zone)}`, ...block('Connections', edges.map(edge))],
      edges: () => [`# ${name(x.from)} -> ${name(x.to)}: ${x.label} (${id}): ${[x.kind, x.protocol].filter(Boolean).join(', ')}${mark(x)}`, x.detail],
      flows: () => [`# ${x.title} (${id})${mark(x)}`, x.summary, ...x.steps.flatMap((s, i) => [`${i + 1}. ${s.text} [${s.edge}]`, s.explain && `   ${s.explain}`])],
    }[x.list]();
    return [...head.filter(Boolean), ...block('Flow steps through it', x.list === 'flows' ? [] : steps), ...block('Discussion about it', said(about(m.discussion))), ...block('The code it cites', code(x))].join('\n');
  }).join('\n\n');
}

/** The model with a note laid on it: a source read for it, or a line of the discussion. A discussion line with a title
 * the model has replaces that line, which is how an open question becomes a decision. */
export function noted(model, {title, detail = null, status = 'open', refs = [], url = null, at = new Date().toISOString().slice(0, 10)}) {
  const keep = (list) => (list ?? []).filter((x) => x.title !== title);
  if (url) return {...model, sources: [...keep(model.sources), {title, url, ...(detail ? {note: detail} : {})}]};
  return {...model, discussion: [...keep(model.discussion), {title, ...(detail ? {detail} : {}), status, ...(refs.length ? {refs} : {}), at}]};
}

/** The coverage ledger entry for a file: the longest path in model.coverage that is the file or a folder holding it. */
export function ledgerFor(model, file) {
  let best = null;
  let bestLength = -1;
  for (const c of model.coverage ?? []) {
    const p = c.path.replace(/\/$/, '');
    const length = p === '.' ? 0 : p.length;
    if ((p === '.' || file === p || file.startsWith(`${p}/`)) && length > bestLength) { best = c; bestLength = length; }
  }
  return best;
}

/** The lines the model cites in each file: path to a list of [start, end]. A citation with no lines is the whole file. */
export function citedSpans(model) {
  const by = new Map();
  for (const ev of allEvidence(model)) {
    if (typeof ev?.path !== 'string') continue;
    if (!by.has(ev.path)) by.set(ev.path, []);
    by.get(ev.path).push(Array.isArray(ev.lines) ? ev.lines : [1, Infinity]);
  }
  return by;
}

/** The ways in and out that have a name: a path, a port, a program, a host. Each is accounted for on its own line, the
 * way a security audit keeps a ledger of entry points and sinks and not of files. The other kinds (an SDK, a data
 * store, identity, a model API, an entry point) stay accounted for by the file.
 * ponytail: the scanner finds those on the import or the constructor and a model cites the call, so a line rule
 * names what is drawn. Measured 2026-11-12 on the saved whole-system models: of the sdk, data, auth, llm and entry
 * signals in cited files, a citation spans 16 of 42 in aws-serverless-shopping-cart@66a863f and 89 of 249 in
 * bedrock-chat@14e17cc. The way up is to follow the imported name to the lines that use it. */
export const SURFACES = ['route', 'listen', 'process', 'http-out'];

/** The architecture signals of one file that the model has not accounted for. A way in or out is accounted for when
 * a citation spans a line it stands on, or when the ledger marks its file read and says why: a file cited for its
 * router can still start a program the model never drew. Any other signal is accounted for when its file is cited or
 * marked read.
 * ponytail: one reason on a file (or a folder) accounts for every way in and out in it, so a reason written for one
 * route also covers a host added to the file later, until the stamp names the file as changed. The way up is a
 * reason for each signal. */
export function looseSignals(model, rel, text, spans = citedSpans(model)) {
  const entry = ledgerFor(model, rel);
  const read = entry?.status === 'read';
  if (read && entry.why) return [];
  const mine = spans.get(rel) ?? [];
  const spanned = (s) => (s.whole ? mine.length > 0 : mine.some(([a, b]) => s.lines.some((l) => l >= a && l <= b)));
  return signalsOf(rel, text).filter((s) => s.kind !== 'env' && (SURFACES.includes(s.kind) ? !spanned(s) : !mine.length && !read));
}

/** What a complete analysis has not accounted for. Every way in and out that the scanner finds (a route, a listener,
 * a program started, an outgoing host) lies inside a citation, or its file is marked read with the reason the model
 * leaves it out. Every file with another architecture signal (an SDK client, a model API, a data store, a queue,
 * identity) is cited or marked read, because a signal in a file nobody read is where a missing box hides. And every
 * file of the repository is cited or in the coverage ledger. The scanner decides what exists; the model only decides
 * what it means. */
export function coverageProblems(model, repoRoot) {
  const spans = citedSpans(model);
  const citedFiles = new Set(spans.keys());
  const out = [];
  const loose = new Map();
  for (const rel of listFiles(repoRoot)) {
    const text = readText(repoRoot, rel);
    if (text === null) continue; // binary or too large to read: nothing to cite
    const entry = ledgerFor(model, rel);
    if (!citedFiles.has(rel) && !entry) {
      const dir = path.posix.dirname(rel);
      const d = loose.get(dir) ?? {files: 0, lines: 0};
      d.files += 1; d.lines += text.split('\n').length;
      loose.set(dir, d);
    }
    const signals = looseSignals(model, rel, text, spans);
    if (signals.length) {
      const state = citedFiles.has(rel) ? 'cited on other lines' : entry ? `${entry.status}${entry.status === 'read' ? ' with no "why"' : ''}` : 'not accounted for';
      out.push(`${rel}: ${signals.length} architecture ${signals.length === 1 ? 'signal' : 'signals'} in no citation (${signals.slice(0, 4).map((s) => `${s.kind} ${s.detail} at line ${s.line}`).join('; ')}${signals.length > 4 ? '; …' : ''}) in a file that is ${state}; read it, cite each route, listener, program and host at its line from the part that owns it, or mark the file read in coverage with a "why" that says why the model leaves it out`);
    }
  }
  // What the model traces ("auth0"): every file that names it is cited or read, tests, settings and documents too,
  // and every file that imports one of those is at least skimmed, because it depends on the term without naming it.
  if (model.trace?.length) {
    const found = trace(repoRoot, model.trace);
    for (const f of found.files) {
      const entry = ledgerFor(model, f.path);
      if (citedFiles.has(f.path) || entry?.status === 'read') continue;
      out.push(`${f.path}: names ${f.terms.join(', ')}${f.count ? ` on ${f.count} ${f.count === 1 ? 'line' : 'lines'} (first at line ${f.lines[0].line})` : ' in its path'}, which the model traces, in a file that is ${entry ? entry.status : 'not accounted for'}; read it, then cite it or mark it read`);
    }
    for (const d of found.dependents) {
      const entry = ledgerFor(model, d.path);
      if (citedFiles.has(d.path) || (entry && entry.status !== 'skipped')) continue;
      out.push(`${d.path}: imports ${d.imports[0]}, which names ${model.trace.join(', ')}; it depends on what the model traces, so skim it at least`);
    }
  }
  for (const [dir, d] of [...loose.entries()].sort((a, b) => b[1].lines - a[1].lines)) {
    out.push(`${dir}/: ${d.files} ${d.files === 1 ? 'file' : 'files'} (${d.lines} lines) neither cited nor in coverage; read, skim or skip them: coverage {path, status, why}`);
  }
  return out;
}

/** Stamps the model to the code it was checked against: a hash of every cited span and of every file in the ledger,
 * and the commit. check() then names every citation whose code changed afterwards, so a page that no longer matches
 * its code says so instead of being trusted. */
export function stamp(model, repoRoot) {
  const cache = new Map();
  for (const ev of allEvidence(model)) ev.sha = sha(cited(repoRoot, ev, cache));
  for (const c of model.coverage ?? []) {
    const full = path.join(repoRoot, c.path);
    if (c.path !== '.' && existsSync(full) && statSync(full).isFile()) c.sha = sha(readFileSync(full, 'utf8'));
  }
  let commit = null;
  try { commit = execFileSync('git', ['-C', repoRoot, 'rev-parse', 'HEAD'], {stdio: ['ignore', 'pipe', 'ignore']}).toString().trim(); } catch { /* not a repository */ }
  model.stamped = {commit, at: new Date().toISOString()};
  return model;
}
