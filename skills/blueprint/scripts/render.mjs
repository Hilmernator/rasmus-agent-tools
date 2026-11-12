// The page: one self-contained HTML file, readable offline and on a phone, in Rasmus's design system. The diagrams
// are drawn here, as SVG, so the page reads and prints without scripts; page.js only adds selecting, flows, the
// sequence view and pan and zoom. Fonts and icons are embedded.
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {cssVariables, embeddedFontFaces, typeClasses} from './rh.mjs';
import {Icons} from './icons.mjs';
import {layout, bestLayout, badgePoint, labelLines, wrap, NODE} from './layout.mjs';
import {excerpts as readExcerpts, citers, ledgerFor, coverageProblems} from './model.mjs';
import {trace} from './scan.mjs';
import {views as viewsOf, areas} from './views.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const NODE_MODULES = path.join(here, 'node_modules');

export const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));

/** A link to the cited lines on GitHub, when the repository is there. */
export function sourceUrl(repo, ev) {
  const m = /github\.com[:/]([\w.-]+)\/([\w.-]+?)(\.git)?$/.exec(repo?.remote ?? '');
  if (!m || !repo.commit) return null;
  const lines = ev.lines ? `#L${ev.lines[0]}${ev.lines[1] !== ev.lines[0] ? `-L${ev.lines[1]}` : ''}` : '';
  return `https://github.com/${m[1]}/${m[2]}/blob/${repo.commit}/${ev.path.split('/').map(encodeURIComponent).join('/')}${lines}`;
}

// A part's plan status (planned, changed, removed) and, on a diff page, its change (added, changed, removed): the
// classes page.css styles and the word on its badge. On a diff page the change wins.
const BADGE = {added: 'Added', changed: 'Changed', removed: 'Removed', planned: 'Planned', 'st-changed': 'Changes', 'st-removed': 'To remove'};
export function marks(x) {
  const cls = `${x.status && x.status !== 'built' ? ` st-${x.status}` : ''}${x.change ? ` chg-${x.change}` : ''}`;
  const badge = x.change ? BADGE[x.change] : x.status === 'planned' ? BADGE.planned : x.status === 'changed' ? BADGE['st-changed'] : x.status === 'removed' ? BADGE['st-removed'] : null;
  return {cls, badge};
}

const points = (ps) => ps.map((p, i) => `${i ? 'L' : 'M'}${p.x.toFixed(1)} ${p.y.toFixed(1)}`).join(' ');

function markers(prefix) {
  return ['def', 'ink', 'sea', 'olive'].map((c) => `<marker id="${prefix}-a-${c}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="9" markerHeight="9" orient="auto-start-reverse" markerUnits="userSpaceOnUse"><path class="arrow ${c === 'def' ? '' : c}" d="M0 1L9 5L0 9z"/></marker>`).join('');
}

/** The diagram of a graph as SVG. `lay` is its layout; every node and edge carries its id for page.js. */
function diagram(graph, lay, icons, {prefix, label, all = graph.nodes, context = [], hidden = false, touched = new Set()}) {
  const faded = new Set(context);
  const zoneById = new Map((graph.zones ?? []).map((z) => [z.id, z]));
  const nodeById = new Map(graph.nodes.map((n) => [n.id, n]));
  const edgeById = new Map(graph.edges.map((e) => [e.id, e]));
  const parts = [];
  for (const zb of [...lay.zones].sort((a, b) => a.depth - b.depth)) {
    const z = zoneById.get(zb.id);
    const icon = icons.forZone(z);
    const iconSvg = icon ? (icon.style === 'aws'
      ? `<use href="#${icon.id}" x="${zb.x}" y="${zb.y}" width="32" height="32"/>`
      : `<use class="z-icon-line" href="#${icon.id}" x="${zb.x + 10}" y="${zb.y + 9}" width="16" height="16"/>`) : '';
    const tx = zb.x + (icon ? 42 : 14);
    parts.push(`<g class="zone${marks(z).cls}" data-id="${esc(z.id)}"><rect class="z-box k-${esc(z.kind)}" x="${zb.x}" y="${zb.y}" width="${zb.w}" height="${zb.h}" rx="${icon?.style === 'aws' ? 0 : 12}"/>${iconSvg}<text class="z-label" x="${tx}" y="${zb.y + 21}">${esc(z.label)}</text>${z.note ? `<text class="n-tech" x="${tx}" y="${zb.y + 37}">${esc(wrap(z.note, Math.floor((zb.w - 60) / 6.8), 1)[0] ?? '')}</text>` : ''}</g>`);
  }
  for (const eb of lay.edges) {
    const e = edgeById.get(eb.id);
    const kind = e.kind ?? 'sync';
    const marker = kind === 'auth' ? 'olive' : 'def';
    const lab = eb.label ? `<g class="e-label"><rect x="${eb.label.x}" y="${eb.label.y}" width="${eb.label.w}" height="${eb.label.h}" rx="4"/>${labelLines(e.label).map((l, i) => `<text x="${eb.label.x + eb.label.w / 2}" y="${eb.label.y + 15 + i * 15}" text-anchor="middle">${esc(l)}</text>`).join('')}</g>` : '';
    parts.push(`<g class="edge k-${esc(kind)}${marks(e).cls}${(e.members ?? []).some((id) => touched.has(id)) ? ' chg-in' : ''}" data-id="${esc(e.id)}" data-from="${esc(e.from)}" data-to="${esc(e.to)}"><path class="e-line" d="${points(eb.points)}" marker-end="url(#${prefix}-a-${marker})"/><path class="e-hit" d="${points(eb.points)}"/>${lab}<title>${esc(`${nodeById.get(e.from)?.label} → ${nodeById.get(e.to)?.label}: ${e.label}${e.protocol ? ` (${e.protocol})` : ''}`)}</title></g>`);
  }
  for (const nb of lay.nodes) {
    const n = nodeById.get(nb.id);
    if (n.kind === 'area') {
      // An area in the overview: its letter, its name, how many components, and their icons.
      const members = (n.members ?? []).map((id) => all.find((m) => m.id === id)).filter(Boolean);
      const row = members.slice(0, 6).map((m, i) => {
        const ic = icons.forNode(m);
        const x = nb.x + 20 + i * 38;
        const y = nb.y + nb.h - 50;
        return ic.style === 'aws' ? `<use href="#${ic.id}" x="${x}" y="${y}" width="30" height="30"><title>${esc(m.label)}</title></use>` : `<rect class="n-tile" x="${x}" y="${y}" width="30" height="30" rx="8"/><use class="n-line" href="#${ic.id}" x="${x + 6}" y="${y + 6}" width="18" height="18"/>`;
      }).join('') + (members.length > 6 ? `<text class="n-tech" x="${nb.x + 20 + 6 * 38}" y="${nb.y + nb.h - 30}">+${members.length - 6}</text>` : '');
      const title = wrap(n.label, 24, 2);
      parts.push(`<g class="node area-box${members.some((m) => touched.has(m.id)) ? ' chg-in' : ''}" data-id="${esc(n.id)}" data-area="${esc(n.area)}" tabindex="0" role="button" aria-label="${esc(`Area ${n.letter}, ${n.label}: open it`)}"><rect class="n-hit area-card" x="${nb.x}" y="${nb.y}" width="${nb.w}" height="${nb.h}" rx="12"/><rect class="area-letter" x="${nb.x + 16}" y="${nb.y + 16}" width="28" height="28" rx="6"/><text class="area-letter-t" x="${nb.x + 30}" y="${nb.y + 35}" text-anchor="middle">${esc(n.letter)}</text>${title.map((l, i) => `<text class="n-title" x="${nb.x + 54}" y="${nb.y + 35 + i * 18}">${esc(l)}</text>`).join('')}<text class="n-tech" x="${nb.x + 54}" y="${nb.y + 35 + title.length * 18 + 2}">${esc(n.tech)}</text>${row}<title>${esc(n.responsibility)}</title></g>`);
      continue;
    }
    const icon = icons.forNode(n);
    const cx = nb.x + nb.w / 2;
    const iconY = nb.y + 12;
    const iconSvg = icon.style === 'aws'
      ? `<use href="#${icon.id}" x="${cx - 24}" y="${iconY}" width="48" height="48"/>`
      : `<rect class="n-tile" x="${cx - 24}" y="${iconY}" width="48" height="48" rx="12"/><use class="n-line" href="#${icon.id}" x="${cx - 14}" y="${iconY + 10}" width="28" height="28"/>`;
    const title = wrap(n.label, 19, 2);
    const tech = n.tech ?? n.service ?? '';
    const titleSvg = title.map((l, i) => `<text class="n-title" x="${cx}" y="${nb.y + 80 + i * 18}" text-anchor="middle">${esc(l)}</text>`).join('');
    const techSvg = tech ? `<text class="n-tech" x="${cx}" y="${nb.y + 80 + title.length * 18 + 2}" text-anchor="middle">${esc(wrap(tech, 22, 1)[0])}</text>` : '';
    const {cls, badge} = marks(n);
    const badgeSvg = badge ? `<g class="n-badge"><rect x="${nb.x + 6}" y="${nb.y + 4}" width="${badge.length * 7 + 12}" height="18" rx="4"/><text x="${nb.x + 12}" y="${nb.y + 17}">${esc(badge.toUpperCase())}</text></g>` : '';
    parts.push(`<g class="node k-${esc(n.kind)}${faded.has(n.id) ? ' ctx' : ''}${cls}" data-id="${esc(n.id)}" tabindex="0" role="button" aria-label="${esc(`${badge ? `${badge}: ` : ''}${n.label}${tech ? `, ${tech}` : ''}`)}"><rect class="n-hit" x="${nb.x}" y="${nb.y}" width="${nb.w}" height="${nb.h}" rx="12"/>${badgeSvg}${iconSvg}${titleSvg}${techSvg}<title>${esc(n.responsibility ?? n.label)}</title></g>`);
  }
  return `<svg class="diagram${hidden ? '' : ' on'}" id="${prefix}" viewBox="0 0 ${lay.width} ${lay.height}" data-w="${lay.width}" data-h="${lay.height}" role="img" aria-label="${esc(label)}" xmlns="http://www.w3.org/2000/svg"><defs>${markers(prefix)}</defs>${parts.join('')}<g class="badges"></g></svg>`;
}

/** The components and connections a plan or a diff touches. */
const touchedOf = (model) => new Set([...model.nodes, ...model.edges].filter((x) => x.change || (x.status && x.status !== 'built')).map((x) => x.id));

/** What the diff, or the plan, touches, as a list to click through: the first thing a reviewer asks for. */
function changesCard(model, diff) {
  const key = diff ? 'change' : 'status';
  const groups = diff ? [['added', 'Added', 'c-add'], ['changed', 'Changed', 'c-mod'], ['removed', 'Removed', 'c-del']] : [['planned', 'To build', 'c-add'], ['changed', 'To change', 'c-mod'], ['removed', 'To remove', 'c-del']];
  const name = (id) => model.nodes.find((n) => n.id === id)?.label ?? id;
  const html = groups.map(([value, title, cls]) => {
    const items = [
      ...model.nodes.filter((n) => n[key] === value).map((n) => `<li><button data-goto="${esc(n.id)}">${esc(n.label)}</button></li>`),
      ...model.edges.filter((e) => e[key] === value).map((e) => `<li><button data-goto="${esc(e.id)}">${esc(name(e.from))} → ${esc(name(e.to))}</button> <span class="muted">${esc(e.label)}</span></li>`),
      ...(diff ? (model.flows ?? []).filter((f) => f.change === value).map((f) => `<li><button data-flow="${esc(f.id)}">Flow: ${esc(f.title)}</button></li>`) : []),
    ];
    return items.length ? `<h3><span class="${cls}">${title}</span> <span class="mono muted">${items.length}</span></h3><ul class="links">${items.join('')}</ul>` : '';
  }).join('');
  if (!html) return diff ? '<div class="card" id="changes-card"><span class="label">What changed</span><h2>The two architectures are the same</h2><p class="muted" style="margin:0">No component, connection or flow differs. The code may still have changed: see the Changes tab.</p></div>' : '';
  return `<div class="card" id="changes-card"><span class="label">${diff ? 'What changed' : 'The plan'}</span><h2>${diff ? 'Every part that differs' : 'Every part the plan touches'}</h2><p class="muted" style="margin:0">Pick one to see it on the diagram${diff ? ', with what it was before and the code that changed under it' : ' and what the plan does to it'}.</p>${html}</div>`;
}

/** Where the code names what the model traces, and what accounts for each of those files: the components that cite
 * it, or its line in the coverage ledger. A file with neither is where a change gets forgotten. */
function tracedCard(model, repoRoot) {
  if (!repoRoot || !model.trace?.length) return '';
  const found = trace(repoRoot, model.trace);
  const by = citers(model);
  const name = (id) => model.nodes.find((n) => n.id === id)?.label ?? model.edges.find((e) => e.id === id)?.label ?? id;
  let open = 0;
  // The same rule as blueprint check --complete: a file that names a term is cited or read; an importer is at least skimmed.
  const state = (p, importer) => {
    if (by.has(p)) return `<div class="refs">${by.get(p).map((id) => `<button data-goto="${esc(id)}">${esc(name(id))}</button>`).join('')}</div>`;
    const entry = ledgerFor(model, p);
    if (entry && (importer ? entry.status !== 'skipped' : entry.status === 'read')) return `<span class="tag olive">${esc(entry.status)}</span>`;
    open += 1;
    return `<span class="tag del">${entry ? `only ${esc(entry.status)}` : 'not accounted for'}</span>`;
  };
  const files = found.files.slice(0, 300).map((f) => `<tr><td class="mono">${esc(f.path)}</td><td class="mono">${f.count || 'path'}</td><td class="mono">${f.lines[0] ? `${f.lines[0].line}: ${esc(f.lines[0].text.slice(0, 90))}` : ''}</td><td class="mono">${f.importedBy || ''}</td><td>${state(f.path, false)}</td></tr>`).join('');
  const deps = found.dependents.slice(0, 300).map((d) => `<tr><td class="mono">${esc(d.path)}</td><td class="mono">${esc(d.imports.join(', '))}</td><td>${state(d.path, true)}</td></tr>`).join('');
  return `<div class="card" style="margin-bottom:24px"><span class="label">Trace</span><h2>Where the code names ${esc(found.terms.join(', '))}</h2><p class="muted" style="margin:0 0 8px">${found.files.length} files name ${found.terms.length === 1 ? 'it' : 'them'}, tests, settings and documents too. ${found.dependents.length} more import one of those, so they depend on it without naming it. ${open ? `<b class="c-del">${open} are not accounted for</b>: a change that forgets them leaves them calling the old way.` : 'Every one belongs to a component or was read.'}</p>
<table class="t"><thead><tr><th>File</th><th>Lines</th><th>First</th><th>Imported by</th><th>In the model</th></tr></thead><tbody>${files}</tbody></table>${deps ? `<h3>Files that import one of those</h3><table class="t"><thead><tr><th>File</th><th>Imports</th><th>In the model</th></tr></thead><tbody>${deps}</tbody></table>` : ''}</div>`;
}

function evidenceCount(model) {
  return [...model.nodes, ...model.edges, ...(model.flows ?? []).flatMap((f) => f.steps)].reduce((n, x) => n + (x.evidence?.length ?? 0), 0);
}

const LANG_COLORS = ['var(--sea)', 'var(--olive)', 'var(--ink-muted)', 'var(--line-strong)', 'var(--sea-soft)', 'var(--olive-soft)'];

/** What the analysis never cited: modules of code, infrastructure files and manifests. A large module here is the
 * first place to look for something the page leaves out. */
function coverage(model, facts) {
  if (!facts) return null;
  const cited = new Set([...model.nodes, ...model.edges, ...(model.flows ?? []).flatMap((f) => f.steps)].flatMap((x) => x.evidence ?? []).map((ev) => ev.path));
  const inModule = (m, p) => (m === '.' ? !p.includes('/') : p === m || p.startsWith(`${m}/`));
  const modules = facts.modules.nodes.filter((m) => m.files > 0);
  const missed = modules.filter((m) => ![...cited].some((p) => inModule(m.id, p)));
  const lines = (list) => list.reduce((n, m) => n + m.lines, 0);
  const infra = [...new Set(facts.infra.map((r) => r.path))].filter((p) => !cited.has(p));
  return {modules: modules.length, covered: modules.length - missed.length, share: lines(modules) ? 1 - lines(missed) / lines(modules) : 1, missed, infra};
}

/** What the page covers, said on the page: complete, or partial with what nobody has accounted for. `left` is what
 * blueprint check --complete names; null when the page was drawn with no code to check against. */
function coverageCard(left) {
  if (!left) return '';
  if (!left.length) return '<div class="card" id="coverage-card" style="margin-bottom:24px"><span class="label">Coverage</span><h2>Complete</h2><p class="muted" style="margin:0">Every file of the repository is cited or in the ledger below. Every route, listener, program started and outgoing host that the scanner found lies inside a citation, or its file has the reason in the ledger. <code>blueprint check --complete</code> checks this.</p></div>';
  const rows = left.slice(0, 80).map((p) => { const at = p.indexOf(': '); return `<tr><td class="mono">${esc(p.slice(0, at))}</td><td>${esc(p.slice(at + 2).replace(/; (read|it depends)[^;]*$/, ''))}</td></tr>`; }).join('');
  return `<div class="card" id="coverage-card" style="margin-bottom:24px"><span class="label">Coverage</span><h2>Partial: ${left.length} ${left.length === 1 ? 'place is' : 'places are'} not accounted for</h2><p class="muted" style="margin:0 0 8px">What the page shows is checked against the code. Nobody has said anything about what is listed here, so a component or a connection can be missing. <code>blueprint cover</code> reads these files and adds what they show.</p><table class="t"><tbody>${rows}</tbody></table>${left.length > 80 ? `<p class="muted" style="margin:8px 0 0">And ${left.length - 80} more: <code>blueprint check --complete</code> lists them all.</p>` : ''}</div>`;
}

/** The coverage ledger: how many files the analysis read, skimmed and skipped, and why. */
function ledger(model) {
  if (!model.coverage?.length) return '';
  const rows = model.coverage.map((c) => `<tr><td class="mono">${esc(c.path)}</td><td><span class="tag${c.status === 'read' ? ' olive' : ''}">${esc(c.status)}</span></td><td>${esc(c.why ?? '')}</td></tr>`).join('');
  return `<div class="card" style="margin-bottom:24px"><span class="label">Coverage ledger</span><h2>What the analysis looked at</h2><p class="muted" style="margin:0 0 8px">Besides every file it cites, the analysis accounted for these. <code>blueprint check --complete</code> refuses a model that leaves a file unaccounted for, a file with a client, a data store or identity code unread, or a route, a listener, a program started or an outgoing host outside every citation with no reason here.</p><table class="t"><tbody>${rows}</tbody></table></div>`;
}

function inventory(facts, moduleSvg, cover) {
  if (!facts) return '<div class="empty">No scan was given to this page: run <code>blueprint build</code> or pass <code>--facts</code> to include what the code says without a model.</div>';
  const code = facts.languages.filter((l) => l.code);
  const total = code.reduce((n, l) => n + l.lines, 0) || 1;
  const bar = code.slice(0, 6).map((l, i) => `<span style="width:${(100 * l.lines / total).toFixed(2)}%;background:${LANG_COLORS[i]}" title="${esc(l.language)}"></span>`).join('');
  const langs = code.slice(0, 6).map((l, i) => `<span><i style="background:${LANG_COLORS[i]}"></i>${esc(l.language)} <span class="mono">${l.lines.toLocaleString('en')}</span></span>`).join('');
  const man = facts.manifests.map((m) => `<tr><td class="mono">${esc(m.path)}</td><td>${esc(m.kind)}</td><td>${esc(m.name ?? '')}</td><td>${esc((m.dependencies ?? []).slice(0, 14).join(', '))}${(m.dependencies ?? []).length > 14 ? ` <span class="muted">+${m.dependencies.length - 14}</span>` : ''}</td></tr>`).join('');
  const infra = facts.infra.slice(0, 300).map((r) => `<tr><td>${esc(r.kind)}</td><td class="mono">${esc(r.type)}</td><td class="mono">${esc(r.name)}</td><td class="mono">${esc(r.path)}:${r.line}</td></tr>`).join('');
  const kinds = {route: 'Routes', entry: 'Entry points', listen: 'Servers and listeners', middleware: 'Middleware', sdk: 'Cloud SDKs and constructs', llm: 'Model APIs', data: 'Data stores', queue: 'Queues and events', auth: 'Identity and authorization', 'http-out': 'Outgoing hosts', net: 'HTTP and socket clients', ipc: 'Inter-process messages', process: 'Programs started', env: 'Environment variables'};
  const signals = Object.entries(kinds).map(([k, title]) => {
    const rows = facts.signals.filter((s) => s.kind === k);
    if (!rows.length) return '';
    const byDetail = new Map();
    for (const r of rows) { const l = byDetail.get(r.detail) ?? []; l.push(r); byDetail.set(r.detail, l); }
    const trs = [...byDetail.entries()].slice(0, 40).map(([d, rs]) => `<tr><td class="mono">${esc(d)}</td><td class="mono">${rs.slice(0, 3).map((r) => `${esc(r.path)}:${r.line}`).join('<br>')}${rs.length > 3 ? `<br><span class="muted">+${rs.length - 3} more</span>` : ''}</td></tr>`).join('');
    return `<div class="card"><span class="label">${esc(k)}</span><h2>${esc(title)}</h2><table class="t"><tbody>${trs}</tbody></table></div>`;
  }).join('');
  return `
${cover && (cover.missed.length || cover.infra.length) ? `<div class="card" style="margin-bottom:24px"><span class="label">Coverage</span><h2>Not cited by the analysis</h2><p class="muted" style="margin:0 0 8px">The analysis cited ${cover.covered} of ${cover.modules} code modules, ${Math.round(cover.share * 100)} % of the code by lines. What it never cited is listed here, largest first: look here for what the page may leave out, or ask for a feature view of it.</p><div class="grid">${cover.missed.length ? `<div><h3>Modules</h3><table class="t"><tbody>${cover.missed.slice(0, 30).map((m) => `<tr><td class="mono">${esc(m.id)}</td><td class="mono">${m.files} files</td><td class="mono">${m.lines.toLocaleString('en')} lines</td></tr>`).join('')}</tbody></table></div>` : ''}${cover.infra.length ? `<div><h3>Infrastructure files</h3><table class="t"><tbody>${cover.infra.slice(0, 30).map((p) => `<tr><td class="mono">${esc(p)}</td><td class="mono">${facts.infra.filter((r) => r.path === p).length} resources</td></tr>`).join('')}</tbody></table></div>` : ''}</div></div>` : ''}
<div class="grid">
  <div class="card"><span class="label">Repository</span><h2>${esc(facts.repo.name)}</h2>
    <dl class="kv"><dt>Files</dt><dd>${facts.files.toLocaleString('en')}</dd><dt>Commit</dt><dd class="mono">${esc((facts.repo.commit ?? 'not a git repository').slice(0, 12))}${facts.repo.dirty ? ' <span class="tag">uncommitted changes</span>' : ''}</dd><dt>Branch</dt><dd class="mono">${esc(facts.repo.branch ?? '')}</dd><dt>Scanned</dt><dd class="mono">${esc(facts.scannedAt.slice(0, 16).replace('T', ' '))} UTC</dd></dl>
    <div class="bars">${bar}</div><div class="langs">${langs}</div></div>
  ${signals}
</div>
${moduleSvg ? `<div class="section-head" style="margin-top:40px"><h2>Modules and imports</h2><span class="muted">Read from import statements by the scanner, without a model. Arrows point at what is imported; numbers count imports.</span></div><div class="canvas" style="height:auto;min-height:0">${moduleSvg}</div>` : ''}
${man ? `<div class="section-head" style="margin-top:40px"><h2>Manifests</h2></div><table class="t"><thead><tr><th>File</th><th>Kind</th><th>Name</th><th>Dependencies</th></tr></thead><tbody>${man}</tbody></table>` : ''}
${infra ? `<div class="section-head" style="margin-top:40px"><h2>Infrastructure as code</h2><span class="muted">${facts.infra.length} resources</span></div><table class="t"><thead><tr><th>Source</th><th>Type</th><th>Name</th><th>Where</th></tr></thead><tbody>${infra}</tbody></table>` : ''}`;
}

/** The module graph from the scan, as a graph the diagram can draw. */
function moduleGraph(facts) {
  if (!facts || facts.modules.edges.length === 0) return null;
  const edges = facts.modules.edges.slice(0, 80);
  const used = new Set(edges.flatMap((e) => [e.from, e.to]));
  const nodes = facts.modules.nodes.filter((m) => used.has(m.id)).map((m) => ({
    id: `m-${m.id}`, label: m.id, kind: 'module',
    tech: m.files ? `${m.files} files · ${m.lines.toLocaleString('en')} lines` : 'package', responsibility: Object.keys(m.languages).join(', ') || m.id,
  }));
  return {
    zones: [],
    nodes,
    edges: edges.map((e, i) => ({id: `me-${i}`, from: `m-${e.from}`, to: `m-${e.to}`, label: String(e.count), kind: 'sync'})),
  };
}

/** Renders `model` (checked) to a page. `facts` is the scan, `repoRoot` where evidence is read from. */
export async function render(model, {facts = null, repoRoot, analyst = null, excerpts: given = null, diff = null} = {}) {
  const icons = new Icons();
  const list = viewsOf(model);
  const start = list.find((v) => v.kind === 'system');
  const laid = await Promise.all(list.map((v) => bestLayout(v.graph)));
  const touched = touchedOf(model);
  const arch = list.map((v, i) => diagram(v.graph, laid[i], icons, {prefix: `v-${v.id}`, label: `${model.title}: ${v.title}`, all: model.nodes, context: v.context, hidden: v !== start, touched})).join('');
  const viewbar = list.length > 1 ? `<div class="viewbar" role="tablist" aria-label="Views">${list.map((v) => `<button class="chip" role="tab" data-show-view="${esc(v.id)}" aria-selected="${v === start}" title="${esc(v.summary ?? '')}">${v.kind === 'feature' ? '<span class="tag sea">Feature</span> ' : ''}${esc(v.title)}</button>`).join('')}</div>` : '';
  const cover = coverage(model, facts);
  // A diff holds parts of two versions and a sketch holds no evidence: neither claims to cover the code.
  const left = repoRoot && !diff && evidenceCount(model) ? coverageProblems(model, repoRoot) : null;
  const mg = moduleGraph(facts);
  const moduleSvg = mg ? diagram(mg, await bestLayout(mg), icons, {prefix: 'mods', label: 'Modules and their imports'}) : '';
  const excerpts = given ?? (repoRoot ? readExcerpts(model, repoRoot) : {});
  const repo = diff?.repo ?? facts?.repo ?? model.repo ?? {};
  const data = {
    model,
    excerpts,
    diff: diff ? {base: diff.base, head: diff.head, files: diff.changes?.files ?? []} : null,
    repo: {name: repo.name, commit: repo.commit, remote: repo.remote},
    start: start.id,
    views: list.map((v, i) => ({
      id: v.id, title: v.title, kind: v.kind, summary: v.summary ?? '', flows: v.flows, context: v.context ?? [],
      // The overview's boxes and merged arrows, which are not in the model.
      areas: v.kind === 'overview' ? v.graph.nodes.filter((n) => n.kind === 'area') : [],
      merged: v.kind === 'overview' ? v.graph.edges : [],
      nodes: Object.fromEntries(laid[i].nodes.map((n) => [n.id, n])),
      edges: Object.fromEntries(laid[i].edges.map((e) => [e.id, {badge: e.label ? {x: e.label.x - 14, y: e.label.y + e.label.h / 2} : badgePoint(e.points)}])),
    })),
    links: Object.fromEntries([...model.nodes, ...model.edges, ...(model.flows ?? []).flatMap((f) => f.steps)].flatMap((x) => x.evidence ?? []).map((ev) => [`${ev.path}:${ev.lines?.join('-') ?? ''}`, sourceUrl(repo, ev)]).filter(([, u]) => u)),
  };
  const nFlows = model.flows?.length ?? 0;
  const plan = {planned: 0, changed: 0, removed: 0};
  for (const x of [...model.nodes, ...model.edges]) if (x.status in plan) plan[x.status] += 1;
  const planned = plan.planned + plan.changed + plan.removed;
  const nChanged = diff?.changes?.files.length ?? 0;
  const diffStats = diff ? `<span class="chg-stat"><a href="#changes-card" id="show-changes"><b class="c-add">+${diff.counts.added}</b> added · <b class="c-mod">${diff.counts.changed}</b> changed · <b class="c-del">−${diff.counts.removed}</b> removed</a></span>${nChanged ? `<span><a href="#" data-tab="changes"><b>${nChanged}</b> files changed</a> <span class="mono"><span class="c-add">+${diff.changes.files.reduce((n, f) => n + f.adds, 0)}</span> <span class="c-del">−${diff.changes.files.reduce((n, f) => n + f.dels, 0)}</span></span></span>` : ''}` : '';
  const planStats = planned && !diff ? `<span class="chg-stat"><a href="#changes-card" id="show-changes">Plan: <b class="c-add">${plan.planned}</b> to build · <b class="c-mod">${plan.changed}</b> to change · <b class="c-del">${plan.removed}</b> to remove</a></span>` : '';
  const scope = diff ? `<span class="tag sea">Diff</span><span class="mono">${esc(diff.base.label)} → ${esc(diff.head.label)}</span>` : planned ? '<span class="tag sea">Proposal</span>' : model.scope?.kind === 'feature' ? `<span class="tag sea">Feature</span><span class="mono">${esc(model.scope.feature)}</span>` : '<span class="tag">System</span>';
  const commit = repo.commit ? `<span class="mono">${esc(repo.name ?? '')}@${esc(repo.commit.slice(0, 7))}</span>` : `<span class="mono">${esc(repo.name ?? '')}</span>`;
  const list2 = (t, l) => (l?.length ? `<h3>${esc(t)}</h3><ul class="list">${l.map((x) => `<li>${esc(x)}</li>`).join('')}</ul>` : '');
  const proposal = model.proposal ? `<div class="card proposal"><span class="label">Proposal</span><h2>${esc(model.proposal.approach ?? 'The plan')}</h2>${model.proposal.problem ? `<p style="margin:0">${esc(model.proposal.problem)}</p>` : ''}${list2('For it', model.proposal.pros)}${list2('Against it', model.proposal.cons)}${list2('Steps', model.proposal.migration)}</div>` : '';
  const notes = proposal + [['Assumptions', model.assumptions], ['Not known from the code', model.unknowns]].filter(([, l]) => l?.length).map(([t, l]) => `<div class="card"><span class="label">${esc(t)}</span><ul class="list">${l.map((x) => `<li>${esc(x)}</li>`).join('')}</ul></div>`).join('');
  const css = readFileSync(path.join(here, 'page.css'), 'utf8');
  const js = readFileSync(path.join(here, 'page.js'), 'utf8');
  const generated = new Date().toISOString().slice(0, 10);
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(model.title)} · Blueprint</title>
<meta name="description" content="${esc(model.summary)}">
<style>${embeddedFontFaces(NODE_MODULES)}${cssVariables()}${typeClasses()}${css}</style>
</head>
<body>
${icons.defs()}
<header class="masthead"><div class="wrap">
  <div class="brand"><span class="logo">rh<b>.</b></span><span class="label">Blueprint</span><span class="crumbs">${scope}${commit}</span></div>
  <h1>${esc(model.title)}</h1>
  <p class="summary" id="summary">${esc(model.summary)}</p>
  <div class="stats"><button class="more" id="more" hidden>Read the whole summary</button><span><b>${model.nodes.length}</b> components</span><span><b>${model.edges.length}</b> connections</span><span><b>${nFlows}</b> ${nFlows === 1 ? 'flow' : 'flows'}</span>${diffStats}${planStats}${evidenceCount(model) ? `<span class="verified">✓ ${evidenceCount(model)} citations checked against the code${repo.commit ? ` at ${esc(repo.commit.slice(0, 7))}` : ''}${model.stamped ? ` · stamped ${esc(model.stamped.at.slice(0, 10))}` : ''}</span>` : '<span>A sketch: nothing in it is built yet</span>'}${cover ? `<span>cites <b>${cover.covered}</b> of ${cover.modules} modules${cover.missed.length ? ` · <a href="#" data-tab="inventory">what it does not cite</a>` : ''}</span>` : ''}${left ? (left.length ? `<span id="coverage-state"><b>Partial coverage</b>: ${left.length} ${left.length === 1 ? 'place' : 'places'} not accounted for · <a href="#" data-tab="inventory">which</a></span>` : '<span class="verified" id="coverage-state">✓ Complete coverage: every file and every way in and out is accounted for</span>') : ''}</div>
</div></header>
<nav class="bar"><div class="wrap">
  <div class="tabs" role="tablist">
    <button role="tab" aria-selected="true" data-view="architecture">Architecture</button>
    <button role="tab" aria-selected="false" data-view="sequence">Sequence</button>
    ${diff ? `<button role="tab" aria-selected="false" data-view="changes">Changes${nChanged ? ` <span class="mono muted">${nChanged}</span>` : ''}</button>` : ''}
    <button role="tab" aria-selected="false" data-view="inventory">Inventory</button>
    <button role="tab" aria-selected="false" data-view="evidence">Evidence</button>
  </div>
  <div class="tools">
    <div class="seg" role="group" aria-label="Icons"><button data-icons="aws" aria-pressed="true" title="AWS icons in AWS's colours">AWS colours</button><button data-icons="quiet" aria-pressed="false" title="Icons in the theme's colour">Quiet</button></div>
    <div class="seg" role="group" aria-label="Theme"><button data-theme-set="auto" aria-pressed="true">Auto</button><button data-theme-set="dark" aria-pressed="false">Dark</button><button data-theme-set="light" aria-pressed="false">Light</button></div>
  </div>
</div></nav>
<main class="wrap">
  <section class="view on" id="view-architecture" role="tabpanel">
    <div class="arch">
      <div class="stage">${viewbar}
      <div class="canvas" id="canvas">${arch}
        <div class="legend" aria-hidden="true"><span><svg width="26" height="6"><path d="M0 3H26" stroke="var(--line-strong)" stroke-width="1.5"/></svg>request</span><span><svg width="26" height="6"><path d="M0 3H26" stroke="var(--line-strong)" stroke-width="1.5" stroke-dasharray="6 5"/></svg>async</span><span><svg width="26" height="6"><path d="M0 3H26" stroke="var(--olive)" stroke-width="1.5"/></svg>identity</span><span><svg width="26" height="6"><path d="M0 3H26" stroke="var(--line-strong)" stroke-width="1.5" stroke-dasharray="2 4"/></svg>deploy / control</span>${diff || planned ? `<span><i class="sw c-add"></i>${diff ? 'added' : 'to build'}</span><span><i class="sw c-mod"></i>${diff ? 'changed' : 'to change'}</span><span><i class="sw c-del"></i>${diff ? 'removed' : 'to remove'}</span>` : ''}</div>
        <div class="hint" id="hint" hidden>Scroll or pinch to zoom in, or pick a flow to follow it close up</div>
        <div class="canvas-tools">${nFlows ? `<select class="btn" id="flow-quick" aria-label="Follow a flow"><option value="">Follow a flow…</option>${model.flows.map((f) => `<option value="${esc(f.id)}">${esc(f.title)}</option>`).join('')}</select>` : ''}${diff || planned ? `<button class="btn" id="only-changes" aria-pressed="false" title="Fade what ${diff ? 'did not change' : 'the plan leaves as it is'} and move to what ${diff ? 'did' : 'it touches'} (C)">Only ${diff ? 'changes' : 'the plan'}</button>` : ''}<button class="btn" id="ask" title="Copy a reference to what is selected, to paste to your assistant (A)">Ask about this</button><button class="btn" id="present" title="Full screen, the flows step by step (P)">Present</button><button class="btn" id="panel-toggle" aria-pressed="false" title="Show or hide flows and the inspector">Hide panel</button></div>
        <div class="caption" id="caption" hidden><span class="keys">← → step · E explain · Esc leave</span><span class="label" id="caption-where"></span><p id="caption-text"></p><p class="explain" id="caption-explain"></p></div>
        <div class="zoom"><button class="btn" data-zoom="in" aria-label="Zoom in">+</button><button class="btn" data-zoom="out" aria-label="Zoom out">−</button><button class="btn" data-zoom="fit">Fit</button></div>
      </div></div>
      <aside class="side">
        ${diff || planned ? changesCard(model, diff) : ''}
        <div class="card" id="discussion-card" hidden></div>
        <div class="card" id="flows-card"><span class="label">Flows</span><h2>${nFlows ? 'Follow a request' : 'No flows'}</h2><p class="muted" style="margin:0">${nFlows ? 'Pick a flow to number its steps on the diagram, as in a reference architecture. ← → step, Space plays.' : 'The analysis traced no flows.'}</p><div class="flows" id="flows"></div><ol class="steps" id="steps"></ol><div class="player" id="player" hidden><button class="btn" data-step="prev" aria-label="Previous step">←</button><button class="btn primary" data-step="play">Play</button><button class="btn" data-step="next" aria-label="Next step">→</button><button class="btn" data-step="clear">Clear</button></div></div>
        <div class="card" id="inspector"><span class="label">Inspector</span><h2>Click a component or a connection</h2><p class="muted" style="margin:0">Its responsibility, its connections and the code it was read from appear here.</p></div>
        ${notes}
      </aside>
    </div>
  </section>
  <section class="view" id="view-sequence" role="tabpanel">
    <div class="section-head"><h2>Sequence</h2><label class="muted">Flow <select id="seq-flow" class="btn"></select></label></div>
    <div class="seq-wrap" id="seq"></div>
  </section>
  ${diff ? `<section class="view" id="view-changes" role="tabpanel">
    <div class="section-head"><h2>Changes</h2><span class="muted">${nChanged ? `The code from ${esc(diff.base.label)} to ${esc(diff.head.label)}, file by file, with the components each file belongs to. A file no component cites is a change the architecture does not show.` : 'No code changes were given: pass --repo, --base and --head to blueprint diff to see them.'}</span></div>
    <div id="changes-list"></div>
  </section>` : ''}
  <section class="view" id="view-inventory" role="tabpanel">
    <div class="section-head"><h2>Inventory</h2><span class="muted">What the scanner read from the code, before any model.</span></div>
    ${coverageCard(left)}${tracedCard(model, repoRoot)}${ledger(model)}${inventory(facts, moduleSvg, cover)}
  </section>
  <section class="view" id="view-evidence" role="tabpanel">
    <div class="section-head"><h2>Evidence</h2><span class="muted">Every citation, by file, with the lines it points at.</span></div>
    <div id="evidence-list"></div>
  </section>
</main>
<footer class="foot"><div class="wrap">${diff ? `Diff of ${esc(diff.base.label)} and ${esc(diff.head.label)} · ` : ''}Blueprint · ${esc(generated)}${analyst ? ` · analysis by ${esc(analyst)}` : ''} · citations checked against ${esc(repo.name ?? 'the repository')}${repo.commit ? ` at ${esc(repo.commit.slice(0, 12))}` : ''}.${model.style ? ` Written to ${esc(model.style.standard)}: ${model.style.hard} rule ${model.style.hard === 1 ? 'break' : 'breaks'} in ${model.style.words} words.` : ''} Components, connections and flows come from the analysis; the inventory comes from the code alone. AWS icons © Amazon Web Services, used per the AWS Architecture Icons terms.</div></footer>
<script type="application/json" id="data">${JSON.stringify(data).replace(/</g, '\\u003c')}</script>
<script>${js}</script>
</body>
</html>`;
}

/** Several proposals for one change side by side: one column each and the same rows, so the reader compares across.
 * `entries` are [{model, href}]; every column links to the proposal's own page. No script: the page is a table. */
export async function comparePage(entries, {idea = null, recommendation = null, analyst = null} = {}) {
  const icons = new Icons();
  const cols = await Promise.all(entries.map(async ({model}, i) => {
    const v = viewsOf(model).find((x) => x.kind === 'system');
    return diagram(v.graph, await bestLayout(v.graph), icons, {prefix: `c${i}`, label: model.title, all: model.nodes, touched: touchedOf(model)});
  }));
  const ul = (l, tag = 'ul') => (l?.length ? `<${tag} class="list">${l.map((x) => `<li>${esc(x)}</li>`).join('')}</${tag}>` : '<span class="muted">Nothing recorded.</span>');
  const count = (m, st) => [...m.nodes, ...m.edges].filter((x) => x.status === st).length;
  const rows = [
    ['Architecture', (m, i) => `<div class="canvas static">${cols[i]}</div>`],
    ['What it is', (m) => esc(m.summary)],
    ['The plan', (m) => `<b class="c-add">${count(m, 'planned')}</b> to build · <b class="c-mod">${count(m, 'changed')}</b> to change · <b class="c-del">${count(m, 'removed')}</b> to remove<br><span class="muted">${m.nodes.length} components, ${m.edges.length} connections after it</span>`],
    ['For it', (m) => ul(m.proposal?.pros)],
    ['Against it', (m) => ul(m.proposal?.cons)],
    ['Steps', (m) => ul(m.proposal?.migration, 'ol')],
    ['Not known', (m) => ul(m.unknowns)],
    // What was said over each page and what was read for it, when a page has any.
    ...(entries.some(({model}) => model.discussion?.length) ? [['Discussion', (m) => (m.discussion?.length ? `<ul class="list plain">${m.discussion.map((d) => `<li><span class="tag ${d.status === 'decided' ? 'olive' : d.status === 'open' ? 'sea' : ''}">${esc(d.status)}</span> ${esc(d.title)}</li>`).join('')}</ul>` : '<span class="muted">Nothing said yet.</span>')]] : []),
    ...(entries.some(({model}) => model.sources?.length) ? [['Read for it', (m) => (m.sources?.length ? `<ul class="list plain">${m.sources.map((x) => `<li>${/^https?:\/\//.test(x.url) ? `<a href="${esc(x.url)}" target="_blank" rel="noopener">${esc(x.title)}</a>` : esc(x.title)}${x.note ? `<br><span class="muted">${esc(x.note)}</span>` : ''}</li>`).join('')}</ul>` : '<span class="muted">No source named.</span>')]] : []),
  ];
  const head = entries.map(({model, href}, i) => `<th scope="col"><span class="label">Option ${i + 1}</span><h2>${href ? `<a href="${esc(href)}">${esc(model.proposal?.approach ?? model.title)}</a>` : esc(model.proposal?.approach ?? model.title)}</h2></th>`).join('');
  const body = rows.map(([title, cell]) => `<tr><th scope="row">${title}</th>${entries.map(({model}, i) => `<td>${cell(model, i)}</td>`).join('')}</tr>`).join('');
  const title = idea ?? entries[0].model.proposal?.problem ?? `${entries.length} proposals`;
  const css = readFileSync(path.join(here, 'page.css'), 'utf8');
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Compare: ${esc(title.slice(0, 60))} · Blueprint</title>
<style>${embeddedFontFaces(NODE_MODULES)}${cssVariables()}${typeClasses()}${css}</style>
</head>
<body>
${icons.defs()}
<header class="masthead"><div class="wrap">
  <div class="brand"><span class="logo">rh<b>.</b></span><span class="label">Blueprint</span><span class="crumbs"><span class="tag sea">Compare</span><span class="mono">${entries.length} proposals</span></span></div>
  <h1>${entries.length} ways to do it</h1>
  <p class="summary open">${esc(title)}</p>
</div></header>
<main class="wrap" style="padding-top:24px">
  ${recommendation ? `<div class="card proposal" style="margin-bottom:24px;max-width:110ch"><span class="label">Recommendation${analyst ? ` · ${esc(analyst)}` : ''}</span><p style="margin:8px 0 0;font-size:16px;line-height:26px">${esc(recommendation)}</p><p class="muted" style="margin:8px 0 0">One architect's opinion. The table below is what it rests on.</p></div>` : ''}
  <div class="compare-wrap"><table class="t compare" style="min-width:${entries.length * 340 + 120}px"><thead><tr><th></th>${head}</tr></thead><tbody>${body}</tbody></table></div>
</main>
<footer class="foot"><div class="wrap">Blueprint · ${new Date().toISOString().slice(0, 10)}${analyst ? ` · sketches by ${esc(analyst)}` : ''} · Planned parts are a proposal: nothing here says they exist. AWS icons © Amazon Web Services, used per the AWS Architecture Icons terms.</div></footer>
</body>
</html>`;
}

export {NODE, wrap};
