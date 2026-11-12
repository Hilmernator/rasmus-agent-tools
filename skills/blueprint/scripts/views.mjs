// The views of one model, so a large system reads in parts and in order: an overview with one box for each area (a
// part of the system by what it is for: ingestion, retrieval, the agent, the API), the whole system with the areas
// as labelled groups, each area on its own with the components it talks to around it, and the feature views the
// model names. Every view is a graph the layout and the diagram take as they are.

/** The area a node belongs to: its zone, or the nearest zone around it, whose kind is "area". */
export function areaOf(model, node) {
  let z = model.zones?.find((x) => x.id === node.zone);
  while (z && z.kind !== 'area') z = model.zones.find((x) => x.id === z.parent);
  return z ?? null;
}

/** The areas, in the model's order, each with its letter: A, B, C… */
export function areas(model) {
  return (model.zones ?? []).filter((z) => z.kind === 'area').map((z, i) => ({...z, letter: String.fromCharCode(65 + (i % 26))}));
}

/** The zones a set of nodes needs: theirs and every zone around them. */
function zonesFor(model, nodes, lettered) {
  const need = new Set();
  for (const n of nodes) { let z = n.zone; while (z && !need.has(z)) { need.add(z); z = model.zones.find((x) => x.id === z)?.parent; } }
  return (model.zones ?? []).filter((z) => need.has(z.id)).map((z) => lettered.get(z.id) ?? z);
}

function flowsWithin(model, edgeIds) {
  return (model.flows ?? []).filter((f) => f.steps.every((s) => edgeIds.has(s.edge))).map((f) => f.id);
}

function subgraph(model, nodeIds, lettered, extra = {}) {
  const nodes = model.nodes.filter((n) => nodeIds.has(n.id));
  const edges = model.edges.filter((e) => nodeIds.has(e.from) && nodeIds.has(e.to));
  return {graph: {zones: zonesFor(model, nodes, lettered), nodes, edges}, flows: flowsWithin(model, new Set(edges.map((e) => e.id))), ...extra};
}

export function views(model) {
  const lettered = new Map(areas(model).map((a) => [a.id, {...a, label: `${a.letter} · ${a.label}`}]));
  const shown = model.nodes.filter((n) => !n.detail);
  const out = [];
  const list = areas(model);
  // The overview: an area is one box, an edge between areas one arrow with how many connections it stands for.
  if (list.length >= 2) {
    const boxOf = new Map();
    const nodes = [];
    for (const a of list) {
      const members = shown.filter((n) => areaOf(model, n)?.id === a.id);
      if (!members.length) continue;
      const id = `area-${a.id}`;
      for (const m of members) boxOf.set(m.id, id);
      nodes.push({id, label: a.label, kind: 'area', letter: a.letter, area: a.id, zone: a.parent ?? undefined, tech: `${members.length} ${members.length === 1 ? 'component' : 'components'}`, responsibility: a.note ?? `${members.map((m) => m.label).join(', ')}.`, members: members.map((m) => m.id), width: 264, height: 150});
    }
    for (const n of shown) if (!boxOf.has(n.id)) { boxOf.set(n.id, n.id); nodes.push(n); }
    const merged = new Map();
    for (const e of model.edges) {
      const from = boxOf.get(e.from);
      const to = boxOf.get(e.to);
      if (!from || !to || from === to) continue;
      const key = `${from}\u0000${to}`;
      const m = merged.get(key) ?? {id: `ov-${merged.size}`, from, to, kind: e.kind, protocol: e.protocol, members: [], evidence: e.evidence};
      m.members.push(e.id);
      merged.set(key, m);
    }
    const edges = [...merged.values()].map((m) => ({...m, label: m.members.length === 1 ? model.edges.find((e) => e.id === m.members[0]).label : `${model.edges.find((e) => e.id === m.members[0]).label} +${m.members.length - 1}`}));
    const used = nodes.filter((n) => n.kind === 'area' || edges.some((e) => e.from === n.id || e.to === n.id));
    const zoneNodes = used.map((n) => (n.kind === 'area' ? {zone: n.zone} : n));
    out.push({id: 'overview', title: 'Overview', kind: 'overview', summary: 'Each part of the system as one box. Open a part to see its components.', graph: {zones: zonesFor(model, zoneNodes, lettered).filter((z) => z.kind !== 'area'), nodes: used, edges}, flows: []});
  }
  out.push({id: 'system', title: 'Whole system', kind: 'system', ...subgraph(model, new Set(shown.map((n) => n.id)), lettered)});
  for (const a of list) {
    const inside = new Set(shown.filter((n) => areaOf(model, n)?.id === a.id).map((n) => n.id));
    if (inside.size < 1) continue;
    // Around the area, faded, what it talks to: so its edges have somewhere to go.
    const around = new Set(model.edges.flatMap((e) => (inside.has(e.from) ? [e.to] : inside.has(e.to) ? [e.from] : [])).filter((id) => !inside.has(id) && !model.nodes.find((n) => n.id === id)?.detail));
    out.push({id: `area-${a.id}`, title: `${a.letter} · ${a.label}`, kind: 'area', summary: a.note ?? '', context: [...around], ...subgraph(model, new Set([...inside, ...around]), lettered)});
  }
  for (const v of model.views ?? []) {
    const view = subgraph(model, new Set(v.nodes), lettered, {id: `view-${v.id}`, title: v.title, kind: 'feature', summary: v.summary ?? ''});
    if (v.flows?.length) view.flows = v.flows;
    out.push(view);
  }
  return out;
}
