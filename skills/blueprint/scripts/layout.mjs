// Where everything goes, worked out by ELK's layered algorithm (Eclipse Layout Kernel, EPL-2.0): components in
// columns in the direction things flow, zones as boxes around their components and zones, edges routed at right
// angles with room for their labels. Nothing on the page has a hand-set coordinate.
import ELK from 'elkjs/lib/elk.bundled.js';

export const NODE = {width: 152, height: 124};
/** An edge label is set in at most two lines of this many characters, so columns can stand close. */
export const LABEL_CHARS = 18;
const LABEL_FONT = 12;

/** Roughly how wide a label is at the edge label size: Hanken Grotesk averages about 0.55em. */
/** `text` in lines of at most `width` characters, at most `lines` of them, the last one ending in … if cut. */
export function wrap(text, width, lines) {
  const words = String(text).split(/\s+/).filter(Boolean);
  const out = [];
  let cur = '';
  for (const w of words) {
    if (!cur) cur = w;
    else if ((cur + ' ' + w).length <= width) cur += ' ' + w;
    else { out.push(cur); cur = w; }
  }
  if (cur) out.push(cur);
  const kept = out.slice(0, lines).map((l) => (l.length > width ? l.slice(0, width - 1) + '…' : l));
  if (out.length > lines) kept[lines - 1] = kept[lines - 1].length < width ? `${kept[lines - 1]}…` : kept[lines - 1].replace(/.?$/, '…');
  return kept;
}

/** The lines an edge label is set in. */
export function labelLines(label) {
  return wrap(label, LABEL_CHARS, 2);
}

export function textWidth(text, size = LABEL_FONT) {
  return Math.ceil([...text].length * size * 0.56) + 16;
}

/**
 * Lays out a graph of `zones` (with optional `parent`), `nodes` (with optional `zone`) and `edges` (`from`, `to`,
 * `label`). Returns absolute boxes for zones and nodes and polylines for edges, plus the label boxes, in one frame.
 */
export async function layout({zones = [], nodes, edges}, {direction = 'RIGHT', options = {}} = {}) {
  const elk = new ELK();
  // Labels are placed afterwards, on the edges (placeLabels): given to ELK, every label becomes a column of its own
  // and the diagram twice as wide. The gap between columns is made to hold most labels instead.
  const widths = edges.filter((e) => e.label).map((e) => Math.max(...labelLines(e.label).map((l) => textWidth(l)))).sort((a, b) => a - b);
  // Rasmus 2026-11-02: arrows hidden behind their labels and edges too close together. The gap now holds 80 % of the
  // labels with at least 32 px of arrow either side; the page pans and zooms, so a larger diagram is fine.
  const typical = widths.length ? widths[Math.floor(widths.length * 0.8)] : 0;
  const gap = direction === 'RIGHT' || direction === 'LEFT' ? Math.min(Math.max(typical + 72, 128), 240) : 112;
  const zoneNode = new Map(zones.map((z) => [z.id, {
    id: z.id, children: [],
    // Spacing is not inherited inside a zone: without these, columns in a zone sit 20 apart, with no room for labels.
    layoutOptions: {'elk.padding': '[top=60,left=36,bottom=36,right=36]', 'elk.spacing.nodeNode': '48', 'elk.layered.spacing.nodeNodeBetweenLayers': String(gap), 'elk.layered.spacing.edgeNodeBetweenLayers': '36', 'elk.spacing.edgeEdge': '24', 'elk.layered.spacing.edgeEdgeBetweenLayers': '20'},
  }]));
  const root = {
    id: '__root',
    layoutOptions: {
      'elk.algorithm': 'layered',
      'elk.direction': direction,
      'elk.hierarchyHandling': 'INCLUDE_CHILDREN',
      'elk.edgeRouting': 'ORTHOGONAL',
      'elk.layered.spacing.nodeNodeBetweenLayers': String(gap),
      'elk.spacing.nodeNode': '48',
      'elk.layered.spacing.edgeNodeBetweenLayers': '36',
      'elk.spacing.edgeEdge': '24',
      'elk.layered.spacing.edgeEdgeBetweenLayers': '20',
      'elk.spacing.componentComponent': '64',
      'elk.layered.nodePlacement.strategy': 'NETWORK_SIMPLEX',
      'elk.layered.considerModelOrder.strategy': 'NODES_AND_EDGES',
      'elk.layered.crossingMinimization.forceNodeModelOrder': 'false',
      'elk.padding': '[top=24,left=24,bottom=24,right=24]',
      'org.eclipse.elk.json.edgeCoords': 'ROOT',
      'org.eclipse.elk.json.shapeCoords': 'ROOT',
      ...options,
    },
    children: [],
    edges: [],
  };
  for (const z of zones) (z.parent && zoneNode.has(z.parent) ? zoneNode.get(z.parent).children : root.children).push(zoneNode.get(z.id));
  for (const n of nodes) {
    const box = {id: n.id, width: n.width ?? NODE.width, height: n.height ?? NODE.height};
    (n.zone && zoneNode.has(n.zone) ? zoneNode.get(n.zone).children : root.children).push(box);
  }
  // An empty zone would be drawn as a box with nothing in it; ELK needs it to have a size.
  for (const z of zoneNode.values()) if (z.children.length === 0) { z.width = 160; z.height = 80; }
  for (const e of edges) {
    root.edges.push({
      id: e.id, sources: [e.from], targets: [e.to],
    });
  }
  const done = await elk.layout(root);
  const out = {width: Math.ceil(done.width), height: Math.ceil(done.height), zones: [], nodes: [], edges: []};
  const walk = (n, depth) => {
    for (const c of n.children ?? []) {
      if (zoneNode.has(c.id)) {
        out.zones.push({id: c.id, x: c.x, y: c.y, w: c.width, h: c.height, depth});
        walk(c, depth + 1);
      } else {
        out.nodes.push({id: c.id, x: c.x, y: c.y, w: c.width, h: c.height});
      }
    }
  };
  walk(done, 0);
  for (const e of done.edges ?? []) {
    const points = [];
    for (const s of e.sections ?? []) {
      const seq = [s.startPoint, ...(s.bendPoints ?? []), s.endPoint];
      for (const p of seq) {
        const last = points[points.length - 1];
        if (!last || last.x !== p.x || last.y !== p.y) points.push({x: p.x, y: p.y});
      }
    }
    const label = edges.find((x) => x.id === e.id)?.label;
    const lines = label ? labelLines(label) : [];
    out.edges.push({id: e.id, points, label: label ? {w: Math.max(...lines.map((l) => textWidth(l))), h: 8 + lines.length * 15} : null});
  }
  placeLabels(out);
  return out;
}

const overlaps = (a, b, gap = 4) => a.x < b.x + b.w + gap && b.x < a.x + a.w + gap && a.y < b.y + b.h + gap && b.y < a.y + a.h + gap;

/** Puts each edge label on its own edge where it covers no other label and no component: the middle of a straight run
 * long enough for it, else the nearest free place along the edge. ELK reserves room for labels but, across nested
 * zones, can stack them over each other. Room is left before the label for step numbers. */
export function placeLabels(lay) {
  const taken = lay.nodes.map((n) => ({x: n.x - 2, y: n.y - 2, w: n.w + 4, h: n.h + 4}));
  const area = (a, b) => Math.max(0, Math.min(a.x + a.w, b.x + b.w) - Math.max(a.x, b.x) + 4) * Math.max(0, Math.min(a.y + a.h, b.y + b.h) - Math.max(a.y, b.y) + 4);
  // Short edges first: they have the fewest places to go.
  const edges = [...lay.edges].filter((e) => e.label).sort((a, b) => length(a.points) - length(b.points));
  for (const e of edges) {
    const {w, h} = e.label;
    const candidates = [];
    for (let i = 1; i < e.points.length; i++) {
      const a = e.points[i - 1];
      const b = e.points[i];
      const horizontal = Math.abs(a.y - b.y) < 0.5;
      const len = Math.abs(a.x - b.x) + Math.abs(a.y - b.y);
      for (let f = 0.5, k = 0; k < 19; k++, f = 0.5 + (k % 2 ? 1 : -1) * Math.ceil(k / 2) * 0.05) {
        const cx = a.x + (b.x - a.x) * f;
        const cy = a.y + (b.y - a.y) * f;
        // On a horizontal run the label sits on the line, with room before it for step numbers; on a vertical one,
        // beside it, either side.
        const boxes = horizontal ? [{x: cx - w / 2, y: cy - h / 2, w, h}] : [{x: cx + 8, y: cy - h / 2, w, h}, {x: cx - 8 - w, y: cy - h / 2, w, h}];
        const fits = horizontal ? len >= w + 64 : len >= h + 24;
        for (const box of boxes) candidates.push({box, cost: (fits ? 0 : 50) + Math.abs(f - 0.5) * 8 + (horizontal ? 0 : 6)});
      }
    }
    let best = null;
    for (const c of candidates) {
      const room = {...c.box, x: c.box.x - 26, w: c.box.w + 26};
      const hit = taken.reduce((n, t) => n + (overlaps(room, t) ? area(room, t) : 0), 0);
      const cost = c.cost + hit;
      if (!best || cost < best.cost) best = {box: c.box, cost};
      if (hit === 0 && c.cost === 0) break;
    }
    e.label = {...best.box};
    taken.push({...best.box, x: best.box.x - 26, w: best.box.w + 26});
  }
}

function length(points) {
  let n = 0;
  for (let i = 1; i < points.length; i++) n += Math.abs(points[i].x - points[i - 1].x) + Math.abs(points[i].y - points[i - 1].y);
  return n;
}

/** Lays the graph out left to right and top to bottom and keeps the one that shows largest in a frame of `aspect`
 * (width over height), unless the model asks for a direction. */
export async function bestLayout(graph, {aspect = 1.7, direction = null} = {}) {
  if (direction) return layout(graph, {direction});
  const tries = await Promise.all(['RIGHT', 'DOWN'].map((d) => layout(graph, {direction: d})));
  const scale = (l) => Math.min(aspect / l.width, 1 / l.height);
  return scale(tries[0]) >= scale(tries[1]) * 0.9 ? tries[0] : tries[1];
}

/** The middle of an edge's longest straight run: where a step number sits. */
export function badgePoint(points) {
  let best = null;
  for (let i = 1; i < points.length; i++) {
    const a = points[i - 1];
    const b = points[i];
    const len = Math.abs(a.x - b.x) + Math.abs(a.y - b.y);
    if (!best || len > best.len) best = {len, x: (a.x + b.x) / 2, y: (a.y + b.y) / 2};
  }
  return best ?? {x: points[0]?.x ?? 0, y: points[0]?.y ?? 0};
}
