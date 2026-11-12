(() => {
  const data = JSON.parse(document.getElementById('data').textContent);
  const {model, excerpts, links, diff} = data;
  // The view on screen: its diagram, its size and where its components and step numbers are.
  let layout = null;
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => [...el.querySelectorAll(s)];
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
  const nodes = new Map(model.nodes.map((n) => [n.id, n]));
  const edges = new Map(model.edges.map((e) => [e.id, e]));
  const flows = model.flows ?? [];
  const store = {
    get(k) { try { return localStorage.getItem(`blueprint:${k}`); } catch { return null; } },
    set(k, v) { try { localStorage.setItem(`blueprint:${k}`, v); } catch { /* private window */ } },
  };

  // The summary shows two lines until asked for the rest.
  const summary = $('#summary');
  const more = $('#more');
  if (summary.scrollHeight > summary.clientHeight + 2) {
    more.hidden = false;
    more.addEventListener('click', () => {
      const open = summary.classList.toggle('open');
      more.textContent = open ? 'Show less' : 'Read the whole summary';
    });
  }

  // Theme and icon colours, remembered for this viewer.
  const setTheme = (t) => {
    if (t === 'auto') delete document.documentElement.dataset.theme; else document.documentElement.dataset.theme = t;
    $$('[data-theme-set]').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.themeSet === t)));
    store.set('theme', t);
  };
  const setIcons = (m) => {
    document.body.classList.toggle('quiet', m === 'quiet');
    $$('[data-icons]').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.icons === m)));
    store.set('icons', m);
  };
  $$('[data-theme-set]').forEach((b) => b.addEventListener('click', () => setTheme(b.dataset.themeSet)));
  $$('[data-icons]').forEach((b) => b.addEventListener('click', () => setIcons(b.dataset.icons)));
  setTheme(store.get('theme') ?? 'auto');
  setIcons(store.get('icons') ?? 'aws');

  // Tabs.
  // Coming back to the diagram from another tab fits it again; staying on it keeps the view, and the camera.
  const show = (view) => {
    const was = document.querySelector('.view.on')?.id;
    $$('.tabs [role=tab]').forEach((t) => t.setAttribute('aria-selected', String(t.dataset.view === view)));
    $$('.view').forEach((v) => v.classList.toggle('on', v.id === `view-${view}`));
    if (view === 'architecture' && was !== 'view-architecture') requestAnimationFrame(() => fit());
    if (view === 'sequence') drawSequence();
  };
  $$('.tabs [role=tab]').forEach((t) => t.addEventListener('click', () => show(t.dataset.view)));
  $$('[data-tab]').forEach((a) => a.addEventListener('click', (ev) => { ev.preventDefault(); show(a.dataset.tab); }));

  // Code, lightly highlighted in Rosé Pine, as the design system asks for code.
  const KW = /\b(async|await|break|case|catch|class|const|continue|def|default|elif|else|enum|export|extends|fn|for|from|func|function|if|impl|import|in|interface|let|match|mod|module|mut|new|pub|raise|resource|return|self|static|struct|switch|this|throw|trait|try|type|use|var|while|with|yield|true|false|null|None|True|False|undefined)\b/g;
  const highlight = (line) => {
    const out = [];
    const re = /(\/\/.*$|#(?!\[).*$|\/\*.*?\*\/|"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`)|(\b\d[\d_.]*\b)|([A-Za-z_]\w*)(?=\s*\()/g;
    let last = 0;
    let m;
    const plain = (s) => esc(s).replace(KW, '<span class="kw">$1</span>');
    while ((m = re.exec(line))) {
      out.push(plain(line.slice(last, m.index)));
      if (m[1]) out.push(`<span class="${/^(\/\/|#|\/\*)/.test(m[1]) ? 'com' : 'str'}">${esc(m[1])}</span>`);
      else if (m[2]) out.push(`<span class="nu">${esc(m[2])}</span>`);
      else out.push(KW.test(m[3]) ? plain(m[3]) : `<span class="fn">${esc(m[3])}</span>`);
      KW.lastIndex = 0;
      last = re.lastIndex;
    }
    out.push(plain(line.slice(last)));
    return out.join('');
  };
  const evidenceHtml = (list) => (list ?? []).map((ev) => {
    const key = ev.lines ? `${ev.path}:${ev.lines[0]}-${ev.lines[1]}` : null;
    const ex = key ? excerpts[key] : null;
    const url = links[`${ev.path}:${ev.lines?.join('-') ?? ''}`];
    const where = `${ev.path}${ev.lines ? `:${ev.lines[0]}${ev.lines[1] !== ev.lines[0] ? `–${ev.lines[1]}` : ''}` : ''}`;
    const code = ex ? `<pre class="code">${ex.text.split('\n').map((l, i) => `<span class="row"><span class="ln">${ex.start + i}</span>${highlight(l)}</span>`).join('')}</pre>${ex.cut ? `<div class="cut">… ${ex.end - ex.start - 59} more lines</div>` : ''}` : '';
    return `<div class="ev"><div class="ev-head"><span>${esc(where)}</span>${url ? `<a href="${esc(url)}" target="_blank" rel="noopener">Source ↗</a>` : ''}</div>${ev.why ? `<div class="ev-why">${esc(ev.why)}</div>` : ''}${code}</div>`;
  }).join('');

  // A part's plan, or on a diff page its change: what was there before, and the code that changed under it.
  const WORD = {added: 'Added', changed: 'Changed', removed: 'Removed'};
  const PLAN = {planned: 'Planned', changed: 'Plan changes it', removed: 'Plan removes it'};
  // A sentence that changed shows the words that changed: what both share stays, the rest is struck out or added.
  // Two sentences that share less than half their words are shown whole, one under the other.
  // ponytail: a table of words by words, fine for a sentence; a field of thousands of words wants Myers.
  const wordDiff = (a, b) => {
    const x = a.match(/\s*\S+/g) ?? [], y = b.match(/\s*\S+/g) ?? [];
    const t = Array.from({length: x.length + 1}, () => new Uint16Array(y.length + 1));
    for (let i = x.length - 1; i >= 0; i--) for (let j = y.length - 1; j >= 0; j--) t[i][j] = x[i] === y[j] ? t[i + 1][j + 1] + 1 : Math.max(t[i + 1][j], t[i][j + 1]);
    if (t[0][0] * 2 < Math.max(x.length, y.length)) return null;
    let out = '', i = 0, j = 0, del = '', ins = '';
    const flush = () => { out += (del ? `<del>${esc(del)}</del>` : '') + (ins ? `<ins>${esc(ins)}</ins>` : ''); del = ins = ''; };
    while (i < x.length || j < y.length) {
      if (i < x.length && j < y.length && x[i] === y[j]) { flush(); out += esc(x[i]); i++; j++; }
      else if (j < y.length && (i === x.length || t[i][j + 1] >= t[i + 1][j])) ins += y[j++];
      else del += x[i++];
    }
    flush();
    return out;
  };
  const fieldDiff = (was, now) => {
    const words = typeof was === 'string' && typeof now === 'string' ? wordDiff(was, now) : null;
    const text = (v) => esc(typeof v === 'object' ? JSON.stringify(v) : v ?? '—');
    return words ? `<dd class="words">${words}</dd>` : `<dd><del>${text(was)}</del><ins>${text(now)}</ins></dd>`;
  };
  const changeHtml = (x) => {
    let out = '';
    if (x.change) out += `<p style="margin:0 0 8px"><span class="tag ${x.change === 'added' ? 'olive' : x.change === 'changed' ? 'sea' : 'del'}">${WORD[x.change]}</span></p>`;
    if (x.change === 'changed') {
      const rows = x.changed.filter((f) => f !== 'evidence').map((f) => `<dt>${esc(f)}</dt>${fieldDiff(x.before[f], x[f])}`).join('');
      out += rows ? `<dl class="kv was">${rows}</dl>` : '';
      if (x.changed.includes('evidence')) out += '<p class="muted" style="margin:0 0 8px">It rests on other files than before.</p>';
    }
    if (x.status && x.status !== 'built') out += `<p style="margin:0 0 8px"><span class="tag ${x.status === 'planned' ? 'olive' : x.status === 'changed' ? 'sea' : 'del'}">${PLAN[x.status]}</span>${x.plan ? ` ${esc(x.plan)}` : ''}</p>`;
    return out;
  };
  // A line that was rewritten shows what changed inside it: a run of removed lines followed by as many added lines is
  // paired line by line, and the part between what they share at the start and at the end is marked.
  // ponytail: one changed span per line, from the common prefix and suffix; a word diff when a line changes in two places.
  const inner = (x, y) => {
    let p = 0;
    while (p < x.length && p < y.length && x[p] === y[p]) p++;
    let q = 0;
    while (q < x.length - p && q < y.length - p && x[x.length - 1 - q] === y[y.length - 1 - q]) q++;
    // Lines that share little are two different lines, not one that changed.
    return (p + q) * 2.5 >= Math.max(x.length, y.length) ? [p, q] : null;
  };
  const marked = (l, cut) => (cut && cut[0] + cut[1] < l.length ? `${highlight(l.slice(0, cut[0]))}<mark>${esc(l.slice(cut[0], l.length - cut[1]))}</mark>${highlight(l.slice(l.length - cut[1]))}` : highlight(l));
  const patchHtml = (f, {open = f.adds + f.dels <= 200} = {}) => {
    let a = 0;
    let b = 0;
    const lines = f.patch.split('\n');
    const cuts = new Map();
    for (let i = 0; i < lines.length; i++) {
      if (lines[i][0] !== '-' || lines[i - 1]?.[0] === '-') continue;
      let d = i;
      while (lines[d]?.[0] === '-') d++;
      let e = d;
      while (lines[e]?.[0] === '+') e++;
      if (e - d !== d - i) continue;
      for (let k = 0; k < d - i; k++) {
        const cut = inner(lines[i + k].slice(1), lines[d + k].slice(1));
        // Past the + or - at the start of the line.
        if (cut) { cuts.set(i + k, [cut[0] + 1, cut[1]]); cuts.set(d + k, [cut[0] + 1, cut[1]]); }
      }
    }
    const rows = lines.map((l, i) => {
      const h = /^@@ -(\d+)(?:,\d+)? \+(\d+)/.exec(l);
      if (h) { a = +h[1]; b = +h[2]; return `<span class="row ph"><span class="ln"></span>${esc(l)}</span>`; }
      if (l.startsWith('\\')) return '';
      const kind = l[0] === '+' ? 'pa' : l[0] === '-' ? 'pd' : '';
      const n = kind === 'pd' ? a++ : (kind === 'pa' ? b++ : (a++, b++));
      return `<span class="row ${kind}"><span class="ln">${n}</span>${marked(l, cuts.get(i))}</span>`;
    }).join('');
    const owners = (f.owners ?? []).map((id) => `<button data-goto="${esc(id)}">${esc(nodes.get(id)?.label ?? `${nodes.get(edges.get(id)?.from)?.label} → ${nodes.get(edges.get(id)?.to)?.label}`)}</button>`).join('');
    return `<details class="ev patch-file"${open ? ' open' : ''}><summary class="ev-head"><span>${esc(f.from ? `${f.from} → ${f.path}` : f.path)}</span><span><span class="c-add">+${f.adds}</span> <span class="c-del">−${f.dels}</span> · ${esc(f.status)}</span></summary>${owners ? `<div class="refs">${owners}</div>` : ''}${f.patch ? `<pre class="code patch">${rows}</pre>` : '<div class="cut">No text changes to show.</div>'}${f.cut ? '<div class="cut">The patch is cut here.</div>' : ''}</details>`;
  };
  const codeChanges = (x) => {
    if (!diff?.files.length) return '';
    const files = new Set([...(x.evidence ?? []), ...(x.before?.evidence ?? [])].map((ev) => ev.path));
    const hit = diff.files.filter((f) => files.has(f.path) || files.has(f.from));
    return hit.length ? `<h3>Code changed under it</h3>${hit.map((f) => patchHtml(f, {open: true})).join('')}` : '';
  };

  // The diagram: pan and zoom by its viewBox.
  const canvas = $('#canvas');
  const viewList = data.views;
  let current = viewList.find((v) => v.id === data.start);
  let svg = $(`#v-${CSS.escape(current.id)}`);
  let W = +svg.dataset.w;
  let H = +svg.dataset.h;
  layout = current;
  let view = {x: 0, y: 0, w: W, h: H};
  const hint = $('#hint');
  const apply = () => {
    svg.setAttribute('viewBox', `${view.x} ${view.y} ${view.w} ${view.h}`);
    // Below about two thirds of life size the components' names are too small to read.
    hint.hidden = canvas.getBoundingClientRect().width / view.w >= 0.66 || svg.classList.contains('flowing');
  };
  // The canvas is as tall as the diagram needs at its width, up to the window: a wide diagram leaves no empty bands.
  const size = () => {
    const width = canvas.clientWidth;
    if (!width) return;
    // No taller than what shows below the header, so the whole diagram is on screen when the page opens.
    // On a short screen that would leave too little, so the diagram may fill the window below the tab bar instead,
    // a scroll past the header away.
    const below = innerHeight - (canvas.getBoundingClientRect().top + scrollY) - 24;
    const room = below >= innerHeight * 0.6 ? below : innerHeight - 110;
    const want = Math.round(Math.min(Math.max(width * H / W + 96, innerWidth < 720 ? 240 : 420), Math.max(room, 420)));
    if (Math.abs(canvas.clientHeight - want) > 2) canvas.style.height = `${want}px`;
  };
  const fit = () => {
    glide++;
    size();
    const r = canvas.getBoundingClientRect();
    if (!r.width) return;
    const pad = 24;
    // Never larger than one and a half times life size: a small diagram on an ultrawide screen stays a diagram.
    const s = Math.max(W / (r.width - pad * 2), H / (r.height - pad * 2 - 40), 1 / 1.5);
    const w = r.width * s;
    const h = r.height * s;
    view = {x: (W - w) / 2, y: (H - h) / 2 - 20 * s, w, h};
    apply();
  };
  const zoomAt = (k, cx, cy) => {
    const w = Math.min(Math.max(view.w * k, W / 12), W * 6);
    const real = w / view.w;
    view = {x: cx - (cx - view.x) * real, y: cy - (cy - view.y) * real, w, h: view.h * real};
    apply();
  };
  // A glide of the view to a box of the diagram, kept to at most life size; instant when motion is reduced.
  const still = matchMedia('(prefers-reduced-motion: reduce)').matches;
  let glide = 0;
  const frameBox = (box) => {
    const r = canvas.getBoundingClientRect();
    // While presenting, the caption covers the bottom: the step is framed in the part above it.
    const covered = canvas.classList.contains('presenting') && !$('#caption').hidden ? $('#caption').getBoundingClientRect().height + 40 : 0;
    const s = Math.max(box.w / (r.width - 96), box.h / (r.height - 96 - covered), 1 / 1.1);
    const to = {w: r.width * s, h: r.height * s};
    to.x = box.x + box.w / 2 - to.w / 2;
    to.y = box.y + box.h / 2 - to.h / 2 + covered * s / 2;
    const from = {...view};
    const id = ++glide;
    const t0 = performance.now();
    const step = (now) => {
      if (id !== glide) return;
      const k = still ? 1 : Math.min(1, (now - t0) / 450);
      const e = k < 0.5 ? 2 * k * k : 1 - (-2 * k + 2) ** 2 / 2;
      view = {x: from.x + (to.x - from.x) * e, y: from.y + (to.y - from.y) * e, w: from.w + (to.w - from.w) * e, h: from.h + (to.h - from.h) * e};
      apply();
      if (k < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  };
  // How large the diagram shows now: below this a step is read close up.
  const shown = () => canvas.getBoundingClientRect().width / view.w;
  const toSvg = (ev) => {
    const r = svg.getBoundingClientRect();
    return {x: view.x + (ev.clientX - r.left) / r.width * view.w, y: view.y + (ev.clientY - r.top) / r.height * view.h};
  };
  const onDiagram = (ev) => !!ev.target.closest('svg.diagram');
  canvas.addEventListener('wheel', (ev) => {
    if (!onDiagram(ev)) return;
    ev.preventDefault();
    const p = toSvg(ev);
    zoomAt(Math.exp(ev.deltaY * (ev.ctrlKey ? 0.01 : 0.0015)), p.x, p.y);
  }, {passive: false});
  let drag = null;
  // Two fingers pinch to zoom and move together to pan.
  const touches = new Map();
  let pinch = null;
  const spread = () => { const [a, b] = [...touches.values()]; return {d: Math.hypot(a.x - b.x, a.y - b.y), x: (a.x + b.x) / 2, y: (a.y + b.y) / 2}; };
  canvas.addEventListener('pointerdown', (ev) => {
    if (!onDiagram(ev)) return;
    touches.set(ev.pointerId, {x: ev.clientX, y: ev.clientY});
    if (touches.size === 2) { pinch = {...spread(), view: {...view}}; drag = {moved: true}; return; }
    drag = {x: ev.clientX, y: ev.clientY, view: {...view}, moved: false, id: ev.pointerId};
  });
  canvas.addEventListener('pointermove', (ev) => {
    if (touches.has(ev.pointerId)) touches.set(ev.pointerId, {x: ev.clientX, y: ev.clientY});
    if (pinch && touches.size === 2) {
      const now = spread();
      const r = svg.getBoundingClientRect();
      const k = Math.min(Math.max(pinch.d / Math.max(now.d, 1), (W / 12) / pinch.view.w), (W * 6) / pinch.view.w);
      const w = pinch.view.w * k;
      const h = pinch.view.h * k;
      // The point under the fingers' midpoint at the start stays under it.
      const fx = pinch.view.x + (pinch.x - r.left) / r.width * pinch.view.w;
      const fy = pinch.view.y + (pinch.y - r.top) / r.height * pinch.view.h;
      view = {x: fx - (now.x - r.left) / r.width * w, y: fy - (now.y - r.top) / r.height * h, w, h};
      apply();
      return;
    }
    if (!drag || drag.id === undefined) return;
    const dx = ev.clientX - drag.x;
    const dy = ev.clientY - drag.y;
    if (!drag.moved && Math.hypot(dx, dy) < 4) return;
    if (!drag.moved) { drag.moved = true; canvas.setPointerCapture(drag.id); svg.classList.add('dragging'); }
    const r = svg.getBoundingClientRect();
    view.x = drag.view.x - dx / r.width * view.w;
    view.y = drag.view.y - dy / r.height * view.h;
    apply();
  });
  const endDrag = (ev) => {
    touches.delete(ev.pointerId);
    if (touches.size < 2) pinch = null;
    if (touches.size > 0) return;
    if (drag?.moved) { svg.classList.remove('dragging'); setTimeout(() => { drag = null; }, 0); } else drag = null;
  };
  canvas.addEventListener('pointerup', endDrag);
  canvas.addEventListener('pointercancel', endDrag);
  $$('[data-zoom]').forEach((b) => b.addEventListener('click', () => {
    if (b.dataset.zoom === 'fit') return fit();
    zoomAt(b.dataset.zoom === 'in' ? 0.8 : 1.25, view.x + view.w / 2, view.y + view.h / 2);
  }));
  // A new size keeps what is being looked at: the step of a flow the camera follows, or else the whole diagram.
  new ResizeObserver(() => (flow && camera && step >= 0 ? goStep(step) : fit())).observe(canvas);

  // The side panel folds away to give the diagram the whole width, and comes back when something is picked.
  const arch = $('.arch');
  const toggle = $('#panel-toggle');
  // Only a choice the reader makes is remembered: closing the drawer on a mid-size screen is not one.
  const panel = (open, {remember = false} = {}) => {
    arch.classList.toggle('wide', !open);
    toggle.textContent = open ? 'Hide panel' : 'Show panel';
    toggle.setAttribute('aria-pressed', String(!open));
    if (remember) store.set('panel', open ? 'open' : 'hidden');
    requestAnimationFrame(() => fit());
  };
  toggle.addEventListener('click', () => panel(arch.classList.contains('wide'), {remember: true}));
  // On a mid-size screen the panel is a drawer over the diagram: it starts closed and opens when something is picked.
  const drawer = () => innerWidth > 720 && innerWidth < 2000;
  if (store.get('panel') === 'hidden' || (drawer() && store.get('panel') !== 'open')) panel(false);

  // Only what changed: the rest of the diagram fades, and the view moves to the parts that differ.
  const only = $('#only-changes');
  const changedBox = () => {
    const boxes = $$('.node[class*=" chg-"],.node[class*=" st-"]', svg).map((g) => current.nodes[g.dataset.id]).filter(Boolean);
    if (!boxes.length) return null;
    const x = Math.min(...boxes.map((n) => n.x));
    const y = Math.min(...boxes.map((n) => n.y));
    return {x, y, w: Math.max(...boxes.map((n) => n.x + n.w)) - x, h: Math.max(...boxes.map((n) => n.y + n.h)) - y};
  };
  const onlyChanges = (on) => {
    canvas.classList.toggle('only-changes', on);
    only.setAttribute('aria-pressed', String(on));
    const box = on && changedBox();
    if (box) frameBox(box); else fit();
  };
  only?.addEventListener('click', () => onlyChanges(!canvas.classList.contains('only-changes')));
  document.addEventListener('keydown', (ev) => { if (only && ev.key === 'c' && !ev.metaKey && !ev.ctrlKey && !ev.altKey && !/^(INPUT|SELECT|TEXTAREA)$/.test(ev.target.tagName)) onlyChanges(!canvas.classList.contains('only-changes')); });
  const reveal = () => { if (arch.classList.contains('wide')) panel(true); };

  // Presenting: the canvas full screen, the camera on every step, the step written large. → starts the first flow and
  // runs on into the next one; Escape leaves.
  const caption = $('#caption');
  const presenting = () => canvas.classList.contains('presenting');
  const presentButton = $('#present');
  const leave = () => { canvas.classList.remove('presenting'); presentButton.textContent = 'Present'; caption.hidden = !flow; requestAnimationFrame(() => fit()); };
  const present = async () => {
    if (document.fullscreenElement) return document.exitFullscreen();
    if (presenting()) return leave();
    // Where full screen is not allowed (an embedded frame), the canvas fills the window instead.
    try { await canvas.requestFullscreen(); } catch { /* present in the window */ }
    canvas.classList.add('presenting');
    presentButton.textContent = 'Exit';
    requestAnimationFrame(() => fit());
  };
  document.addEventListener('fullscreenchange', () => { if (!document.fullscreenElement && presenting()) leave(); });
  presentButton.addEventListener('click', present);
  // The flows are one click away even when the panel is closed.
  const quick = $('#flow-quick');
  quick?.addEventListener('change', () => { if (quick.value) pickFlow(quick.value, 0); else stopFlow(); });

  // Selecting a component or a connection.
  const inspector = $('#inspector');
  const clearMarks = () => {
    svg.classList.remove('focus');
    $$('.sel,.near', svg).forEach((el) => el.classList.remove('sel', 'near'));
  };
  const connections = (id) => model.edges.filter((e) => e.from === id || e.to === id);
  const selectNode = (id, {hash = true} = {}) => {
    const n = nodes.get(id);
    if (!n) return;
    if (!current.nodes[id]) useView(viewWith([id])?.id, {hash: false});
    if (!presenting()) reveal();
    stopFlow();
    clearMarks();
    svg.classList.add('focus');
    $(`.node[data-id="${CSS.escape(id)}"]`, svg)?.classList.add('sel', 'near');
    for (const e of connections(id)) {
      $(`.edge[data-id="${CSS.escape(e.id)}"]`, svg)?.classList.add('near');
      $(`.node[data-id="${CSS.escape(e.from === id ? e.to : e.from)}"]`, svg)?.classList.add('near');
    }
    const out = model.edges.filter((e) => e.from === id);
    const inn = model.edges.filter((e) => e.to === id);
    const zone = (model.zones ?? []).find((z) => z.id === n.zone);
    const rel = (list, dir) => list.length ? `<h3>${dir}</h3><ul class="links">${list.map((e) => `<li><button data-edge="${esc(e.id)}">${dir === 'Calls and sends' ? '→' : '←'} ${esc(nodes.get(dir === 'Calls and sends' ? e.to : e.from)?.label)}</button> <span class="muted">${esc(e.label)}</span></li>`).join('')}</ul>` : '';
    inspector.innerHTML = `<span class="label">${esc(n.kind)}${zone ? ` · ${esc(zone.label)}` : ''}</span><h2>${esc(n.label)}</h2>${changeHtml(n)}${n.tech || n.service ? `<p class="mono muted" style="margin:0 0 8px">${esc([n.service, n.tech].filter(Boolean).join(' · '))}</p>` : ''}<p style="margin:0">${esc(n.responsibility)}</p>${n.security ? `<h3>Security</h3><p style="margin:0">${esc(n.security)}</p>` : ''}${rel(out, 'Calls and sends')}${rel(inn, 'Called by')}${codeChanges(n)}${n.evidence?.length ? `<h3>In the code</h3>${evidenceHtml(n.evidence)}` : ''}`;
    if (hash) history.replaceState(null, '', `#node=${encodeURIComponent(id)}`);
  };
  const selectEdge = (id, {hash = true} = {}) => {
    const e = edges.get(id);
    if (!e) return;
    if (!current.edges[id]) useView(viewWith([e.from, e.to])?.id, {hash: false});
    if (!presenting()) reveal();
    stopFlow();
    clearMarks();
    svg.classList.add('focus');
    $(`.edge[data-id="${CSS.escape(id)}"]`, svg)?.classList.add('sel', 'near');
    $(`.node[data-id="${CSS.escape(e.from)}"]`, svg)?.classList.add('near');
    $(`.node[data-id="${CSS.escape(e.to)}"]`, svg)?.classList.add('near');
    const inFlows = flows.filter((f) => f.steps.some((s) => s.edge === id));
    inspector.innerHTML = `<span class="label">${esc(e.kind ?? 'sync')} connection${e.protocol ? ` · ${esc(e.protocol)}` : ''}</span><h2>${esc(e.label)}</h2>${changeHtml(e)}<ul class="links"><li><button data-node="${esc(e.from)}">${esc(nodes.get(e.from)?.label)}</button> → <button data-node="${esc(e.to)}">${esc(nodes.get(e.to)?.label)}</button></li></ul>${e.detail ? `<p style="margin:8px 0 0">${esc(e.detail)}</p>` : ''}${inFlows.length ? `<h3>In flows</h3><ul class="links">${inFlows.map((f) => `<li><button data-flow="${esc(f.id)}">${esc(f.title)}</button></li>`).join('')}</ul>` : ''}${codeChanges(e)}${e.evidence?.length ? `<h3>In the code</h3>${evidenceHtml(e.evidence)}` : ''}`;
    if (hash) history.replaceState(null, '', `#edge=${encodeURIComponent(id)}`);
  };
  canvas.addEventListener('click', (ev) => {
    if (drag?.moved || !onDiagram(ev)) return;
    const node = ev.target.closest('.node');
    const edge = ev.target.closest('.edge');
    // A box in the overview opens its area.
    if (node?.dataset.area) return useView(`area-${node.dataset.area}`);
    if (edge && edge.dataset.id.startsWith('ov-')) return selectMerged(edge.dataset.id);
    if (node) selectNode(node.dataset.id);
    else if (edge) selectEdge(edge.dataset.id);
    else { clearMarks(); stopFlow(); history.replaceState(null, '', location.pathname); }
  });
  canvas.addEventListener('keydown', (ev) => {
    const node = ev.target.closest?.('.node');
    if (node && (ev.key === 'Enter' || ev.key === ' ')) { ev.preventDefault(); if (node.dataset.area) useView(`area-${node.dataset.area}`); else selectNode(node.dataset.id); }
  });

  // Views: the overview, the whole system, each area, the feature views. A component or a flow not in the view on
  // screen opens a view that has it.
  function useView(id, {hash = true} = {}) {
    const next = viewList.find((v) => v.id === id);
    if (!next) return;
    if (next !== current) {
      stopFlow();
      clearMarks();
      svg.classList.remove('on');
      current = next;
      svg = $(`#v-${CSS.escape(current.id)}`);
      svg.classList.add('on');
      W = +svg.dataset.w;
      H = +svg.dataset.h;
      layout = current;
      $$('[data-show-view]').forEach((b) => b.setAttribute('aria-selected', String(b.dataset.showView === id)));
      fit();
    }
    if (current.kind === 'area' || current.kind === 'overview' || current.kind === 'feature') {
      inspector.innerHTML = `<span class="label">${esc(current.kind === 'overview' ? 'Overview' : current.kind === 'feature' ? 'Feature view' : 'Area')}</span><h2>${esc(current.title)}</h2>${current.summary ? `<p style="margin:0">${esc(current.summary)}</p>` : ''}${current.flows.length ? `<h3>Flows here</h3><ul class="links">${current.flows.map((f) => `<li><button data-flow="${esc(f)}">${esc(flows.find((x) => x.id === f)?.title)}</button></li>`).join('')}</ul>` : ''}${current.context.length ? '<p class="muted">Faded: what this area talks to.</p>' : ''}`;
    }
    if (hash) history.replaceState(null, '', current.id === data.start ? location.pathname : `#view=${encodeURIComponent(current.id)}`);
  }
  const viewWith = (nodeIds) => (viewList.find((v) => v === current && nodeIds.every((n) => v.nodes[n])) ?? viewList.find((v) => v.kind === 'system' && nodeIds.every((n) => v.nodes[n])) ?? viewList.find((v) => nodeIds.every((n) => v.nodes[n])));
  $$('[data-show-view]').forEach((b) => b.addEventListener('click', () => useView(b.dataset.showView)));
  // An arrow of the overview stands for the connections between two areas.
  function selectMerged(id) {
    const m = current.merged.find((x) => x.id === id);
    if (!m) return;
    reveal();
    clearMarks();
    svg.classList.add('focus');
    $(`.edge[data-id="${CSS.escape(id)}"]`, svg)?.classList.add('sel', 'near');
    for (const n of [m.from, m.to]) $(`.node[data-id="${CSS.escape(n)}"]`, svg)?.classList.add('near');
    const name = (n) => current.areas.find((a) => a.id === n)?.label ?? nodes.get(n)?.label;
    inspector.innerHTML = `<span class="label">${m.members.length} ${m.members.length === 1 ? 'connection' : 'connections'}</span><h2>${esc(name(m.from))} → ${esc(name(m.to))}</h2><ul class="links">${m.members.map((e) => edges.get(e)).map((e) => `<li><button data-edge="${esc(e.id)}">${esc(nodes.get(e.from)?.label)} → ${esc(nodes.get(e.to)?.label)}</button> <span class="muted">${esc(e.label)}</span></li>`).join('')}</ul>`;
  }
  document.addEventListener('click', (ev) => {
    const b = ev.target.closest('[data-node],[data-edge],[data-flow],[data-goto]');
    if (!b || b.closest('svg')) return;
    if (b.dataset.goto) { show('architecture'); nodes.has(b.dataset.goto) ? selectNode(b.dataset.goto) : edges.has(b.dataset.goto) ? selectEdge(b.dataset.goto) : useView(`area-${b.dataset.goto}`); }
    if (b.dataset.node) selectNode(b.dataset.node);
    if (b.dataset.edge) selectEdge(b.dataset.edge);
    if (b.dataset.flow) pickFlow(b.dataset.flow, 0);
    // The list of changes stands above the inspector: a pick from it brings what was picked into sight.
    if (b.closest('#changes-card,#discussion-card')) inspector.scrollIntoView({block: 'start', behavior: 'smooth'});
  });
  // The count of changes in the masthead opens the list of them.
  $('#show-changes')?.addEventListener('click', (ev) => {
    ev.preventDefault();
    show('architecture');
    panel(true);
    $('#changes-card').scrollIntoView({block: 'nearest'});
  });

  // Flows: numbered steps on the diagram, as in a reference architecture, played one at a time.
  const flowList = $('#flows');
  const stepList = $('#steps');
  const player = $('#player');
  let flow = null;
  let step = -1;
  let timer = null;
  flowList.innerHTML = flows.map((f, i) => `<button class="flow-pick" data-pick="${esc(f.id)}" aria-pressed="false"><span class="n">${String(i + 1).padStart(2, '0')}</span><span><b>${esc(f.title)}</b>${f.summary ? `<br><span class="muted">${esc(f.summary)}</span>` : ''}</span></button>`).join('');
  $$('[data-pick]', flowList).forEach((b) => b.addEventListener('click', () => (flow?.id === b.dataset.pick ? stopFlow() : pickFlow(b.dataset.pick, -1))));
  function stopFlow() {
    clearInterval(timer); timer = null;
    caption.hidden = true;
    $('[data-step="play"]').textContent = 'Play';
    if (!flow) return;
    flow = null; step = -1;
    svg.classList.remove('flowing');
    $$('.in,.now', svg).forEach((el) => el.classList.remove('in', 'now'));
    $$('.badges').forEach((b) => { b.innerHTML = ''; });
    stepList.innerHTML = '';
    player.hidden = true;
    $$('[data-pick]').forEach((b) => b.setAttribute('aria-pressed', 'false'));
    if (quick) quick.value = '';
  }
  let camera = false;
  function pickFlow(id, at) {
    const f = flows.find((x) => x.id === id);
    if (!f) return;
    show('architecture');
    if (!current.flows.includes(id)) useView(viewList.find((v) => v.kind === 'system' && v.flows.includes(id))?.id ?? viewList.find((v) => v.flows.includes(id))?.id, {hash: false});
    if (!presenting()) reveal();
    stopFlow();
    clearMarks();
    flow = f;
    fit();
    camera = presenting() || shown() < 0.8;
    svg.classList.add('flowing');
    $$('[data-pick]').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.pick === id)));
    if (quick) quick.value = id;
    const perEdge = new Map();
    f.steps.forEach((s, i) => {
      const e = edges.get(s.edge);
      $(`.edge[data-id="${CSS.escape(s.edge)}"]`, svg)?.classList.add('in');
      $(`.node[data-id="${CSS.escape(e.from)}"]`, svg)?.classList.add('in');
      $(`.node[data-id="${CSS.escape(e.to)}"]`, svg)?.classList.add('in');
      const k = perEdge.get(s.edge) ?? 0;
      perEdge.set(s.edge, k + 1);
      const p = layout.edges[s.edge].badge;
      const ns = 'http://www.w3.org/2000/svg';
      const g = document.createElementNS(ns, 'g');
      g.setAttribute('class', 'badge in');
      g.dataset.step = String(i);
      g.innerHTML = `<circle cx="${p.x - k * 26}" cy="${p.y}" r="11"/><text x="${p.x - k * 26}" y="${p.y + 4}" text-anchor="middle">${i + 1}</text>`;
      $('.badges', svg).appendChild(g);
    });
    stepList.innerHTML = f.steps.map((s, i) => {
      const e = edges.get(s.edge);
      return `<li data-i="${i}"><span class="num">${i + 1}</span><span>${esc(s.text)}<div class="who">${esc(nodes.get(e.from)?.label)} → ${esc(nodes.get(e.to)?.label)}</div>${s.explain ? `<button class="explain-toggle" data-explain="${i}">Explain</button><div class="explain">${esc(s.explain)}</div>` : ''}</span></li>`;
    }).join('');
    $$('li', stepList).forEach((li) => li.addEventListener('click', (ev) => {
      if (ev.target.closest('[data-explain]')) { li.classList.toggle('open'); return; }
      goStep(+li.dataset.i);
    }));
    player.hidden = false;
    inspector.innerHTML = `<span class="label">Flow · ${f.steps.length} steps</span><h2>${esc(f.title)}</h2>${f.summary ? `<p style="margin:0">${esc(f.summary)}</p>` : ''}<p class="muted">Pick a step, or play them in order.</p>`;
    history.replaceState(null, '', `#flow=${encodeURIComponent(id)}`);
    if (at >= 0) goStep(at);
  }
  function goStep(i) {
    if (!flow) return;
    step = Math.max(0, Math.min(i, flow.steps.length - 1));
    const s = flow.steps[step];
    const e = edges.get(s.edge);
    $$('.now', svg).forEach((el) => el.classList.remove('now'));
    $(`.edge[data-id="${CSS.escape(s.edge)}"]`, svg)?.classList.add('now');
    $(`.node[data-id="${CSS.escape(e.to)}"]`, svg)?.classList.add('now');
    $$(`.badge[data-step="${step}"]`, svg).forEach((b) => b.classList.add('now'));
    $$('li', stepList).forEach((li) => li.classList.toggle('now', +li.dataset.i === step));
    caption.hidden = false;
    // In a large diagram the camera follows the step: both ends of the connection, close enough to read.
    const a = layout.nodes[e.from];
    const b = layout.nodes[e.to];
    if (camera && a && b) {
      const x = Math.min(a.x, b.x) - 60;
      const y = Math.min(a.y, b.y) - 60;
      frameBox({x, y, w: Math.max(a.x + a.w, b.x + b.w) + 60 - x, h: Math.max(a.y + a.h, b.y + b.h) + 60 - y});
    }
    $(`li[data-i="${step}"]`, stepList)?.scrollIntoView({block: 'nearest'});
    $$('li', stepList).forEach((li) => li.classList.toggle('open', +li.dataset.i === step));
    inspector.innerHTML = `<span class="label">${esc(flow.title)} · step ${step + 1} of ${flow.steps.length}</span><h2>${esc(nodes.get(e.from)?.label)} → ${esc(nodes.get(e.to)?.label)}</h2><p style="margin:0">${esc(s.text)}</p>${s.explain ? `<h3>Explained</h3><p style="margin:0">${esc(s.explain)}</p>` : ''}<p class="muted" style="margin:8px 0 0">${esc(e.label)}${e.protocol ? ` · ${esc(e.protocol)}` : ''}</p>${evidenceHtml(s.evidence?.length ? s.evidence : e.evidence)}`;
    history.replaceState(null, '', `#flow=${encodeURIComponent(flow.id)}&step=${step + 1}`);
    caption.hidden = false;
    $('#caption-where').textContent = `${flow.title} · ${step + 1} / ${flow.steps.length} · ${nodes.get(e.from)?.label} → ${nodes.get(e.to)?.label}`;
    $('#caption-text').textContent = s.text;
    $('#caption-explain').textContent = s.explain ?? '';
  }
  const play = () => {
    if (timer) { clearInterval(timer); timer = null; $('[data-step="play"]').textContent = 'Play'; return; }
    if (!flow) return;
    if (step >= flow.steps.length - 1) step = -1;
    goStep(step + 1);
    $('[data-step="play"]').textContent = 'Pause';
    timer = setInterval(() => {
      if (step >= flow.steps.length - 1) { clearInterval(timer); timer = null; $('[data-step="play"]').textContent = 'Play'; return; }
      goStep(step + 1);
    }, 2800);
  };
  $$('[data-step]').forEach((b) => b.addEventListener('click', () => {
    const a = b.dataset.step;
    if (a === 'play') play();
    else if (a === 'clear') { stopFlow(); fit(); history.replaceState(null, '', location.pathname); }
    else goStep(step + (a === 'next' ? 1 : -1));
  }));
  document.addEventListener('keydown', (ev) => {
    if (ev.target.closest('input,select,textarea')) return;
    if (ev.key === 'Escape' && presenting()) { if (document.fullscreenElement) document.exitFullscreen(); else leave(); return; }
    if (ev.key === 'Escape' && !presenting()) { stopFlow(); clearMarks(); fit(); }
    if ((ev.key === 'p' || ev.key === 'P') && !ev.metaKey && !ev.ctrlKey) { ev.preventDefault(); present(); return; }
    if ((ev.key === 'e' || ev.key === 'E') && !ev.metaKey && !ev.ctrlKey && flow) { ev.preventDefault(); caption.classList.toggle('explaining'); $$('li', stepList).forEach((li) => li.classList.toggle('open', +li.dataset.i === step && !li.classList.contains('open'))); if (presenting()) goStep(step); return; }
    if (presenting() && ev.key === 'ArrowRight' && flows.length) {
      // On from the last step to the next flow, or into the first one.
      const at = flows.indexOf(flow);
      if (!flow) { ev.preventDefault(); return pickFlow(flows[0].id, 0); }
      if (step >= flow.steps.length - 1 && at < flows.length - 1) { ev.preventDefault(); return pickFlow(flows[at + 1].id, 0); }
    }
    if (!flow) return;
    if (ev.key === 'ArrowRight') { ev.preventDefault(); goStep(step + 1); }
    if (ev.key === 'ArrowLeft') { ev.preventDefault(); goStep(step - 1); }
    if (ev.key === ' ' && !ev.target.closest('button')) { ev.preventDefault(); play(); }
  });

  // Sequence view of a flow: who talks to whom, in order.
  const seqSelect = $('#seq-flow');
  seqSelect.innerHTML = flows.map((f) => `<option value="${esc(f.id)}">${esc(f.title)}</option>`).join('');
  seqSelect.addEventListener('change', () => drawSequence());
  function drawSequence() {
    const host = $('#seq');
    const f = flows.find((x) => x.id === seqSelect.value) ?? flows[0];
    if (!f) { host.innerHTML = '<div class="empty" style="margin:16px">The analysis traced no flows.</div>'; return; }
    // Lifelines in the order they first take part; each step a numbered arrow with the connection's short label,
    // and what happens written out beside the diagram, in a column of its own, as a numbered legend.
    const actors = [];
    for (const st of f.steps) { const e = edges.get(st.edge); for (const id of [e.from, e.to]) if (!actors.includes(id)) actors.push(id); }
    // The lifelines share the width with the notes; past what fits, the view scrolls sideways.
    const avail = (host.clientWidth || 1400) - 72;
    const colW = Math.min(220, Math.max(100, (avail - 360) / actors.length));
    const notesW = Math.min(640, Math.max(320, avail - actors.length * colW));
    const top = 76;
    const x = (id) => 24 + actors.indexOf(id) * colW + colW / 2;
    const notesX = 24 + actors.length * colW + 24;
    const wrapText = (t, n) => { const out = ['']; for (const word of t.split(' ')) { if ((out[out.length - 1] + ' ' + word).trim().length > n) out.push(word); else out[out.length - 1] = (out[out.length - 1] + ' ' + word).trim(); } return out; };
    const rows = f.steps.map((st) => wrapText(st.text, Math.floor((notesW - 34) / 7.2)));
    const rowH = rows.map((l) => Math.max(56, l.length * 18 + 22));
    const ys = [];
    let at = top;
    for (const h of rowH) { ys.push(at); at += h; }
    const height = top + rowH.reduce((a, b) => a + b, 0) + 24;
    const width = notesX + notesW + 24;
    // Wider screens draw it larger, up to a third larger than designed; narrow ones scroll.
    let out = `<svg style="width:max(${width}px, min(100%, ${Math.round(width * 1.35)}px));height:auto" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" xmlns="http://www.w3.org/2000/svg"><defs><marker id="seq-a" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse"><path d="M0 1L9 5L0 9z" style="fill:var(--ink-muted)"/></marker></defs>`;
    out += `<text class="seq-sub" x="${notesX}" y="40">WHAT HAPPENS</text>`;
    for (const id of actors) {
      const n = nodes.get(id);
      const room = Math.floor((colW - 24) / 7.4);
      const label = n.label.length > room ? n.label.slice(0, room - 1) + '…' : n.label;
      out += `<g class="seq-actor"><rect x="${x(id) - (colW - 16) / 2}" y="20" width="${colW - 16}" height="36" rx="8"/><text x="${x(id)}" y="43" text-anchor="middle">${esc(label)}</text></g><line class="seq-life" x1="${x(id)}" y1="56" x2="${x(id)}" y2="${height - 12}"/>`;
    }
    f.steps.forEach((st, i) => {
      const e = edges.get(st.edge);
      const y = ys[i] + 30;
      const x1 = x(e.from);
      const x2 = x(e.to);
      const left = Math.min(x1, x2);
      const span = Math.abs(x2 - x1);
      const label = `${e.label}${e.protocol ? ` · ${e.protocol}` : ''}`;
      const fitted = label.length * 6.6 > span - 36 ? label.slice(0, Math.max(4, Math.floor((span - 36) / 6.6) - 1)) + '…' : label;
      out += `<g class="seq-step" data-i="${i}"><path class="seq-msg k-${esc(e.kind ?? 'sync')}" d="M${x1} ${y}H${x2 + (x2 > x1 ? -2 : 2)}" marker-end="url(#seq-a)"/>`;
      out += `<circle cx="${left + 16}" cy="${y - 13}" r="10" style="fill:var(--ink)"/><text x="${left + 16}" y="${y - 9}" text-anchor="middle" style="font:500 11px var(--font-mono);fill:var(--surface)">${i + 1}</text>`;
      out += `<text class="seq-sub" x="${left + 32}" y="${y - 9}"><title>${esc(label)}</title>${esc(fitted)}</text>`;
      out += `<line x1="${Math.max(x1, x2) + 8}" y1="${y}" x2="${notesX - 8}" y2="${y}" style="stroke:var(--line);stroke-dasharray:2 4"/>`;
      out += `<circle cx="${notesX + 10}" cy="${y - 4}" r="10" style="fill:var(--ink)"/><text x="${notesX + 10}" y="${y}" text-anchor="middle" style="font:500 11px var(--font-mono);fill:var(--surface)">${i + 1}</text>`;
      out += rows[i].map((l, j) => `<text class="seq-text" x="${notesX + 30}" y="${y + j * 18}">${esc(l)}</text>`).join('');
      out += '</g>';
    });
    host.innerHTML = out + '</svg>';
  }

  // Evidence, by file.
  const cites = [];
  model.nodes.forEach((n) => (n.evidence ?? []).forEach((ev) => cites.push({ev, by: `Component: ${n.label}`, go: `data-node="${esc(n.id)}"`})));
  model.edges.forEach((e) => (e.evidence ?? []).forEach((ev) => cites.push({ev, by: `Connection: ${nodes.get(e.from)?.label} → ${nodes.get(e.to)?.label}`, go: `data-edge="${esc(e.id)}"`})));
  flows.forEach((f) => f.steps.forEach((st, i) => (st.evidence ?? []).forEach((ev) => cites.push({ev, by: `${f.title}, step ${i + 1}`, go: `data-flow="${esc(f.id)}"`}))));
  const byFile = new Map();
  for (const c of cites) { const l = byFile.get(c.ev.path) ?? []; l.push(c); byFile.set(c.ev.path, l); }
  $('#evidence-list').innerHTML = [...byFile.entries()].sort((a, b) => a[0].localeCompare(b[0])).map(([file, list]) => `<div class="card" style="margin-bottom:16px"><span class="label">${list.length} ${list.length === 1 ? 'citation' : 'citations'}</span><h2 class="mono" style="font-size:15px">${esc(file)}</h2>${list.sort((a, b) => (a.ev.lines?.[0] ?? 0) - (b.ev.lines?.[0] ?? 0)).map((c) => `<div style="margin-top:14px"><ul class="links"><li>${c.go ? `<button ${c.go}>${esc(c.by)}</button>` : esc(c.by)}</li></ul>${evidenceHtml([c.ev])}</div>`).join('')}</div>`).join('') || '<div class="empty">No citations.</div>';
  if (diff?.files.length) {
    const owned = diff.files.filter((f) => f.owners?.length);
    const loose = diff.files.filter((f) => !f.owners?.length);
    $('#changes-list').innerHTML = `${owned.length ? `<h3>In the architecture</h3>${owned.map(patchHtml).join('')}` : ''}${loose.length ? `<h3 style="margin-top:32px">Not in the architecture</h3><p class="muted">No component or connection cites these files. A large change here is a part the diagram may miss.</p>${loose.map(patchHtml).join('')}` : ''}`;
  }

  // What was said over the page and what was read for it. blueprint note writes both into the page's data, so the
  // card is drawn here, from the data, and not when the page is made.
  const talk = model.discussion ?? [];
  const sources = (model.sources ?? []).filter((x) => /^https?:\/\//.test(x.url));
  if (talk.length || sources.length) {
    const ref = (id) => {
      const f = flows.find((x) => x.id === id);
      const e = edges.get(id);
      const zone = (model.zones ?? []).find((z) => z.id === id);
      if (f) return `<button data-flow="${esc(id)}">${esc(f.title)}</button>`;
      if (nodes.has(id) || e || zone) return `<button data-goto="${esc(id)}">${esc(nodes.get(id)?.label ?? zone?.label ?? `${nodes.get(e.from)?.label} → ${nodes.get(e.to)?.label}`)}</button>`;
      return `<span>${esc(id)}</span>`;
    };
    const order = ['open', 'decided', 'dropped'];
    const count = (st) => talk.filter((d) => d.status === st).length;
    const line = (d) => `<li class="talk-${esc(d.status)}"><span class="tag ${d.status === 'decided' ? 'olive' : d.status === 'open' ? 'sea' : ''}">${esc(d.status)}</span> <b>${esc(d.title)}</b>${d.detail ? `<p>${esc(d.detail)}</p>` : ''}${d.refs?.length ? `<p class="refs">${d.refs.map(ref).join('')}</p>` : ''}</li>`;
    const card = $('#discussion-card');
    card.innerHTML = `<span class="label">Discussion</span><h2>${talk.length ? `${count('open')} open · ${count('decided')} decided` : 'Read for it'}</h2>${talk.length ? `<ul class="talk">${[...talk].sort((a, b) => order.indexOf(a.status) - order.indexOf(b.status)).map(line).join('')}</ul>` : ''}${sources.length ? `${talk.length ? '<h3>Read for it</h3>' : ''}<ul class="talk">${sources.map((x) => `<li>${/^https?:\/\//.test(x.url) ? `<a href="${esc(x.url)}" target="_blank" rel="noopener">${esc(x.title)}</a>` : esc(x.title)}${x.note ? `<p>${esc(x.note)}</p>` : ''}</li>`).join('')}</ul>` : ''}`;
    card.hidden = false;
  }

  // Pointing. The reader picks a part and gives their assistant a reference to it, so that "this one" means one
  // thing to both. The reference names the page, the part, and the command that reads the part with its code.
  const askButton = $('#ask');
  const pointed = () => {
    const file = location.protocol === 'file:' ? decodeURIComponent(location.pathname) : location.href.split('#')[0];
    const id = $('.sel', svg)?.dataset.id;
    const e = edges.get(id);
    const at = flow
      ? [`the flow "${flow.title}"${step >= 0 ? `, step ${step + 1} ("${flow.steps[step].text}")` : ''}`, `${flow.id}${step >= 0 ? ` ${flow.steps[step].edge}` : ''}`]
      : nodes.has(id) ? [`the component "${nodes.get(id).label}"`, id]
      : e ? [`the connection "${nodes.get(e.from)?.label} → ${nodes.get(e.to)?.label}: ${e.label}"`, id] : null;
    return `${at ? `In the Blueprint page ${file}, look at ${at[0]}.` : `Look at the Blueprint page ${file}.`} Read it first: blueprint show "${file}"${at ? ` ${at[1]}` : ''}\n\nMy question: `;
  };
  askButton?.addEventListener('click', async () => {
    const text = pointed();
    try { await navigator.clipboard.writeText(text); } catch {
      // A page opened from a file may have no clipboard API: the old way still copies.
      const t = document.createElement('textarea');
      t.value = text;
      document.body.append(t);
      t.select();
      document.execCommand('copy');
      t.remove();
    }
    askButton.dataset.copied = text;
    askButton.textContent = 'Copied. Paste it to your assistant';
    setTimeout(() => { askButton.textContent = 'Ask about this'; }, 2200);
  });
  document.addEventListener('keydown', (ev) => {
    if ((ev.key === 'a' || ev.key === 'A') && !ev.metaKey && !ev.ctrlKey && !ev.altKey && !ev.target.closest('input,select,textarea')) { ev.preventDefault(); askButton?.click(); }
  });

  // Links straight to a component, a connection or a step.
  requestAnimationFrame(() => {
    fit();
    const h = new URLSearchParams(location.hash.slice(1));
    if (h.get('view')) useView(h.get('view'), {hash: false});
    if (h.get('node')) selectNode(h.get('node'), {hash: false});
    else if (h.get('edge')) selectEdge(h.get('edge'), {hash: false});
    else if (h.get('flow')) pickFlow(h.get('flow'), h.get('step') ? +h.get('step') - 1 : -1);
  });
})();
