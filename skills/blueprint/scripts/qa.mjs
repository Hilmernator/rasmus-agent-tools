// Opens a Blueprint page in headless Chrome the way a reader would and fails on what a reader would notice: script
// errors, an empty diagram, text that overflows its component, a flow that does not step, a broken theme or phone
// layout. Writes screenshots beside the page for looking at.
//   node qa.mjs PAGE.html [--shots DIR]
import {existsSync, readdirSync, mkdirSync} from 'node:fs';
import {homedir} from 'node:os';
import path from 'node:path';
import puppeteer from 'puppeteer-core';

export function chrome() {
  if (process.env.BLUEPRINT_CHROME) return process.env.BLUEPRINT_CHROME;
  const mac = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
  if (existsSync(mac)) return mac;
  const cache = path.join(homedir(), '.cache/hyperframes/chrome/chrome-headless-shell');
  if (existsSync(cache)) {
    for (const v of readdirSync(cache).sort().reverse()) {
      const bin = path.join(cache, v, 'chrome-headless-shell-mac-arm64/chrome-headless-shell');
      if (existsSync(bin)) return bin;
    }
  }
  throw new Error('no Chrome found: set BLUEPRINT_CHROME to a Chrome or chrome-headless-shell executable');
}

export async function qa(page, {shots = null} = {}) {
  const problems = [];
  const file = path.resolve(page);
  const dir = shots ?? file.replace(/\.html$/, '.qa');
  mkdirSync(dir, {recursive: true});
  const browser = await puppeteer.launch({executablePath: chrome(), headless: true, args: ['--no-sandbox', '--force-color-profile=srgb']});
  try {
    const tab = await browser.newPage();
    tab.on('pageerror', (e) => problems.push(`script error: ${e.message}`));
    tab.on('console', (m) => { if (m.type() === 'error') problems.push(`console error: ${m.text()}`); });
    await tab.setViewport({width: 1600, height: 1000, deviceScaleFactor: 2});
    await tab.emulateMediaFeatures([{name: 'prefers-color-scheme', value: 'dark'}]);
    await tab.goto(`file://${file}`, {waitUntil: 'load'});
    await tab.evaluate(() => document.fonts.ready);
    await new Promise((r) => setTimeout(r, 300));
    const facts = await tab.evaluate(() => {
      const svg = document.querySelector('svg.diagram.on');
      const nodes = [...svg.querySelectorAll('.node')];
      // A title wider than its component's box spills onto its neighbours.
      const spill = nodes.flatMap((n) => {
        const box = n.querySelector('.n-hit').getBBox();
        return [...n.querySelectorAll('text')].filter((t) => { const b = t.getBBox(); return b.x < box.x - 1 || b.x + b.width > box.x + box.width + 1; }).map((t) => `${n.dataset.id}: "${t.textContent}" is ${Math.round(t.getBBox().width)} wide in ${Math.round(box.width)}`);
      });
      const labels = [...svg.querySelectorAll('.e-label')].flatMap((g) => { const r = g.querySelector('rect').getBBox(); const t = g.querySelector('text').getBBox(); return t.width > r.width + 2 ? [`edge label "${g.textContent}" is ${Math.round(t.width)} wide in ${Math.round(r.width)}`] : []; });
      const fonts = ['Hanken Grotesk', 'JetBrains Mono', 'Newsreader'].filter((f) => !document.fonts.check(`16px "${f}"`));
      const missing = [...svg.querySelectorAll('use')].map((u) => u.getAttribute('href')).filter((h) => !document.querySelector(h));
      return {nodes: nodes.length, edges: svg.querySelectorAll('.edge').length, spill, labels, fonts, missing, flows: document.querySelectorAll('[data-pick]').length, bodyWidth: document.body.scrollWidth};
    });
    if (facts.nodes === 0) problems.push('the diagram has no components');
    problems.push(...facts.spill.map((s) => `text overflows: ${s}`), ...facts.labels, ...facts.missing.map((m) => `icon ${m} is not defined`), ...facts.fonts.map((f) => `font ${f} did not load`));
    await tab.screenshot({path: path.join(dir, 'architecture-dark.png')});
    if (facts.flows) {
      await tab.select('#flow-quick', await tab.$eval('#flow-quick option:nth-child(2)', (o) => o.value));
      await tab.click('[data-step="next"]');
      // The camera glides to the step in about half a second.
      await new Promise((r) => setTimeout(r, 700));
      const stepped = await tab.evaluate(() => ({now: document.querySelectorAll('svg.diagram.on .edge.now').length, badges: document.querySelectorAll('svg.diagram.on .badge').length, hash: location.hash}));
      if (stepped.now !== 1 || stepped.badges === 0 || !stepped.hash.includes('step=2')) problems.push(`stepping a flow did not mark step 2: ${JSON.stringify(stepped)}`);
      await tab.screenshot({path: path.join(dir, 'flow-step-2.png')});
      await tab.keyboard.press('Escape');
    }
    // Views: the overview's boxes open their areas; a step's explanation opens with the step.
    if (await tab.$('[data-show-view="overview"]')) {
      await tab.click('[data-show-view="overview"]');
      await new Promise((r) => setTimeout(r, 200));
      await tab.screenshot({path: path.join(dir, 'overview.png')});
      const box = await tab.$('svg.diagram.on .area-box');
      if (!box) problems.push('the overview has no area boxes');
      else {
        await box.click();
        await new Promise((r) => setTimeout(r, 200));
        const opened = await tab.evaluate(() => document.querySelector('svg.diagram.on').id);
        if (!opened.startsWith('v-area-')) problems.push(`clicking an area box opened ${opened}, not the area`);
        await tab.screenshot({path: path.join(dir, 'area.png')});
      }
      await tab.click('[data-show-view="system"]');
      await new Promise((r) => setTimeout(r, 200));
    }
    if (facts.flows) {
      await tab.select('#flow-quick', await tab.$eval('#flow-quick option:nth-child(2)', (o) => o.value));
      const explained = await tab.evaluate(() => { const li = document.querySelector('#steps li.now'); return li ? {explain: !!li.querySelector('.explain'), open: li.classList.contains('open')} : null; });
      if (explained?.explain && !explained.open) problems.push('the current step does not show its explanation');
      await tab.screenshot({path: path.join(dir, 'explain.png')});
      await tab.keyboard.press('Escape');
    }
    // Presenting: P fills the screen, → starts the first flow with the step written large, Escape leaves.
    if (facts.flows) {
      await tab.keyboard.press('p');
      await new Promise((r) => setTimeout(r, 300));
      await tab.keyboard.press('ArrowRight');
      await tab.keyboard.press('ArrowRight');
      await new Promise((r) => setTimeout(r, 700));
      const shown = await tab.evaluate(() => ({on: document.querySelector('#canvas').classList.contains('presenting'), caption: !document.querySelector('#caption').hidden && document.querySelector('#caption-text').textContent, height: document.querySelector('#canvas').clientHeight}));
      if (!shown.on || !shown.caption || shown.height < 990) problems.push(`presenting did not fill the screen with the step written out: ${JSON.stringify(shown)}`);
      await tab.screenshot({path: path.join(dir, 'present.png')});
      await tab.keyboard.press('Escape');
      await new Promise((r) => setTimeout(r, 200));
      if (await tab.evaluate(() => document.querySelector('#canvas').classList.contains('presenting'))) problems.push('Escape did not leave presenting');
      await tab.keyboard.press('Escape');
    }
    const first = await tab.$('svg.diagram.on .node');
    await first.click();
    const inspected = await tab.evaluate(() => document.querySelector('#inspector h2').textContent);
    if (/Click a component/.test(inspected)) problems.push('clicking a component did not open it in the inspector');
    await tab.screenshot({path: path.join(dir, 'inspector.png')});
    // Pointing: with a component picked, "Ask about this" copies a reference that names it and the command that reads it.
    const asked = await tab.evaluate(async () => {
      const b = document.querySelector('#ask');
      if (!b) return null;
      b.click();
      await new Promise((r) => setTimeout(r, 100));
      return {copied: b.dataset.copied ?? '', id: document.querySelector('svg.diagram.on .sel')?.dataset.id};
    });
    if (!asked) problems.push('the page has no "Ask about this" button: it was drawn by an older Blueprint, render it again');
    else if (!asked.id || !asked.copied.includes('blueprint show "') || !asked.copied.trimEnd().endsWith('My question:') || !asked.copied.includes(`" ${asked.id}\n`)) problems.push(`"Ask about this" did not copy a reference to the picked component: ${JSON.stringify(asked)}`);
    // The discussion over the page stands beside the diagram, every line of it.
    const talk = await tab.evaluate(() => {
      const m = JSON.parse(document.querySelector('#data').textContent).model;
      const card = document.querySelector('#discussion-card');
      return {want: (m.discussion?.length ?? 0) + (m.sources?.length ?? 0), shown: card && !card.hidden ? card.querySelectorAll('li').length : 0};
    });
    if (talk.want !== talk.shown) problems.push(`the page holds ${talk.want} lines of discussion and sources and shows ${talk.shown}`);
    else if (talk.want) await (await tab.$('#discussion-card')).screenshot({path: path.join(dir, 'discussion.png')});
    // A page of changes or of a plan: the count in the header opens the list, a pick from the list shows that part's
    // change in sight, and the diagram can show the changes alone.
    if (await tab.$('#changes-card [data-goto]')) {
      await tab.keyboard.press('Escape');
      await tab.click('#only-changes');
      await new Promise((r) => setTimeout(r, 300));
      const faded = await tab.evaluate(() => ({on: document.querySelector('#canvas').classList.contains('only-changes'), dim: getComputedStyle(document.querySelector('svg.diagram.on .node:not([class*="chg-"]):not([class*="st-"])') ?? document.body).opacity}));
      if (!faded.on || faded.dim === '1') problems.push(`"Only changes" did not fade what is unchanged: ${JSON.stringify(faded)}`);
      await tab.screenshot({path: path.join(dir, 'only-changes.png')});
      await tab.click('#only-changes');
      const picked = await tab.evaluate(async () => {
        document.querySelector('#show-changes')?.click();
        document.querySelector('#changes-card [data-goto]').click();
        await new Promise((r) => setTimeout(r, 800));
        const box = document.querySelector('#inspector').getBoundingClientRect(), side = document.querySelector('.side').getBoundingClientRect();
        return {inSight: box.top >= side.top - 1 && box.top < Math.min(side.bottom, innerHeight), says: !!document.querySelector('#inspector .tag'), top: Math.round(box.top), panel: [Math.round(side.top), Math.round(side.bottom)]};
      });
      if (!picked.inSight || !picked.says) problems.push(`a pick from the list of changes did not show its change in the inspector: ${JSON.stringify(picked)}`);
      await tab.screenshot({path: path.join(dir, 'change.png')});
    }
    for (const view of ['sequence', 'inventory', 'evidence']) {
      await tab.click(`[data-view="${view}"]`);
      await new Promise((r) => setTimeout(r, 150));
      await tab.screenshot({path: path.join(dir, `${view}.png`), fullPage: view !== 'evidence'});
    }
    await tab.click('[data-view="architecture"]');
    await tab.click('[data-theme-set="light"]');
    await new Promise((r) => setTimeout(r, 200));
    await tab.screenshot({path: path.join(dir, 'architecture-light.png')});
    await tab.click('[data-icons="quiet"]');
    await tab.screenshot({path: path.join(dir, 'architecture-light-quiet.png')});
    await tab.click('[data-icons="aws"]');
    await tab.click('[data-theme-set="auto"]');
    // An ultrawide screen at work: the page and the diagram use the width.
    await tab.setViewport({width: 3440, height: 1440, deviceScaleFactor: 1});
    await new Promise((r) => setTimeout(r, 400));
    const wide = await tab.evaluate(() => ({canvas: document.querySelector('#canvas').clientWidth, page: document.documentElement.scrollWidth}));
    if (wide.page > 3440) problems.push(`on an ultrawide screen the page is ${wide.page}px wide and scrolls sideways`);
    if (wide.canvas < 2600) problems.push(`on an ultrawide screen the diagram gets only ${wide.canvas}px of 3440`);
    await tab.screenshot({path: path.join(dir, 'ultrawide.png')});
    for (const view of ['sequence', 'evidence']) {
      await tab.click(`[data-view="${view}"]`);
      await new Promise((r) => setTimeout(r, 150));
      await tab.screenshot({path: path.join(dir, `ultrawide-${view}.png`)});
    }
    await tab.click('[data-view="architecture"]');
    await tab.setViewport({width: 390, height: 844, deviceScaleFactor: 2, isMobile: true, hasTouch: true});
    await new Promise((r) => setTimeout(r, 300));
    const phone = await tab.evaluate(() => document.documentElement.scrollWidth);
    if (phone > 392) problems.push(`on a phone the page is ${phone}px wide and scrolls sideways`);
    await tab.screenshot({path: path.join(dir, 'phone.png'), fullPage: true});
  } finally {
    await browser.close();
  }
  return {problems, shots: dir};
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [page] = process.argv.slice(2);
  if (!page) { console.error('usage: node qa.mjs PAGE.html [--shots DIR]'); process.exit(2); }
  const i = process.argv.indexOf('--shots');
  qa(page, {shots: i > 0 ? process.argv[i + 1] : null}).then(({problems, shots}) => {
    console.log(problems.length ? problems.join('\n') : 'no problems found');
    console.log(`screenshots in ${shots}`);
    process.exit(problems.length ? 1 : 0);
  }, (e) => { console.error(e.message); process.exit(1); });
}
