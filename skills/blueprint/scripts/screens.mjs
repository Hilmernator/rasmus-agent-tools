// Opens a page at the screen sizes people use and reports, for each, how much room the diagram gets, how large it
// is drawn, whether the page scrolls sideways and whether the whole diagram is on screen; with a screenshot each.
//   node screens.mjs PAGE.html
import {mkdirSync} from 'node:fs';
import path from 'node:path';
import puppeteer from 'puppeteer-core';
import {chrome} from './qa.mjs';

export const SCREENS = [
  ['phone', 390, 844, 3, true],
  ['phone-landscape', 844, 390, 3, true],
  ['tablet', 820, 1180, 2, true],
  ['tablet-landscape', 1180, 820, 2, true],
  ['laptop-13', 1280, 800, 2, false],
  ['laptop-16', 1728, 1117, 2, false],
  ['monitor-1080p', 1920, 1080, 1, false],
  ['monitor-1440p', 2560, 1440, 1, false],
  ['ultrawide', 3440, 1440, 1, false],
  ['super-ultrawide', 5120, 1440, 1, false],
  ['4k', 3840, 2160, 2, false],
];

export async function screens(page) {
  const file = path.resolve(page);
  const dir = file.replace(/\.html$/, '.screens');
  mkdirSync(dir, {recursive: true});
  const browser = await puppeteer.launch({executablePath: chrome(), headless: true, args: ['--no-sandbox']});
  const rows = [];
  const problems = [];
  try {
    for (const [name, width, height, scale, touch] of SCREENS) {
      const tab = await browser.newPage();
      await tab.setViewport({width, height, deviceScaleFactor: scale, isMobile: touch, hasTouch: touch});
      await tab.goto(`file://${file}`, {waitUntil: 'load'});
      await tab.evaluate(() => document.fonts.ready);
      await new Promise((r) => setTimeout(r, 400));
      const m = await tab.evaluate(() => {
        const canvas = document.querySelector('#canvas');
        const svg = document.querySelector('svg.diagram.on');
        const vb = svg.viewBox.baseVal;
        const r = canvas.getBoundingClientRect();
        // The drawn size of the diagram's own content, from its first and last components.
        const nodes = [...svg.querySelectorAll('.node .n-hit')].map((n) => n.getBoundingClientRect());
        const box = nodes.reduce((b, n) => ({l: Math.min(b.l, n.left), t: Math.min(b.t, n.top), r: Math.max(b.r, n.right), b: Math.max(b.b, n.bottom)}), {l: Infinity, t: Infinity, r: -Infinity, b: -Infinity});
        return {
          canvas: [Math.round(r.width), Math.round(r.height)],
          scale: r.width / vb.width,
          sideways: document.documentElement.scrollWidth > innerWidth + 1,
          inCanvas: box.l >= r.left - 1 && box.r <= r.right + 1 && box.t >= r.top - 1 && box.b <= r.bottom + 1,
          onScreen: box.b <= innerHeight + 1 && box.t >= 0,
          title: Math.round(parseFloat(getComputedStyle(svg.querySelector('.n-title')).fontSize) * r.width / vb.width),
        };
      });
      rows.push({name, size: `${width}x${height}`, ...m});
      if (m.sideways) problems.push(`${name}: the page scrolls sideways`);
      if (!m.inCanvas) problems.push(`${name}: the diagram does not fit its canvas`);
      if (!touch && !m.onScreen) problems.push(`${name}: the diagram is not all on screen when the page opens`);
      await tab.screenshot({path: path.join(dir, `${name}.png`)});
      await tab.close();
    }
  } finally {
    await browser.close();
  }
  return {rows, problems, dir};
}

if (import.meta.url === `file://${process.argv[1]}`) {
  screens(process.argv[2]).then(({rows, problems, dir}) => {
    for (const r of rows) console.log(`${r.name.padEnd(17)} ${r.size.padEnd(10)} canvas ${r.canvas.join('x').padEnd(10)} drawn at ${(r.scale * 100).toFixed(0).padStart(3)}%, titles ${r.title}px${r.onScreen ? '' : ', below the fold'}`);
    console.log(problems.length ? problems.join('\n') : 'no problems found');
    console.log(`screenshots in ${dir}`);
    process.exit(problems.length ? 1 : 0);
  }, (e) => { console.error(e.message); process.exit(1); });
}
