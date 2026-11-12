// Rasmus Hilmersson's design system, as Blueprint pages use it. tokens.json is a copy of
// ~/youtube/rasmushilmersson/design-system/tokens.json; `node rh.mjs --sync` copies it again. Dark is the primary theme.
import {readFileSync, copyFileSync, existsSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
export const tokens = JSON.parse(readFileSync(path.join(here, 'tokens.json'), 'utf8'));

/** A colour token's value in a theme ("dark" or "light"); aliases such as `link` resolve. */
export function color(name, theme = 'dark') {
  const token = tokens.color.tokens.find((t) => t.name === name);
  if (!token) throw new Error(`rh: no colour token "${name}"`);
  const value = typeof token.value === 'string' ? token.value : token.value[theme];
  const alias = /^\{(.+)\}$/.exec(value);
  return alias ? color(alias[1], theme) : value;
}

/** Every colour of a theme, by token name. */
export function palette(theme = 'dark') {
  return Object.fromEntries(tokens.color.tokens.map((t) => [t.name, color(t.name, theme)]));
}

const focus = (theme) => tokens.shadow.tokens.find((t) => t.name === 'focus-ring').value[theme];

function block(theme) {
  const colors = Object.entries(palette(theme)).map(([k, v]) => `--${k}:${v};`).join('');
  return `${colors}--focus-ring:${focus(theme)};color-scheme:${theme};`;
}

/** CSS custom properties for both themes, as the design system's styles.css sets them: dark unless the visitor
 * prefers light, and `data-theme` on the root forces either. */
export function cssVariables() {
  const families = Object.entries(tokens.type.families).map(([k, v]) => `--font-${k}:${v};`).join('');
  const space = tokens.spacing.tokens.map((t) => `--${t.name}:${t.value};`).join('');
  const radius = tokens.radius.tokens.map((t) => `--${t.name}:${t.value};`).join('');
  return `:root,[data-theme="dark"]{${block('dark')}${families}${space}${radius}}` +
    `@media (prefers-color-scheme: light){:root:not([data-theme="dark"]){${block('light')}}}` +
    `[data-theme="light"]{${block('light')}}`;
}

/** The type scale's named styles (display, heading, title, body, small, label, code) as CSS classes `.t-<name>`. */
export function typeClasses() {
  return tokens.type.groups.flatMap((g) => g.styles.map((s) => {
    const family = g.family ?? (s.name === 'label' || s.name === 'code' ? 'mono' : 'sans');
    const upper = s.name === 'label' ? 'text-transform:uppercase;' : '';
    return `.t-${s.name}{font-family:var(--font-${family});font-size:${s.fontSize};line-height:${s.lineHeight};font-weight:${s.fontWeight};${s.letterSpacing ? `letter-spacing:${s.letterSpacing};` : ''}${upper}}`;
  })).join('');
}

/** The font files the system uses, from the @fontsource packages: Newsreader 500, Hanken Grotesk 400/600/800,
 * JetBrains Mono 400/500, Latin subset. All are under the SIL Open Font License. */
export const fontFiles = [
  {family: 'Newsreader', weight: 500, file: '@fontsource/newsreader/files/newsreader-latin-500-normal.woff2'},
  {family: 'Hanken Grotesk', weight: 400, file: '@fontsource/hanken-grotesk/files/hanken-grotesk-latin-400-normal.woff2'},
  {family: 'Hanken Grotesk', weight: 600, file: '@fontsource/hanken-grotesk/files/hanken-grotesk-latin-600-normal.woff2'},
  {family: 'Hanken Grotesk', weight: 800, file: '@fontsource/hanken-grotesk/files/hanken-grotesk-latin-800-normal.woff2'},
  {family: 'JetBrains Mono', weight: 400, file: '@fontsource/jetbrains-mono/files/jetbrains-mono-latin-400-normal.woff2'},
  {family: 'JetBrains Mono', weight: 500, file: '@fontsource/jetbrains-mono/files/jetbrains-mono-latin-500-normal.woff2'},
];

/** @font-face rules. `src(font)` returns the URL for a font: a data: URL to embed it, or a relative path. */
export function fontFaces(src) {
  return fontFiles.map((f) => `@font-face{font-family:"${f.family}";src:url(${src(f)}) format("woff2");font-weight:${f.weight};font-style:normal;font-display:block}`).join('');
}

/** @font-face rules with the fonts embedded, read from `nodeModules`. */
export function embeddedFontFaces(nodeModules) {
  return fontFaces((f) => `data:font/woff2;base64,${readFileSync(path.join(nodeModules, f.file)).toString('base64')}`);
}

if (process.argv[1] === fileURLToPath(import.meta.url) && process.argv.includes('--sync')) {
  const source = path.join(process.env.HOME ?? '', 'youtube/rasmushilmersson/design-system/tokens.json');
  if (!existsSync(source)) throw new Error(`no design system at ${source}`);
  copyFileSync(source, path.join(here, 'tokens.json'));
  console.log(`copied ${source}`);
}
