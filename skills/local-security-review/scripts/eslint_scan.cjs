// Load only the pinned toolchain, never the scanned repository's JS config.
const fs = require('node:fs');
const path = require('node:path');
const { createRequire } = require('node:module');

async function main() {
  const [toolchain, target, inventory, output] = process.argv.slice(2);
  const load = createRequire(path.join(toolchain, 'package.json'));
  const { ESLint } = load('eslint');
  const security = load('eslint-plugin-security');
  const parser = load('@typescript-eslint/parser');
  const eslint = new ESLint({
    cwd: target, overrideConfigFile: true, allowInlineConfig: false,
    ignore: false, fix: false,
    overrideConfig: [{
      files: ['**/*.{js,jsx,mjs,cjs,ts,tsx,mts,cts}'],
      languageOptions: { parser, ecmaVersion: 'latest', sourceType: 'module',
        parserOptions: { project: false, projectService: false, ecmaFeatures: { jsx: true } } },
      plugins: { security },
      rules: Object.fromEntries(Object.keys(security.rules).map(name => [`security/${name}`, 'warn'])),
    }, {
      files: ['**/*.{cjs,cts}'], languageOptions: { sourceType: 'commonjs' },
    }],
  });
  const files = JSON.parse(fs.readFileSync(inventory, 'utf8'));
  const results = await eslint.lintFiles(files.map(name => path.join(target, name)));
  fs.writeFileSync(output, JSON.stringify(results), { mode: 0o600 });
}

main().catch(() => { process.exitCode = 2; });
