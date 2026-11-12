import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, mkdirSync, writeFileSync, readFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {scan, trace, signalsOf} from '../scan.mjs';
import {check, excerpts, coverageProblems, stamp, readPage, citers, pageWith, showText, noted} from '../model.mjs';
import {diffModels, gitChanges, owners} from '../diff.mjs';
import {layout, placeLabels} from '../layout.mjs';
import {render, comparePage, wrap, sourceUrl} from '../render.mjs';
import {awsServiceIcon} from '../icons.mjs';
import {parseAnswer, chooseFiles, traceText, sketch, options, update, cover, unread} from '../analyze.mjs';
import {lint, texts} from '../style.mjs';
import {views} from '../views.mjs';

// A small serverless repository: an API route, a Lambda that writes to DynamoDB, a CloudFormation template.
function repo() {
  const root = mkdtempSync(path.join(tmpdir(), 'blueprint-'));
  const put = (rel, text) => { mkdirSync(path.dirname(path.join(root, rel)), {recursive: true}); writeFileSync(path.join(root, rel), text); };
  put('package.json', JSON.stringify({name: 'orders', dependencies: {'@aws-sdk/client-dynamodb': '3.0.0', express: '4.0.0'}}));
  put('src/api/server.js', "import express from 'express';\nimport {save} from '../store/orders.js';\nconst app = express();\napp.post('/orders', async (req, res) => res.json(await save(req.body)));\n");
  put('src/store/orders.js', "import {DynamoDBClient, PutItemCommand} from '@aws-sdk/client-dynamodb';\nconst db = new DynamoDBClient({});\nexport async function save(order) {\n  return db.send(new PutItemCommand({TableName: process.env.ORDERS_TABLE, Item: order}));\n}\n");
  put('template.yaml', 'Resources:\n  OrdersTable:\n    Type: AWS::DynamoDB::Table\n  Api:\n    Type: AWS::Serverless::Function\n');
  return root;
}

function model() {
  return {
    title: 'Orders', summary: 'Customers post orders over HTTP. The API stores them in DynamoDB.', scope: {kind: 'system'},
    zones: [{id: 'aws', label: 'AWS Cloud', kind: 'aws-cloud'}],
    nodes: [
      {id: 'user', label: 'Customer', kind: 'user', responsibility: 'Places orders.'},
      {id: 'api', label: 'Orders API', kind: 'service', zone: 'aws', tech: 'Node.js, Express', responsibility: 'Accepts orders.', evidence: [{path: 'src/api/server.js', lines: [3, 4], why: 'the route'}]},
      {id: 'table', label: 'Orders table', kind: 'database', zone: 'aws', service: 'Amazon DynamoDB', responsibility: 'Stores orders.', evidence: [{path: 'template.yaml', lines: [2, 3]}]},
    ],
    edges: [
      {id: 'post', from: 'user', to: 'api', label: 'POST /orders', kind: 'sync', protocol: 'HTTPS', evidence: [{path: 'src/api/server.js', lines: [4, 4]}]},
      {id: 'put', from: 'api', to: 'table', label: 'PutItem', kind: 'data', evidence: [{path: 'src/store/orders.js', lines: [4, 4]}]},
    ],
    flows: [{id: 'place', title: 'Place an order', steps: [{edge: 'post', text: 'The customer posts an order.'}, {edge: 'put', text: 'The API writes it.'}]}],
  };
}

test('the scan reads routes, SDK clients, environment, infrastructure and imports with their lines', () => {
  const facts = scan(repo(), {feature: 'store orders'});
  const has = (kind, detail) => facts.signals.find((s) => s.kind === kind && s.detail === detail);
  assert.equal(has('route', 'POST /orders').line, 4);
  assert.equal(has('sdk', 'AWS dynamodb').path, 'src/store/orders.js');
  assert.ok(has('env', 'ORDERS_TABLE'));
  assert.deepEqual(facts.infra.map((r) => [r.type, r.name, r.line]), [['AWS::DynamoDB::Table', 'OrdersTable', 3], ['AWS::Serverless::Function', 'Api', 5]]);
  assert.deepEqual(facts.modules.edges.map((e) => [e.from, e.to]), [['src/api', 'src/store']]);
  assert.equal(facts.feature.files[0].path, 'src/store/orders.js', 'the file most about storing orders comes first');
  assert.equal(chooseFiles(facts)[0], 'src/store/orders.js', 'an analyst reads the feature first');
});

test('a model passes only when every reference resolves and every citation exists', () => {
  const root = repo();
  assert.deepEqual(check(model(), {repoRoot: root}), []);
  const broken = model();
  broken.edges[0].to = 'nowhere';
  broken.nodes[1].evidence = [{path: 'src/api/server.js', lines: [3, 99]}];
  broken.nodes[2].evidence = [{path: '../secrets.txt', lines: [1, 1]}];
  broken.flows[0].steps[1].edge = 'missing';
  broken.nodes.push({id: 'lonely', label: 'Lonely', kind: 'service', responsibility: 'Nothing.', evidence: [{path: 'template.yaml', lines: [1, 1]}]});
  const issues = check(broken, {repoRoot: root}).join('\n');
  assert.match(issues, /edges\[0\] "post": to "nowhere" is not a node/);
  assert.match(issues, /lines 3-99 run past the end of "src\/api\/server.js", which has 5 lines/);
  assert.match(issues, /must be relative to the repository and stay inside it/);
  assert.match(issues, /steps\[1\]: edge "missing" is not an edge/);
  assert.match(issues, /"lonely": has no edge/);
  assert.deepEqual(excerpts(model(), root)['src/api/server.js:4-4'].text, "app.post('/orders', async (req, res) => res.json(await save(req.body)));");
});

test('the layout puts nodes inside their zones and labels where they cover nothing', async () => {
  const lay = await layout(model());
  const zone = lay.zones.find((z) => z.id === 'aws');
  for (const id of ['api', 'table']) {
    const n = lay.nodes.find((x) => x.id === id);
    assert.ok(n.x >= zone.x && n.y >= zone.y && n.x + n.w <= zone.x + zone.w && n.y + n.h <= zone.y + zone.h, `${id} is inside the zone`);
  }
  const boxes = [...lay.nodes.map((n) => ({x: n.x, y: n.y, w: n.w, h: n.h})), ...lay.edges.map((e) => e.label)];
  for (let i = 0; i < boxes.length; i++) for (let j = i + 1; j < boxes.length; j++) {
    const a = boxes[i];
    const b = boxes[j];
    assert.ok(!(a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h), `boxes ${i} and ${j} overlap`);
  }
  // Two labels that would sit on the same spot are pushed apart.
  const crowded = {nodes: [], edges: [0, 1].map((i) => ({id: `e${i}`, points: [{x: 0, y: 0}, {x: 400, y: 0}], label: {w: 100, h: 22}}))};
  placeLabels(crowded);
  const [a, b] = crowded.edges.map((e) => e.label);
  assert.ok(Math.abs(a.x - b.x) >= 100 || Math.abs(a.y - b.y) >= 22, 'labels on one line do not overlap');
});

test('the page embeds its fonts, AWS icons and evidence, and works offline', async () => {
  const root = repo();
  const html = await render(model(), {facts: scan(root), repoRoot: root, analyst: 'test'});
  assert.match(html, /@font-face\{font-family:"Hanken Grotesk";src:url\(data:font\/woff2;base64,/);
  assert.match(html, /<symbol id="i-aws-aws-services-databases-48-amazon-dynamodb-48"/, 'DynamoDB is drawn with its AWS icon');
  assert.match(html, /<symbol id="i-aws-aws-groups-aws-cloud-32"/);
  assert.doesNotMatch(html, /(src|href)="https?:\/\//, 'nothing is fetched from the network');
  const data = JSON.parse(html.match(/<script type="application\/json" id="data">(.*?)<\/script>/s)[1]);
  assert.equal(data.excerpts['template.yaml:2-3'].text, '  OrdersTable:\n    Type: AWS::DynamoDB::Table');
  assert.ok(data.views.find((v) => v.id === 'system').edges.put.badge, 'each edge has a place for its step number');
});

test('small helpers', () => {
  assert.equal(awsServiceIcon('AWS Lambda'), 'aws/services/compute/48/aws-lambda-48');
  assert.equal(awsServiceIcon('Amazon S3'), 'aws/services/storage/48/amazon-simple-storage-service-48');
  assert.equal(awsServiceIcon('Amazon Bedrock AgentCore'), 'aws/services/artificial-intelligence/48/amazon-bedrock-agentcore-48');
  assert.equal(awsServiceIcon('Auth0'), null);
  assert.deepEqual(wrap('Amazon Bedrock AgentCore Gateway service', 22, 2), ['Amazon Bedrock', 'AgentCore Gateway…']);
  assert.equal(sourceUrl({remote: 'git@github.com:acme/app.git', commit: 'abc'}, {path: 'crates/core/src/lib.rs', lines: [3, 9]}), 'https://github.com/acme/app/blob/abc/crates/core/src/lib.rs#L3-L9');
  assert.deepEqual(parseAnswer('Here it is:\n```json\n{"a": 1}\n```'), {a: 1});
});

test('the writing check names the text that breaks a rule', {skip: lint(model()) === null && 'the asd-ste100 skill is not installed'}, () => {
  const m = model();
  assert.deepEqual(texts(m).map((t) => t.where).slice(0, 3), ['summary', 'nodes "user".responsibility', 'nodes "api".responsibility']);
  assert.equal(lint(m).hard.length, 0, 'short active sentences pass');
  m.nodes[1].responsibility = 'Accepts orders; it validates them.';
  m.flows[0].steps[0].text = 'The order is posted by the customer.';
  const found = lint(m);
  assert.deepEqual(found.hard.map((f) => [f.where, f.rule]), [['nodes "api".responsibility', 'semicolon']]);
  assert.deepEqual(found.advisory.map((f) => [f.where, f.rule]), [['flows "place".steps[0].text', 'passive-voice']]);
});

test('a model in areas reads as an overview, the whole system, each area and its feature views', () => {
  const root = repo();
  const m = model();
  m.zones.push({id: 'ingest', label: 'Ingestion', kind: 'area', parent: 'aws', note: 'Takes orders in.'}, {id: 'store', label: 'Storage', kind: 'area', parent: 'aws', note: 'Keeps them.'});
  m.nodes[1].zone = 'ingest';
  m.nodes[2].zone = 'store';
  m.nodes.push({id: 'validator', label: 'Validator', kind: 'function', zone: 'ingest', detail: true, responsibility: 'Checks an order.', evidence: [{path: 'src/api/server.js', lines: [4, 4]}]});
  m.edges.push({id: 'check', from: 'api', to: 'validator', label: 'validate', kind: 'sync', evidence: [{path: 'src/api/server.js', lines: [4, 4]}]});
  m.flows[0].steps[0].explain = 'The customer sends the order over HTTPS. The API answers when it is stored.';
  assert.match(check(m, {repoRoot: root}).join('\n'), /"validator": is detail but in no view/);
  m.views = [{id: 'validation', title: 'Order validation', nodes: ['user', 'api', 'validator'], flows: []}];
  assert.deepEqual(check(m, {repoRoot: root}), []);
  const list = views(m);
  assert.deepEqual(list.map((v) => v.id), ['overview', 'system', 'area-ingest', 'area-store', 'view-validation']);
  const overview = list[0];
  assert.deepEqual(overview.graph.nodes.map((n) => n.id).sort(), ['area-ingest', 'area-store', 'user']);
  assert.deepEqual(overview.graph.edges.map((e) => [e.from, e.to, e.members]), [['user', 'area-ingest', ['post']], ['area-ingest', 'area-store', ['put']]]);
  assert.ok(!list[1].graph.nodes.some((n) => n.id === 'validator'), 'a detail component is left out of the whole system');
  assert.equal(list[1].graph.zones.find((z) => z.id === 'ingest').label, 'A · Ingestion', 'areas are lettered');
  assert.deepEqual(list[2].context.sort(), ['table', 'user'], 'an area shows what it talks to');
  assert.deepEqual(list[4].graph.nodes.map((n) => n.id), ['user', 'api', 'validator']);
  m.views[0].flows = ['place'];
  assert.match(check(m, {repoRoot: root}).join('\n'), /flow "place" steps over edge "put", whose ends are not both in the view/);
});

test('a plan needs no evidence for what is planned, and says how a changed part changes', () => {
  const root = repo();
  const m = model();
  m.nodes.push({id: 'adapter', label: 'Identity adapter', kind: 'service', zone: 'aws', status: 'planned', responsibility: 'Checks tokens from any provider.'});
  m.edges.push({id: 'verify', from: 'api', to: 'adapter', label: 'verify token', kind: 'auth', status: 'planned'});
  m.nodes[1].status = 'changed';
  m.nodes[1].plan = 'It asks the adapter instead of Auth0.';
  assert.deepEqual(check(m, {repoRoot: root}), []);
  delete m.edges.at(-1).status;
  delete m.nodes[1].plan;
  const issues = check(m, {repoRoot: root}).join('\n');
  assert.match(issues, /edges\[2\] "verify": connects "adapter", which is planned/);
  assert.match(issues, /a changed part needs "plan"/);
});

test('a complete check accounts for every file and reads every file with an architecture signal', () => {
  const root = repo();
  writeFileSync(path.join(root, 'README.md'), '# Orders\n');
  mkdirSync(path.join(root, 'app/api/login'), {recursive: true});
  writeFileSync(path.join(root, 'app/api/login/route.ts'), "export async function POST(req) {\n  return fetch('https://tenant.auth0.com/oauth/token');\n}\n");
  const facts = scan(root);
  assert.ok(facts.signals.find((s) => s.kind === 'route' && s.detail === 'route /api/login'), 'a Next.js route file is an endpoint');
  assert.ok(facts.signals.find((s) => s.kind === 'net' && s.path === 'app/api/login/route.ts'));
  const m = model();
  const problems = () => coverageProblems(m, root).join('\n');
  assert.match(problems(), /app\/api\/login\/route\.ts: \d+ architecture signals .* not accounted for/);
  assert.match(problems(), /\.\/: 2 files .* neither cited nor in coverage/);
  m.coverage = [{path: '.', status: 'skipped', why: 'Manifests and docs.'}, {path: 'app', status: 'skimmed', why: 'Looked for routes.'}];
  assert.match(problems(), /route\.ts: .* in a file that is skimmed; read it/, 'a skimmed file with a route is not enough');
  m.coverage.push({path: 'app/api/login/route.ts', status: 'read'});
  assert.match(problems(), /route\.ts: 3 architecture signals .*http-out https:\/\/tenant\.auth0\.com at line 2\) in a file that is read with no "why"/, 'a way in or out that is left out needs the reason');
  m.coverage.at(-1).why = 'The login route; identity is outside this page.';
  assert.deepEqual(coverageProblems(m, root), []);
  assert.deepEqual(check(m, {repoRoot: root}), []);
});

test('a way in or out is accounted for on its own line: a file cited for one route does not hide the next', async () => {
  const root = repo();
  const server = path.join(root, 'src/api/server.js');
  writeFileSync(server, `${readFileSync(server, 'utf8')}app.delete('/orders/:id', (req, res) => res.end());\nexecFile('pdftk', ['receipt.pdf']);\n// execFile('pdftk') again\n`);
  const m = model();
  m.coverage = [{path: '.', status: 'skipped', why: 'Manifests.'}];
  assert.deepEqual(signalsOf('src/api/server.js', readFileSync(server, 'utf8')).find((s) => s.kind === 'process').lines, [6, 7], 'a signal keeps every line it stands on');
  assert.match(coverageProblems(m, root).join('\n'), /^src\/api\/server\.js: 2 architecture signals in no citation \(route DELETE \/orders\/:id at line 5; process pdftk at line 6\) in a file that is cited on other lines/);
  assert.equal(coverageProblems(m, root).length, 1, 'the SDK import in src/store/orders.js is accounted for by the citation of the call');
  assert.deepEqual(unread(m, root), ['src/api/server.js'], 'cover reads the file again');
  m.nodes[1].evidence.push({path: 'src/api/server.js', lines: [5, 5], why: 'the delete route'}, {path: 'src/api/server.js', lines: [7, 7], why: 'the second place the program is named'});
  assert.deepEqual(coverageProblems(m, root), [], 'a citation of any line a signal stands on accounts for it');
  m.nodes[1].evidence.length = 1;
  // cover names them to the analyst, and keeps asking until each is cited or the file has its reason.
  const asked = [];
  const got = await cover(structuredClone(m), {repoRoot: root, send: async (prompt) => {
    asked.push(prompt);
    return asked.length === 1 ? '{}' : JSON.stringify({nodes: [{id: 'api', evidence: [{path: 'src/api/server.js', lines: [5, 5], why: 'Orders are deleted here.'}]}], files: [{path: 'src/api/server.js', why: 'It also prints a receipt with pdftk, which this page leaves out.'}]});
  }});
  assert.match(asked[0], /SIGNALS IN THESE LINES THAT NO PART CITES \(rule 4a\)\n {2}src\/api\/server\.js:5 route DELETE \/orders\/:id\n {2}src\/api\/server\.js:6 process pdftk\n/);
  assert.match(asked[1], /files: "src\/api\/server\.js": process pdftk at line 6 is in no citation/);
  assert.deepEqual(coverageProblems(got, root), []);
  assert.deepEqual(got.coverage.at(-1), {path: 'src/api/server.js', status: 'read', why: 'It also prints a receipt with pdftk, which this page leaves out.'}, 'a cited file keeps the reason for what is left out of it');
  assert.equal(got.nodes[1].evidence.length, 2);
  m.coverage.push({path: 'src/api', status: 'read', why: 'The delete route and the receipt printer are admin tools, outside this page.'});
  assert.deepEqual(coverageProblems(m, root), [], 'or the ledger says why the model leaves it out');
  // The page says which it is.
  assert.match(await render(m, {repoRoot: root}), /id="coverage-state">✓ Complete coverage/);
  const partial = await render(model(), {repoRoot: root});
  assert.match(partial, /id="coverage-state"><b>Partial coverage<\/b>: 2 places not accounted for/);
  assert.match(partial, /<td class="mono">src\/api\/server\.js<\/td><td>2 architecture signals in no citation \(route DELETE \/orders\/:id at line 5; process pdftk at line 6\) in a file that is cited on other lines<\/td>/);
});

test('a stamped model names every citation whose code changed', () => {
  const root = repo();
  const m = stamp(model(), root);
  assert.deepEqual(check(m, {repoRoot: root}), []);
  writeFileSync(path.join(root, 'src/store/orders.js'), readFileSync(path.join(root, 'src/store/orders.js'), 'utf8').replace('PutItemCommand({', 'PutItemCommand({ConditionExpression: "x", '));
  assert.match(check(m, {repoRoot: root}).join('\n'), /edges\[1\] "put".evidence\[0\]: the code at src\/store\/orders\.js:4-4 changed since the model was stamped/);
});

test('a page holds its model, and a diff marks what was added, changed and removed with the code under each', async () => {
  const root = repo();
  const git = (...a) => execFileSync('git', ['-C', root, ...a], {stdio: 'pipe'}).toString();
  git('init', '-q', '-b', 'main'); git('add', '.'); git('-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-qm', 'base');
  git('checkout', '-qb', 'feature');
  writeFileSync(path.join(root, 'src/store/orders.js'), readFileSync(path.join(root, 'src/store/orders.js'), 'utf8').replace('Item: order', 'Item: {...order, at: Date.now()}'));
  writeFileSync(path.join(root, 'src/audit.js'), 'export const audit = () => {};\n');
  git('add', '.'); git('-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-qm', 'feature');
  const page = await render(model(), {repoRoot: root});
  assert.deepEqual(readPage(writeTemp(page)).model.nodes.map((n) => n.id), ['user', 'api', 'table'], 'the page alone is the state');
  const head = model();
  head.nodes[2].label = 'Orders store';
  head.nodes.splice(0, 1);
  head.edges.splice(0, 1);
  head.flows = [{id: 'place', title: 'Place an order', steps: [{edge: 'put', text: 'The API writes it.'}]}];
  head.nodes.push({id: 'audit', label: 'Audit log', kind: 'service', zone: 'aws', responsibility: 'Records changes.', evidence: [{path: 'src/audit.js', lines: [1, 1]}]});
  head.edges.push({id: 'log', from: 'api', to: 'audit', label: 'record', kind: 'async', evidence: [{path: 'src/audit.js', lines: [1, 1]}]});
  const {model: merged, counts} = diffModels(model(), head);
  assert.deepEqual(counts, {added: 2, changed: 2, removed: 2});
  assert.deepEqual(merged.nodes.map((n) => [n.id, n.change ?? '']), [['user', 'removed'], ['api', ''], ['table', 'changed'], ['audit', 'added']]);
  assert.deepEqual(merged.nodes[2].changed, ['label']);
  const changes = owners(merged, gitChanges(root, 'main', 'feature'));
  assert.deepEqual(changes.files.map((f) => [f.path, f.status, f.owners]), [['src/audit.js', 'added', ['audit', 'log']], ['src/store/orders.js', 'modified', ['put']]]);
  assert.match(changes.files[1].patch, /^\+.*at: Date\.now\(\)/m);
  const html = await render(merged, {repoRoot: root, diff: {base: {label: 'main'}, head: {label: 'feature'}, counts, changes, repo: {}}});
  assert.match(html, /class="node k-user chg-removed"/);
  assert.match(html, /data-view="changes"/);
});

// The identity provider as a real repository names it: in code, in settings, in a document, and behind a wrapper.
function withAuth0(root) {
  const put = (rel, text) => { mkdirSync(path.dirname(path.join(root, rel)), {recursive: true}); writeFileSync(path.join(root, rel), text); };
  put('src/auth/client.js', "import {Auth0Client} from '@auth0/auth0-spa-js';\nexport const login = () => new Auth0Client({});\n");
  put('src/api/guard.js', "import {login} from '../auth/client.js';\nexport const guard = () => login();\n");
  put('.env.example', 'AUTH0_DOMAIN=tenant.eu.auth0.com\nAUTH0_CLIENT_SECRET=hunter2\n');
  put('.env', 'AUTH0_CLIENT_SECRET=real\n');
  put('docs/login.md', 'Login goes through Auth0.\n');
  execFileSync('git', ['-C', root, 'init', '-q']);
  return root;
}

test('a trace finds every file that names a term and every file that imports one, and a complete check holds the model to it', async () => {
  const root = withAuth0(repo());
  const found = trace(root, ['Auth0']);
  assert.deepEqual(found.files.map((f) => f.path).sort(), ['.env.example', 'docs/login.md', 'src/auth/client.js'], 'code, settings and documents, and never the real .env');
  assert.deepEqual(found.dependents, [{path: 'src/api/guard.js', imports: ['src/auth/client.js']}], 'a file behind the wrapper names nothing and still depends on it');
  assert.equal(found.files.find((f) => f.path === '.env.example').lines[1].text, 'AUTH0_CLIENT_SECRET=…', 'a setting is named, its value is not shown');
  assert.ok(scan(root).signals.find((s) => s.kind === 'env' && s.detail === 'AUTH0_DOMAIN' && s.path === '.env.example'), 'a settings file declares its variables');

  const m = model();
  m.coverage = [{path: '.', status: 'skipped', why: 'Manifests.'}, {path: 'docs', status: 'skimmed', why: 'Prose.'}, {path: 'src', status: 'skimmed', why: 'Helpers.'}];
  m.trace = ['auth0'];
  const problems = coverageProblems(m, root).join('\n');
  assert.match(problems, /src\/auth\/client\.js: names auth0 on 2 lines \(first at line 1\), which the model traces, in a file that is skimmed/);
  assert.match(problems, /docs\/login\.md: names auth0/);
  assert.match(problems, /\.env\.example: names auth0 .* in a file that is skipped/);
  assert.doesNotMatch(problems, /guard\.js/, 'an importer that is skimmed is enough');
  m.nodes[1].evidence.push({path: 'src/auth/client.js', lines: [1, 2]});
  m.coverage.push({path: 'docs/login.md', status: 'read'}, {path: '.env.example', status: 'read'});
  assert.deepEqual(coverageProblems(m, root).filter((p) => /auth0/.test(p)), []);
  assert.deepEqual(citers(m).get('src/auth/client.js'), ['api']);
  assert.match(traceText(found, m), /src\/auth\/client\.js: 2 lines, imported by 1 \[Orders API\]/);
  assert.match(traceText(found, m), /src\/api\/guard\.js -> src\/auth\/client\.js \[in no component\]/);
  const html = await render(m, {facts: scan(root), repoRoot: root});
  assert.match(html, /Where the code names auth0/);
  assert.doesNotMatch(html, /only skimmed|not accounted for/);
  assert.match(await render({...m, coverage: m.coverage.slice(0, 3)}, {facts: scan(root), repoRoot: root}), /only skimmed/, 'the page says which traced file the model leaves out');
});

test('the frameworks and settings a wide repository uses give signals', () => {
  const root = repo();
  const put = (rel, text) => { mkdirSync(path.dirname(path.join(root, rel)), {recursive: true}); writeFileSync(path.join(root, rel), text); };
  put('src/users.controller.ts', "@Controller('users')\nexport class Users {\n  @Get(':id')\n  one() {}\n}\n");
  put('src/Api.java', 'class Api {\n  @PostMapping("/pay")\n  void pay() {}\n  @Scheduled(cron = "0 0 * * *")\n  void nightly() {}\n}\n');
  put('api/orders.proto', 'service Orders {\n  rpc Place (Order) returns (Receipt);\n}\n');
  put('config/app.yaml', 'issuer: https://tenant.eu.auth0.com/\n');
  const got = scan(root).signals.map((s) => `${s.path} ${s.kind} ${s.detail}`);
  for (const want of ['src/users.controller.ts route CONTROLLER users', 'src/users.controller.ts route GET :id', 'src/Api.java route POST /pay', 'src/Api.java entry scheduled @Scheduled', 'api/orders.proto route grpc rpc Place', 'config/app.yaml http-out https://tenant.eu.auth0.com']) {
    assert.ok(got.includes(want), `${want}\n${got.join('\n')}`);
  }
});

test('an analyst is asked again until the answer holds, an option that never holds is left out, and an update keeps the ledger', async () => {
  const root = repo();
  const plan = () => {
    const m = model();
    m.nodes.push({id: 'adapter', label: 'Identity adapter', kind: 'service', zone: 'aws', status: 'planned', responsibility: 'Checks tokens.'});
    m.edges.push({id: 'verify', from: 'api', to: 'adapter', label: 'verify token', kind: 'auth', status: 'planned'});
    m.proposal = {problem: 'Login is tied to one provider.', approach: 'Adapter', pros: ['One seam.'], cons: ['One more hop.'], migration: ['Add the adapter.']};
    return m;
  };
  const broken = plan();
  broken.edges.at(-1).to = 'nowhere';
  const asked = [];
  const twice = async (prompt) => { asked.push(prompt); return JSON.stringify(asked.length === 1 ? broken : plan()); };
  const got = await sketch('Replace Auth0', {base: model(), repoRoot: root, send: twice});
  assert.equal(got.nodes.at(-1).id, 'adapter');
  assert.equal(asked.length, 2);
  assert.match(asked[1], /IT HAS THESE PROBLEMS\n- edges\[2\] "verify": to "nowhere" is not a node/, 'the second question carries what was wrong');

  // Three options are named; the third never gives a sketch that holds.
  const send = async (prompt) => {
    if (prompt.includes('{"options"')) return JSON.stringify({options: ['Adapter', 'Proxy', 'Rewrite'].map((name) => ({name, approach: `${name} it.`}))});
    return JSON.stringify(prompt.includes('option 3 of 3') ? broken : plan());
  };
  const said = [];
  const held = await options('Replace Auth0', 3, {base: model(), repoRoot: root, send, say: (m) => said.push(m)});
  assert.deepEqual(held.map((o) => o.name), ['Adapter', 'Proxy']);
  assert.ok(said.some((m) => /^Rewrite: no sketch/.test(m)), said.join('\n'));
  const page = await comparePage(held.map((o, i) => ({model: o.model, href: `p-${i + 1}.html`})), {idea: 'Replace Auth0', recommendation: 'Choose the adapter.'});
  assert.match(page, /href="p-2\.html"/);
  assert.match(page, /Choose the adapter\./);
  assert.match(page, /One more hop\./);
  assert.doesNotMatch(page, /<script(?! type="application\/json")/, 'the comparison needs no script');

  // The code under a citation changes: the analyst returns the parts only, and the ledger and the trace stay.
  const m = stamp({...model(), coverage: [{path: '.', status: 'skipped', why: 'Manifests.'}], trace: ['orders']}, root);
  assert.equal(await update(m, {repoRoot: root, send: () => { throw new Error('not asked'); }}), m, 'nothing changed, nobody is asked');
  writeFileSync(path.join(root, 'src/store/orders.js'), readFileSync(path.join(root, 'src/store/orders.js'), 'utf8').replace('PutItemCommand({', 'PutItemCommand({ConditionExpression: "x", '));
  let brief;
  const next = await update(m, {repoRoot: root, send: async (prompt) => { brief = prompt; const {coverage, trace: t, ...parts} = model(); parts.edges[1].label = 'PutItem if new'; return JSON.stringify(parts); }});
  assert.match(brief, /changed since the model was stamped/);
  assert.equal(next.edges[1].label, 'PutItem if new');
  assert.deepEqual([next.coverage.length, next.trace, next.stamped], [1, ['orders'], undefined], 'what the analyst left out is kept, and the old stamp is gone');
  assert.deepEqual(check(stamp(next, root), {repoRoot: root}), []);
});

test('a diff page lists what changed, can show only that, and marks an area that holds a change', async () => {
  const head = model();
  head.zones.push({id: 'ingest', label: 'Ingestion', kind: 'area', parent: 'aws'}, {id: 'store', label: 'Storage', kind: 'area', parent: 'aws'});
  head.nodes[1].zone = 'ingest';
  head.nodes[2].zone = 'store';
  const base = JSON.parse(JSON.stringify(head));
  head.nodes[2].label = 'Orders store';
  const {model: merged, counts} = diffModels(base, head);
  const html = await render(merged, {diff: {base: {label: 'main'}, head: {label: 'feature'}, counts, changes: null, repo: {}}});
  assert.match(html, /id="changes-card"[\s\S]*?data-goto="table"/, 'the changed component is one click away');
  assert.match(html, /id="only-changes"/);
  assert.match(html, /class="[^"]*area-box[^"]*chg-in/, 'the overview marks the area that holds the change');
  const same = await render(diffModels(base, base).model, {diff: {base: {label: 'a'}, head: {label: 'b'}, counts: {added: 0, changed: 0, removed: 0}, changes: null, repo: {}}});
  assert.match(same, /The two architectures are the same/);
  assert.doesNotMatch(await render(model(), {}), /id="only-changes"/, 'a page of one architecture has no such button');
});

function writeTemp(text) {
  const file = path.join(mkdtempSync(path.join(tmpdir(), 'blueprint-page-')), 'page.html');
  writeFileSync(file, text);
  return file;
}

test('cover reads what nobody read: a file ends cited or in the ledger with a reason, and no citation is lost', async () => {
  const root = repo();
  writeFileSync(path.join(root, 'README.md'), '# Orders\n');
  writeFileSync(path.join(root, 'src/store/retry.js'), 'export const retry = (f) => f().catch(f);\n');
  writeFileSync(path.join(root, '.env.example'), 'ORDERS_TABLE=orders-prod-7f3a\n');
  execFileSync('git', ['-C', root, 'init', '-q']); // git lists a dotfile; a folder with no git does not
  const m = model();
  assert.deepEqual(unread(m, root).sort(), ['.env.example', 'README.md', 'package.json', 'src/store/retry.js']);
  const asked = [];
  const send = async (prompt) => {
    asked.push(prompt);
    return JSON.stringify({
      nodes: [{id: 'api', evidence: [{path: 'src/store/retry.js', lines: [1, 1], why: 'A failed write is tried once more.'}]}],
      files: [{path: 'package.json', why: 'The manifest.'}, {path: '.env.example', why: 'Names the settings.'}, ...(asked.length > 1 ? [{path: 'README.md', why: 'A one-line readme.'}] : [])],
    });
  };
  const got = await cover(m, {repoRoot: root, send});
  assert.equal(asked.length, 2, 'a file that the answer says nothing about is asked for again');
  assert.match(asked[0], /ORDERS_TABLE=…/);
  assert.doesNotMatch(asked[0], /orders-prod-7f3a/, 'the value of a setting never goes to the analyst');
  assert.match(asked[1], /files: "README\.md" was shown to its last line/);
  assert.deepEqual(coverageProblems(got, root), []);
  assert.deepEqual(got.nodes[1].evidence.map((ev) => ev.path), ['src/api/server.js', 'src/store/retry.js'], 'the old citation is kept');
  assert.deepEqual(got.coverage.map((c) => [c.path, c.status]).sort(), [['.env.example', 'read'], ['README.md', 'read'], ['package.json', 'read']]);
  assert.equal(await cover(got, {repoRoot: root, send: () => { throw new Error('not asked'); }}), got, 'nothing unread, nobody is asked');

  // A round that never holds leaves its files unread, and says so.
  const said = [];
  const same = await cover(m, {repoRoot: root, send: async () => '{}', say: (x) => said.push(x)});
  assert.equal(unread(same, root).length, 4);
  assert.ok(said.some((x) => /did not hold/.test(x)), said.join('\n'));
});

test('a note is laid on the page without drawing it again, and the page reads back as text for an assistant', async () => {
  const root = repo();
  const file = writeTemp(await render(model(), {repoRoot: root}));
  let page = readPage(file);
  const put = (entry) => {
    writeFileSync(file, pageWith(readFileSync(file, 'utf8'), {...page, model: noted(page.model, entry)}));
    page = readPage(file);
  };
  put({title: 'Who checks the token?', detail: 'The route </script> has $1 none.', refs: ['post'], at: '2026-11-12'});
  assert.equal(page.model.discussion[0].detail, 'The route </script> has $1 none.', 'a note cannot break out of the page data');
  put({title: 'Who checks the token?', status: 'decided', detail: 'The API checks it.', refs: ['post'], at: '2026-11-12'});
  put({title: 'OWASP ASVS', url: 'https://owasp.org/asvs', detail: 'Session rules.'});
  assert.deepEqual(page.model.discussion, [{title: 'Who checks the token?', detail: 'The API checks it.', status: 'decided', refs: ['post'], at: '2026-11-12'}], 'the same title replaces the line');
  assert.deepEqual(check(page.model, {repoRoot: root}), []);
  const bad = check(noted(page.model, {title: 'x', status: 'maybe', refs: ['nowhere']})).join('\n');
  assert.match(bad, /discussion\[1\]: .*maybe/);
  assert.match(bad, /discussion\[1\]: .*nowhere/);
  assert.match(check(noted(page.model, {title: 'x', url: 'javascript:alert(1)'})).join('\n'), /sources\[1\]: url "javascript:alert\(1\)" must be an http or https address/);

  const all = showText(page);
  assert.match(all, /## Discussion\n- \(decided\) Who checks the token\?/);
  assert.match(all, /OWASP ASVS: https:\/\/owasp\.org\/asvs/);
  const one = showText(page, ['api']);
  assert.match(one, /# Orders API \(api\): service, Node\.js, Express/);
  assert.match(one, /Place an order, step 1/);
  assert.match(one, /src\/api\/server\.js:3-4: the route\n\s+3\| const app = express\(\);/, 'a part comes with the code it cites');
  assert.match(showText(page, ['post']), /## Discussion about it\n- \(decided\)/);
  assert.throws(() => showText(page, ['nope']), /the page has no part "nope"/);
});

test('a sketch names only sources it was given, and carries what the base read and said', async () => {
  const root = repo();
  const base = {...model(), coverage: [{path: '.', status: 'skipped', why: 'Manifests.'}], discussion: [{title: 'Keep the table?', status: 'open', refs: ['table', 'gone']}]};
  const plan = (url) => {
    const m = model();
    m.nodes.push({id: 'adapter', label: 'Identity adapter', kind: 'service', zone: 'aws', status: 'planned', responsibility: 'Checks tokens.'});
    m.edges.push({id: 'verify', from: 'api', to: 'adapter', label: 'verify token', kind: 'auth', status: 'planned'});
    m.proposal = {problem: 'Anyone can post.', approach: 'Adapter', pros: ['One seam.'], cons: ['One more hop.'], migration: ['Add the adapter.']};
    m.sources = [{title: 'RFC 9700', url}];
    return m;
  };
  const asked = [];
  const send = async (prompt) => { asked.push(prompt); return JSON.stringify(plan(asked.length === 1 ? 'https://made.up/guide' : 'https://www.rfc-editor.org/rfc/rfc9700')); };
  const got = await sketch('Check tokens', {base, repoRoot: root, research: 'RFC 9700 (https://www.rfc-editor.org/rfc/rfc9700): check the audience of every token.', send});
  assert.equal(asked.length, 2);
  assert.match(asked[0], /WHAT WAS READ FOR THIS[\s\S]*rfc9700/);
  assert.match(asked[1], /sources: "https:\/\/made\.up\/guide" is not in what you were given to read/);
  assert.deepEqual(got.sources.map((s) => s.url), ['https://www.rfc-editor.org/rfc/rfc9700']);
  assert.deepEqual(got.coverage, base.coverage);
  assert.deepEqual(got.discussion[0].refs, ['table'], 'a note about a part the sketch dropped keeps the parts that are left');
});
