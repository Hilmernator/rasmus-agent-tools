// The facts about a repository that need no model: its files and languages, manifests, infrastructure resources,
// code signals (routes, SDK clients, data stores, queues, identity, model APIs, outgoing hosts, environment) and how
// its modules import each other, each with the file and line it was read from. The analysis starts from these, and
// they are shown on the page as the inventory, so what a model wrote can be told apart from what the code says.
import {execFileSync} from 'node:child_process';
import {readFileSync, statSync, readdirSync, existsSync} from 'node:fs';
import path from 'node:path';

const MAX_FILE = 512 * 1024;
const SKIP_DIRS = new Set(['node_modules', '.git', 'target', 'dist', 'build', 'out', '.next', '.venv', 'venv', '__pycache__', 'vendor', '.cache', 'coverage', '.terraform', 'cdk.out']);
// A real environment file holds secrets, and a page is shared: it is never read. .env.example names the same variables.
const SKIP_FILES = /(^|\/)(\.env|\.env\.local|\.env\.[\w-]+\.local|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|Cargo\.lock|poetry\.lock|uv\.lock|go\.sum|.*\.min\.(js|css)|.*\.map)$/;

export const LANGUAGES = {
  '.ts': 'TypeScript', '.tsx': 'TypeScript', '.mts': 'TypeScript', '.cts': 'TypeScript',
  '.js': 'JavaScript', '.jsx': 'JavaScript', '.mjs': 'JavaScript', '.cjs': 'JavaScript',
  '.py': 'Python', '.rs': 'Rust', '.go': 'Go', '.java': 'Java', '.kt': 'Kotlin', '.cs': 'C#', '.rb': 'Ruby',
  '.php': 'PHP', '.swift': 'Swift', '.m': 'Objective-C', '.c': 'C', '.h': 'C', '.cpp': 'C++', '.hpp': 'C++',
  '.tf': 'Terraform', '.hcl': 'HCL', '.sql': 'SQL', '.sh': 'Shell', '.yml': 'YAML', '.yaml': 'YAML',
  '.json': 'JSON', '.md': 'Markdown', '.html': 'HTML', '.css': 'CSS', '.astro': 'Astro', '.vue': 'Vue', '.svelte': 'Svelte',
  '.toml': 'TOML', '.proto': 'Protocol Buffers', '.graphql': 'GraphQL', '.prisma': 'Prisma',
};
const CODE = new Set(['TypeScript', 'JavaScript', 'Python', 'Rust', 'Go', 'Java', 'Kotlin', 'C#', 'Ruby', 'PHP', 'Swift', 'Objective-C', 'C', 'C++', 'Astro', 'Vue', 'Svelte']);

/** Files of the repository, relative and sorted: what git tracks or would track, else a walk that skips the usual
 * generated and vendored folders. */
export function listFiles(root) {
  let files;
  try {
    files = execFileSync('git', ['-C', root, 'ls-files', '-co', '--exclude-standard', '-z'], {maxBuffer: 256 * 1024 * 1024}).toString().split('\0').filter(Boolean);
  } catch {
    files = [];
    const walk = (dir) => {
      for (const e of readdirSync(path.join(root, dir), {withFileTypes: true})) {
        if (e.name.startsWith('.') && e.name !== '.github') continue;
        const rel = dir ? `${dir}/${e.name}` : e.name;
        if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) walk(rel); } else if (e.isFile()) files.push(rel);
      }
    };
    walk('');
  }
  return files.filter((f) => !f.split('/').some((p) => SKIP_DIRS.has(p)) && !SKIP_FILES.test(f) && existsSync(path.join(root, f))).sort();
}

function git(root, args) {
  try { return execFileSync('git', ['-C', root, ...args], {stdio: ['ignore', 'pipe', 'ignore']}).toString().trim(); } catch { return null; }
}

/** Text of a file, or null for one too large or binary. */
export function readText(root, rel) {
  const full = path.join(root, rel);
  try {
    if (statSync(full).size > MAX_FILE) return null;
    const buf = readFileSync(full);
    if (buf.subarray(0, 8000).includes(0)) return null;
    return buf.toString('utf8');
  } catch { return null; }
}

// Code signals: [kind, file pattern, line pattern, detail from the match]. Kept to patterns that say something about
// architecture; a line can give several.
const JS = /\.((m|c)?(t|j)sx?|astro|vue|svelte)$/;
const PY = /\.py$/;
const RS = /\.rs$/;
const GO = /\.go$/;
const JVM = /\.(java|kt|scala)$/;
const ANY = /\.((m|c)?(t|j)sx?|astro|vue|svelte|py|rs|go|java|kt|scala|rb|php|cs|swift|dart|exs?)$/;
// Settings say what code leaves out: the identity provider's domain in .env.example, the model in a YAML file, the
// SDK in a manifest. CONFIG files give hosts and declared variables; WIDE adds them to the identity and model signals.
const ENVFILE = /(^|\/)\.env[\w.-]*$/;
const CONFIG = /(^|\/)\.env[\w.-]*$|\.(ya?ml|toml|tf|tfvars|ini|properties|conf)$/;
const WIDE = {test: (rel) => ANY.test(rel) || CONFIG.test(rel) || /\.(json|xml|plist)$/.test(rel)};
const SIGNALS = [
  ['route', JS, /\b(app|router|server|fastify|api|hono)\.(get|post|put|patch|delete|all|route)\(\s*['"`]([^'"`]+)['"`]/, (m) => `${m[2].toUpperCase()} ${m[3]}`],
  ['route', PY, /@\w+\.(get|post|put|patch|delete|route|api_route)\(\s*['"]([^'"]+)['"]/, (m) => `${m[1].toUpperCase()} ${m[2]}`],
  ['route', PY, /\bpath\(\s*['"]([^'"]*)['"]/, (m) => `path ${m[1]}`],
  ['route', RS, /\.route\(\s*"([^"]+)"\s*,\s*(get|post|put|patch|delete|any)/, (m) => `${m[2].toUpperCase()} ${m[1]}`],
  ['route', GO, /\.(HandleFunc|Handle|GET|POST|PUT|DELETE)\(\s*"([^"]+)"/, (m) => `${m[1]} ${m[2]}`],
  ['route', RS, /#\[(get|post|put|patch|delete|route)\(\s*"([^"]+)"/, (m) => `${m[1].toUpperCase()} ${m[2]}`],
  ['route', JS, /\b(app|router|server)\.use\(\s*['"`]([^'"`]+)['"`]/, (m) => `USE ${m[2]}`],
  ['route', JS, /^\s*export\s+(?:async\s+)?(?:function|const)\s+(GET|POST|PUT|PATCH|DELETE)\b/, (m) => `${m[1]} (file route)`],
  ['route', JS, /@(Get|Post|Put|Patch|Delete|All|Sse|MessagePattern|EventPattern)\(\s*(?:['"`]([^'"`]*)['"`])?/, (m) => `${m[1].toUpperCase()} ${m[2] || '/'}`],
  ['route', JS, /@Controller\(\s*(?:['"`]([^'"`]*)['"`])?/, (m) => `CONTROLLER ${m[1] || '/'}`],
  ['route', JS, /\b(initTRPC|createTRPCRouter|publicProcedure|protectedProcedure)\b/, (m) => `trpc ${m[1]}`],
  ['route', JVM, /@(Get|Post|Put|Patch|Delete|Request)Mapping\b(?:\(\s*(?:(?:value|path)\s*=\s*)?[[{]?\s*"([^"]*)")?/, (m) => `${m[1].toUpperCase()} ${m[2] || '/'}`],
  ['route', /\.cs$/, /\[Http(Get|Post|Put|Patch|Delete)(?:\(\s*"([^"]*)")?/, (m) => `${m[1].toUpperCase()} ${m[2] || '/'}`],
  ['route', /\.cs$/, /\.Map(Get|Post|Put|Patch|Delete)\(\s*"([^"]+)"/, (m) => `${m[1].toUpperCase()} ${m[2]}`],
  ['route', /\.rb$/, /^\s*(get|post|put|patch|delete|resources?|mount)\s+['":]([\w/:.#-]+)/, (m) => `${m[1].toUpperCase()} ${m[2]}`],
  ['route', /\.php$/, /Route::(get|post|put|patch|delete|any|resource)\(\s*['"]([^'"]+)['"]/, (m) => `${m[1].toUpperCase()} ${m[2]}`],
  ['route', ANY, /(?:\b(ApolloServer|makeExecutableSchema|buildSchema|GraphQLSchema|graphqlHTTP|createYoga|strawberry\.Schema|graphene\.Schema|async_graphql::Schema)\b|@(Resolver|Query|Mutation|Subscription)\()/, (m) => `graphql ${m[1] ?? m[2]}`],
  ['route', /\.(graphql|gql)$/, /^\s*(?:extend\s+)?type\s+(Query|Mutation|Subscription)\b/, (m) => `graphql ${m[1]}`],
  ['route', /\.proto$/, /^\s*(service)\s+(\w+)|^\s*(rpc)\s+(\w+)\s*\(/, (m) => `grpc ${m[1] ?? m[3]} ${m[2] ?? m[4]}`],
  ['listen', ANY, /(grpc\.NewServer|grpc\.server\(|new\s+grpc\.Server|tonic::transport::Server|WebSocketServer|socketio\.Server|Deno\.serve|Bun\.serve)/, (m) => m[1].replace(/\($/, '')],
  ['entry', ANY, /(cron\.schedule|@Cron\(|@Scheduled\(|new\s+CronJob|BackgroundScheduler|@shared_task|@\w+\.task\b|ScheduleExpression)/, (m) => `scheduled ${m[1].replace(/\($/, '')}`],
  ['listen', ANY, /(TcpListener|UdpSocket::bind|UnixListener|createServer\(|\.listen\(\s*[\w.]*(?:port|PORT|\d)|HTTPServer\(|uvicorn\.run|axum::serve|hyper::Server|warp::serve|ListenAndServe|serve\(\s*\{)/, (m) => m[1].replace(/\($/, '')],
  ['ipc', ANY, /\b(UnixStream|NSXPC\w*|ipcMain|ipcRenderer|contextBridge|postMessage|WKWebView|BroadcastChannel|registerProtocol)\b/, (m) => m[1]],
  ['net', ANY, /\b(fetch\(|axios|got\(|ky\.|reqwest::|ureq::|requests\.(?:get|post|put|delete|request)|httpx\.|aiohttp|urllib\.request|http\.Client|URLSession|new\s+WebSocket\(|EventSource\()/, (m) => m[1].replace(/\($/, '')],
  ['middleware', JS, /\b(app|router|server)\.use\(\s*(?!['"`])(\w+)/, (m) => `use ${m[2]}`],
  ['entry', JS, /\bexport\s+(const|async\s+function|function)\s+(handler|main|lambdaHandler)\b/, (m) => `handler ${m[2]}`],
  ['entry', PY, /^def\s+(lambda_handler|handler|main)\s*\(/, (m) => `handler ${m[1]}`],
  ['entry', PY, /if\s+__name__\s*==\s*['"]__main__['"]/, () => 'python __main__'],
  ['entry', RS, /^\s*(pub\s+)?(async\s+)?fn\s+main\s*\(/, () => 'fn main'],
  ['entry', GO, /^func\s+main\s*\(/, () => 'func main'],
  ['sdk', JS, /from\s+['"]@aws-sdk\/client-([\w-]+)['"]/, (m) => `AWS ${m[1]}`],
  ['sdk', JS, /require\(\s*['"]@aws-sdk\/client-([\w-]+)['"]\s*\)/, (m) => `AWS ${m[1]}`],
  ['sdk', JS, /from\s+['"]aws-cdk-lib\/aws-([\w-]+)['"]/, (m) => `CDK ${m[1]}`],
  ['sdk', PY, /boto3\.(client|resource)\(\s*['"]([\w-]+)['"]/, (m) => `AWS ${m[2]}`],
  ['sdk', RS, /\baws_sdk_(\w+)::/, (m) => `AWS ${m[1]}`],
  ['llm', WIDE, /(@anthropic-ai\/sdk|\banthropic\b\.|Anthropic\(|from\s+anthropic|openai|OpenAI\(|bedrock-runtime|BedrockRuntime|InvokeModel|ConverseCommand|claude-[\w.-]+|gpt-[\w.-]+)/, (m) => m[1]],
  ['data', ANY, /\b(DynamoDB(?:Client|DocumentClient)?|PrismaClient|new\s+Pool\(|createPool|mongoose\.connect|MongoClient|redis\.createClient|new\s+Redis\(|ioredis|sqlite3?|psycopg2?|sqlalchemy|create_engine|sqlx::|diesel::|rusqlite|SELECT\s+.+\s+FROM)\b/i, (m) => m[1]],
  ['queue', ANY, /\b(SQSClient|SendMessageCommand|SNSClient|PublishCommand|EventBridgeClient|PutEventsCommand|KafkaJS|new\s+Kafka\(|amqplib|kinesis|StartExecutionCommand|SFNClient)\b/, (m) => m[1]],
  ['queue', ANY, /(?:\b(bullmq|BullModule|[Cc]elery|pika|nats\.connect|PubSub|ServiceBusClient|EventHubProducerClient)\b|@(KafkaListener|SqsListener|RabbitListener|Processor)\()/, (m) => m[1] ?? m[2]],
  ['auth', WIDE, /\b(jwt\.verify|jwtVerify|jsonwebtoken|jose|passport\.|Auth0\w*|auth0|Cognito\w*|CognitoJwtVerifier|OAuth2?|oidc|openid|Authorization|Bearer|getServerSession|getSession|withApiAuthRequired|withPageAuthRequired|withMiddlewareAuthRequired|getAccessToken|useUser|express-openid-connect|NextAuth|next-auth|msal|Entra|AzureAD|Clerk\w*|clerkMiddleware|supabase\.auth|firebase\/auth|getAuth|lucia|better-auth|keycloak|Okta\w*|Set-Cookie|cookies\(\)|api[_-]?key|bcrypt|argon2|pbkdf2|createHmac|express-session|cookie-session|iron-session|csrf|SAML\w*|saml|WebAuthn|passkeys?|totp|jwks|JWKS|id_token|access_token|refresh_token|client_secret)\b/, (m) => m[1]],
  ['http-out', ANY, /['"`](https:\/\/[a-z0-9.-]+\.[a-z]{2,})(?=[/'"`:])/i, (m) => m[1]],
  ['http-out', CONFIG, /(https:\/\/[a-z0-9.-]+\.[a-z]{2,})/i, (m) => m[1]],
  ['env', ENVFILE, /^\s*(?:export\s+)?([A-Z][A-Z0-9_]+)\s*=/, (m) => m[1]],
  ['env', JS, /process\.env\.([A-Z][A-Z0-9_]+)/, (m) => m[1]],
  ['env', PY, /os\.(?:environ(?:\.get)?\[?\(?|getenv\()\s*['"]([A-Z][A-Z0-9_]+)['"]/, (m) => m[1]],
  ['env', RS, /env::var\(\s*"([A-Z][A-Z0-9_]+)"/, (m) => m[1]],
  ['process', ANY, /\b(execFileSync|execFile|spawnSync|spawn|exec)\(\s*['"`]([\w./-]+)['"`]|Command::new\(\s*"([\w./-]+)"|subprocess\.\w+\(\s*\[\s*['"]([\w./-]+)['"]/, (m) => m[2] ?? m[3] ?? m[4]],
];

// Routes given by where a file is, not by a call: Next.js, SvelteKit, Remix, Nuxt and the like. A file here is an
// endpoint even when its code names no path.
const FILE_ROUTES = [
  [/(^|\/)app\/(.*\/)?route\.(m|c)?(t|j)sx?$/, (rel) => `route ${rel.replace(/^.*?app\//, '/').replace(/\/?route\.\w+$/, '') || '/'}`],
  [/(^|\/)pages\/api\/.+\.(m|c)?(t|j)sx?$/, (rel) => `api ${rel.replace(/^.*?pages\//, '/').replace(/(\/index)?\.\w+$/, '')}`],
  [/(^|\/)(src\/)?middleware\.(m|c)?(t|j)s$/, () => 'middleware (runs before every matched request)'],
  [/(^|\/)\+server\.(t|j)s$/, (rel) => `endpoint ${rel.replace(/^.*?routes\//, '/').replace(/\/?\+server\.\w+$/, '') || '/'}`],
  [/(^|\/)app\/routes\/.+\.(t|j)sx?$/, (rel) => `remix ${rel.replace(/^.*?routes\//, '/').replace(/\.\w+$/, '')}`],
  [/(^|\/)server\/(api|routes)\/.+\.(t|j)s$/, (rel) => `nuxt ${rel.replace(/^.*?server\//, '/').replace(/\.\w+$/, '')}`],
];

export const SIGNAL_KINDS = ['route', 'entry', 'listen', 'middleware', 'sdk', 'llm', 'data', 'queue', 'auth', 'http-out', 'net', 'ipc', 'process', 'env'];

const IGNORED_HOSTS = /(w3\.org|schema\.org|example\.(com|org)|localhost|github\.com\/[\w-]+\/[\w-]+\/(blob|tree)|json-schema\.org|creativecommons|apache\.org\/licenses|opensource\.org|mozilla\.org)/;

function infraOf(rel, text) {
  const out = [];
  const lines = text.split('\n');
  const add = (i, kind, type, name) => out.push({path: rel, line: i + 1, kind, type, name});
  if (rel.endsWith('.tf')) {
    lines.forEach((l, i) => {
      const r = /^\s*(resource|data|module)\s+"([\w-]+)"\s*(?:"([\w-]+)")?/.exec(l);
      if (r) add(i, 'terraform', r[1] === 'module' ? `module ${r[2]}` : r[1] === 'data' ? `data ${r[2]}` : r[2], r[3] ?? r[2]);
      const p = /^\s*provider\s+"([\w-]+)"/.exec(l);
      if (p) add(i, 'terraform', `provider ${p[1]}`, p[1]);
    });
  }
  if (/\.(ya?ml|json)$/.test(rel)) {
    let resource = null;
    lines.forEach((l, i) => {
      const n = /^ {2}([A-Za-z0-9]+):\s*$/.exec(l);
      if (n) resource = n[1];
      const t = /^\s*"?Type"?\s*:\s*"?((AWS|Custom|Alexa)::[\w:]+)"?/.exec(l);
      if (t) add(i, 'cloudformation', t[1], resource ?? '');
    });
  }
  if (/(^|\/)(docker-)?compose(\.[\w-]+)?\.ya?ml$/.test(rel)) {
    let inServices = false;
    lines.forEach((l, i) => {
      if (/^services:\s*$/.test(l)) { inServices = true; return; }
      if (/^\S/.test(l)) inServices = false;
      const s = /^ {2}([\w.-]+):\s*$/.exec(l);
      if (inServices && s) add(i, 'compose', 'service', s[1]);
    });
  }
  if (/(^|\/)serverless\.ya?ml$/.test(rel)) {
    lines.forEach((l, i) => { const h = /^\s*handler:\s*(\S+)/.exec(l); if (h) add(i, 'serverless', 'function', h[1]); });
  }
  if (/\.ya?ml$/.test(rel) && /^kind:\s*\w+/m.test(text) && /^apiVersion:/m.test(text)) {
    lines.forEach((l, i) => { const k = /^kind:\s*(\w+)/.exec(l); if (k) add(i, 'kubernetes', k[1], ''); });
  }
  if (/(^|\/)Dockerfile[\w.-]*$/.test(rel)) {
    lines.forEach((l, i) => { const f = /^\s*FROM\s+(\S+)/i.exec(l); if (f) add(i, 'docker', 'image', f[1]); const c = /^\s*(CMD|ENTRYPOINT)\s+(.+)/i.exec(l); if (c) add(i, 'docker', c[1].toLowerCase(), c[2].slice(0, 80)); });
  }
  if (/^\.github\/workflows\/.+\.ya?ml$/.test(rel)) {
    lines.forEach((l, i) => {
      const nm = /^name:\s*(.+)/.exec(l); if (nm) add(i, 'workflow', 'workflow', nm[1].trim());
      const u = /^\s*-?\s*uses:\s*(\S+)/.exec(l); if (u && /(deploy|aws|azure|gcp|google|terraform|cdk|docker|pages|vercel|netlify)/i.test(u[1])) add(i, 'workflow', 'action', u[1]);
      const r = /^\s*-?\s*run:\s*(.*(deploy|cdk|terraform|sam |serverless|docker push|kubectl|helm).*)/i.exec(l); if (r) add(i, 'workflow', 'run', r[1].trim().slice(0, 100));
    });
  }
  if (JS.test(rel)) {
    lines.forEach((l, i) => {
      const c = /new\s+(\w+)\.(\w+)\(\s*(?:this|scope|stack|\w+)\s*,\s*['"`]([^'"`]+)['"`]/.exec(l);
      if (c && /^[a-z]/.test(c[1]) && /^[A-Z]/.test(c[2])) add(i, 'cdk', `${c[1]}.${c[2]}`, c[3]);
    });
  }
  return out;
}

function manifestOf(rel, text) {
  const base = path.basename(rel);
  try {
    if (base === 'package.json') {
      const p = JSON.parse(text);
      return {path: rel, kind: 'npm', name: p.name ?? null, dependencies: Object.keys({...p.dependencies, ...p.peerDependencies}), devDependencies: Object.keys(p.devDependencies ?? {}), scripts: p.scripts ?? {}, bin: p.bin ?? null, main: p.main ?? null, workspaces: p.workspaces ?? null};
    }
    if (base === 'Cargo.toml') {
      const name = /^\[package\][^[]*?^name\s*=\s*"([^"]+)"/ms.exec(text)?.[1] ?? null;
      const deps = [...text.matchAll(/^\[(?:dev-)?dependencies\]([^[]*)/gm)].flatMap((m) => [...m[1].matchAll(/^([\w-]+)\s*=/gm)].map((d) => d[1]));
      const members = /members\s*=\s*\[([^\]]*)\]/s.exec(text)?.[1].match(/"([^"]+)"/g)?.map((s) => s.slice(1, -1)) ?? null;
      return {path: rel, kind: 'cargo', name, dependencies: deps, workspaces: members};
    }
    if (base === 'pyproject.toml') {
      const name = /^name\s*=\s*"([^"]+)"/m.exec(text)?.[1] ?? null;
      const deps = (/dependencies\s*=\s*\[([^\]]*)\]/s.exec(text)?.[1].match(/"([^"]+)"/g) ?? []).map((s) => s.slice(1, -1).split(/[<>=!~ ;[]/)[0]);
      return {path: rel, kind: 'python', name, dependencies: deps};
    }
    if (base === 'requirements.txt') {
      return {path: rel, kind: 'python', name: null, dependencies: text.split('\n').map((l) => l.trim().split(/[<>=!~ ;[]/)[0]).filter((l) => l && !l.startsWith('#') && !l.startsWith('-'))};
    }
    if (base === 'go.mod') {
      return {path: rel, kind: 'go', name: /^module\s+(\S+)/m.exec(text)?.[1] ?? null, dependencies: [...text.matchAll(/^\s+([\w./-]+)\s+v[\d.]+/gm)].map((m) => m[1])};
    }
    if (base === 'pom.xml' || base === 'build.gradle' || base === 'build.gradle.kts') {
      return {path: rel, kind: base === 'pom.xml' ? 'maven' : 'gradle', name: /<artifactId>([^<]+)</.exec(text)?.[1] ?? null, dependencies: [...text.matchAll(/<artifactId>([^<]+)<\/artifactId>|implementation\s*\(?['"]([^'"]+)['"]/g)].map((m) => m[1] ?? m[2]).slice(1)};
    }
  } catch (e) {
    return {path: rel, kind: 'unreadable', error: String(e.message ?? e)};
  }
  return null;
}

/** The module a file belongs to: its folder, at most two levels deep, or the root. */
export function moduleOf(rel) {
  const parts = rel.split('/').slice(0, -1);
  if (parts.length === 0) return '.';
  const head = parts[0];
  // A package's own source folder is part of the package: crates/core/src/x.rs is crates/core.
  if (parts.length >= 2 && ['crates', 'packages', 'apps', 'services', 'libs', 'plugins', 'lambdas', 'functions', 'experiments', 'cmd', 'internal', 'pkg'].includes(head)) return `${head}/${parts[1]}`;
  if (parts.length >= 2 && ['src', 'lib', 'app'].includes(head)) return `${head}/${parts[1]}`;
  return head;
}

/** The files of the repository that `rel` imports. JavaScript and Python by file; Rust by crate, as its Cargo.toml. */
export function importsOf(rel, text, files, crateDirs = new Map()) {
  const out = [];
  const dir = path.posix.dirname(rel);
  const resolveRel = (spec) => {
    const base = path.posix.normalize(path.posix.join(dir, spec));
    const tries = [base, ...['.ts', '.tsx', '.mts', '.js', '.jsx', '.mjs', '.cjs', '.py'].map((e) => base + e), ...['index.ts', 'index.tsx', 'index.js', 'index.mjs', '__init__.py'].map((i) => `${base}/${i}`)];
    // TypeScript lets an import name the .js its .ts compiles to.
    tries.push(base.replace(/\.js$/, '.ts'), base.replace(/\.js$/, '.tsx'), base.replace(/\.mjs$/, '.mts'));
    return tries.find((t) => files.has(t));
  };
  if (JS.test(rel) || /\.(astro|vue|svelte)$/.test(rel)) {
    for (const m of text.matchAll(/(?:import\s[^'"`;]*?from\s*|import\s*\(\s*|require\(\s*|export\s[^'"`;]*?from\s*|import\s+)['"](\.{1,2}\/[^'"]+)['"]/g)) {
      const to = resolveRel(m[1]);
      if (to) out.push(to);
    }
  } else if (PY.test(rel)) {
    for (const m of text.matchAll(/^\s*from\s+(\.+)([\w.]*)\s+import|^\s*(?:from|import)\s+([\w.]+)/gm)) {
      if (m[1]) {
        const up = m[1].length - 1;
        let base = dir;
        for (let i = 0; i < up; i++) base = path.posix.dirname(base);
        const t = (m[2] ? `${base}/${m[2].replace(/\./g, '/')}` : base).replace(/^\.\//, '');
        const hit = [`${t}.py`, `${t}/__init__.py`].find((x) => files.has(x));
        if (hit) out.push(hit);
      } else if (m[3]) {
        const t = m[3].replace(/\./g, '/');
        const hit = [`${t}.py`, `${t}/__init__.py`, `src/${t}.py`, `src/${t}/__init__.py`].find((x) => files.has(x));
        if (hit) out.push(hit);
      }
    }
  } else if (RS.test(rel)) {
    for (const m of text.matchAll(/\buse\s+([a-z_][\w]*)::/g)) {
      const dirOf = crateDirs.get(m[1]);
      if (dirOf) out.push(`${dirOf}/Cargo.toml`);
    }
  }
  return out;
}

/** The architecture signals in one file, each once per file and detail, with its first line and every line it stands
 * on (`lines`). A signal that the file's place gives has no line of its own (`whole`). */
export function signalsOf(rel, text) {
  const out = [];
  for (const [pattern, detail] of FILE_ROUTES) if (pattern.test(rel)) out.push({kind: 'route', detail: detail(rel), path: rel, line: 1, lines: [1], whole: true, text: '(the file\'s place makes it an endpoint)'});
  const seen = new Map();
  text.split('\n').forEach((line, i) => {
    if (line.length > 400) return;
    for (const [kind, filePattern, pattern, detail] of SIGNALS) {
      if (!filePattern.test(rel)) continue;
      const m = pattern.exec(line);
      if (!m) continue;
      const d = detail(m);
      if (!d || (kind === 'http-out' && IGNORED_HOSTS.test(d))) continue;
      const key = `${kind}|${d}`;
      if (seen.has(key)) { seen.get(key).lines.push(i + 1); continue; }
      const signal = {kind, detail: d, path: rel, line: i + 1, lines: [i + 1], text: line.trim().slice(0, 160)};
      seen.set(key, signal);
      out.push(signal);
    }
  });
  return out;
}

/** Where the code names `terms` (a provider, a library, a table: "auth0", "stripe"), in any case, in any text file:
 * code, settings, tests and documents. `files` are the files that name a term, in their text or their path, most
 * mentions first. `dependents` are the files that import one of those and name no term themselves: the callers a
 * change behind a wrapper must keep working, which no search for the term finds. */
export function trace(root, terms) {
  root = path.resolve(root);
  const wanted = [...new Set(terms.map((t) => t.toLowerCase()))];
  const all = listFiles(root);
  const fileSet = new Set(all);
  const files = [];
  const imports = new Map();
  for (const rel of all) {
    const text = readText(root, rel);
    if (text === null) continue;
    const named = new Set(wanted.filter((t) => rel.toLowerCase().includes(t)));
    const lines = [];
    let count = 0;
    text.split('\n').forEach((line, i) => {
      const l = line.toLowerCase();
      const found = wanted.filter((t) => l.includes(t));
      if (!found.length) return;
      found.forEach((t) => named.add(t));
      count += 1;
      // A settings file gives the name; the value can be a secret and the lines go on the page.
      if (lines.length < 5) lines.push({line: i + 1, text: (ENVFILE.test(rel) ? line.replace(/=.*/, '=…') : line).trim().slice(0, 160)});
    });
    if (named.size) files.push({path: rel, terms: [...named], count, lines});
    const to = importsOf(rel, text, fileSet);
    if (to.length) imports.set(rel, to);
  }
  // ponytail: one hop, and only where imports resolve to a file (JavaScript, TypeScript, Python). A caller of a caller
  // is not listed; follow the import graph further when a wrapper is itself wrapped.
  const hit = new Set(files.map((f) => f.path));
  const dependents = [];
  for (const [rel, to] of imports) {
    const through = [...new Set(to.filter((t) => hit.has(t)))];
    if (!hit.has(rel) && through.length) dependents.push({path: rel, imports: through});
  }
  for (const f of files) f.importedBy = [...imports.values()].filter((to) => to.includes(f.path)).length;
  files.sort((a, b) => b.count - a.count || a.path.localeCompare(b.path));
  return {terms: wanted, files, dependents};
}

function featureTerms(query) {
  const stop = new Set(['the', 'and', 'for', 'with', 'how', 'what', 'from', 'into', 'flow', 'feature', 'this', 'that', 'när', 'och', 'hur', 'för', 'med', 'som', 'det']);
  const words = query.toLowerCase().split(/[^a-z0-9åäö_-]+/).flatMap((w) => [w, ...w.split(/[-_]/)]).filter((w) => w.length >= 3 && !stop.has(w));
  return [...new Set(words)];
}

/** Scans `root`. With `feature`, the files most about it are ranked, with the lines that mention it. */
export function scan(root, {feature = null} = {}) {
  root = path.resolve(root);
  const files = listFiles(root);
  const fileSet = new Set(files);
  const languages = new Map();
  const manifests = [];
  const infra = [];
  const signals = [];
  const texts = new Map();
  for (const rel of files) {
    const text = readText(root, rel);
    if (text === null) continue;
    texts.set(rel, text);
    const lang = LANGUAGES[path.extname(rel).toLowerCase()] ?? (path.basename(rel).startsWith('Dockerfile') ? 'Dockerfile' : null);
    if (lang) {
      const l = languages.get(lang) ?? {language: lang, files: 0, lines: 0, code: CODE.has(lang)};
      l.files += 1; l.lines += text.split('\n').length;
      languages.set(lang, l);
    }
    const man = manifestOf(rel, text);
    if (man) manifests.push(man);
    infra.push(...infraOf(rel, text));
  }
  const crateDirs = new Map(manifests.filter((m) => m.kind === 'cargo' && m.name).map((m) => [m.name.replace(/-/g, '_'), path.posix.dirname(m.path)]));
  const moduleEdges = new Map();
  const modules = new Map();
  for (const [rel, text] of texts) {
    const lang = LANGUAGES[path.extname(rel).toLowerCase()];
    const isCode = CODE.has(lang);
    if (isCode) {
      const mod = moduleOf(rel);
      const m = modules.get(mod) ?? {id: mod, files: 0, lines: 0, languages: {}};
      m.files += 1; m.lines += text.split('\n').length; m.languages[lang] = (m.languages[lang] ?? 0) + 1;
      modules.set(mod, m);
      for (const to of importsOf(rel, text, fileSet, crateDirs)) {
        const target = to.endsWith('Cargo.toml') ? path.posix.dirname(to) : moduleOf(to);
        if (target === mod) continue;
        const key = `${mod}\u0000${target}`;
        const e = moduleEdges.get(key) ?? {from: mod, to: target, count: 0, example: `${rel}`};
        e.count += 1;
        moduleEdges.set(key, e);
      }
    }
    signals.push(...signalsOf(rel, text));
  }
  // Modules a Rust crate is made of are named by the crate's folder.
  for (const e of moduleEdges.values()) if (!modules.has(e.to)) modules.set(e.to, {id: e.to, files: 0, lines: 0, languages: {}});
  let featureHits = null;
  if (feature) {
    const terms = featureTerms(feature);
    const ranked = [];
    for (const [rel, text] of texts) {
      const lower = rel.toLowerCase();
      const pathHits = terms.filter((t) => lower.includes(t)).length;
      const hits = [];
      const matched = new Set();
      text.split('\n').forEach((line, i) => {
        const l = line.toLowerCase();
        const found = terms.filter((t) => l.includes(t));
        if (found.length) { found.forEach((t) => matched.add(t)); if (hits.length < 12) hits.push({line: i + 1, text: line.trim().slice(0, 160)}); }
      });
      const score = pathHits * 6 + matched.size * 3 + Math.min(hits.length, 12) * 0.5;
      if (score > 0 && (matched.size > 0 || pathHits > 0)) ranked.push({path: rel, score: Math.round(score * 10) / 10, terms: [...matched], hits});
    }
    ranked.sort((a, b) => b.score - a.score || a.path.localeCompare(b.path));
    featureHits = {query: feature, terms, files: ranked.slice(0, 40)};
  }
  const count = (kind) => signals.filter((s) => s.kind === kind).length;
  return {
    scannedAt: new Date().toISOString(),
    repo: {
      name: path.basename(root), root,
      commit: git(root, ['rev-parse', 'HEAD']), branch: git(root, ['rev-parse', '--abbrev-ref', 'HEAD']),
      remote: git(root, ['remote', 'get-url', 'origin']), dirty: (git(root, ['status', '--porcelain']) ?? '').length > 0,
    },
    files: files.length,
    languages: [...languages.values()].sort((a, b) => b.lines - a.lines),
    manifests,
    infra,
    signals,
    signalCounts: Object.fromEntries(SIGNAL_KINDS.map((k) => [k, count(k)])),
    modules: {nodes: [...modules.values()].sort((a, b) => b.lines - a.lines), edges: [...moduleEdges.values()].sort((a, b) => b.count - a.count)},
    tree: files.filter((f) => f.split('/').length <= 3),
    feature: featureHits,
  };
}
