// Icons for the page: AWS's own architecture icons for AWS services and groups, from the skill's own copy
// (../assets/svg, provenance in its catalog), and a small line set in the design system's style (one 1.5px stroke on a
// 24px grid, currentColor) for everything else. They are inlined once as <symbol>s, with their colours turned into CSS
// variables so the page can show them in AWS's colours or quietly in the theme's.
import {readFileSync, existsSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import path from 'node:path';

const LIBRARY = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../assets/svg');
let catalog = null;
function assets() {
  catalog ??= existsSync(path.join(LIBRARY, 'catalog.json')) ? JSON.parse(readFileSync(path.join(LIBRARY, 'catalog.json'), 'utf8')).assets : [];
  return catalog;
}

const short = (s) => s.toLowerCase().replace(/\b(amazon|aws)\b/g, '').replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');

// Names people and code use for AWS services, to the catalog's names.
const ALIASES = {
  s3: 'simple-storage-service', sqs: 'simple-queue-service', sns: 'simple-notification-service', kms: 'key-management-service',
  iam: 'identity-and-access-management', ecs: 'elastic-container-service', eks: 'elastic-kubernetes-service', ecr: 'elastic-container-registry',
  elb: 'elastic-load-balancing', alb: 'elastic-load-balancing', nlb: 'elastic-load-balancing', 'application-load-balancer': 'elastic-load-balancing',
  apigateway: 'api-gateway', 'api-gw': 'api-gateway', 'http-api': 'api-gateway', 'rest-api': 'api-gateway',
  agentcore: 'bedrock-agentcore', 'bedrock-agentcore-gateway': 'bedrock-agentcore', 'agentcore-gateway': 'bedrock-agentcore', 'agentcore-runtime': 'bedrock-agentcore',
  'secrets-manager': 'secrets-manager', 'secretsmanager': 'secrets-manager', 'parameter-store': 'systems-manager', ssm: 'systems-manager',
  route53: 'route-53', 'cloudwatch-logs': 'cloudwatch', logs: 'cloudwatch', 'step-function': 'step-functions', sfn: 'step-functions', states: 'step-functions',
  'event-bridge': 'eventbridge', events: 'eventbridge', kinesis: 'kinesis-data-streams', opensearch: 'opensearch-service', elasticsearch: 'opensearch-service',
  'cognito-user-pool': 'cognito', 'cognito-identity': 'cognito', 'cognito-idp': 'cognito', 'bedrock-runtime': 'bedrock', lambda: 'lambda', 'lambda-function': 'lambda',
  'dynamo-db': 'dynamodb', dynamo: 'dynamodb', cloudformation: 'cloudformation', cdk: 'cloud-development-kit', acm: 'certificate-manager', 'x-ray': 'x-ray', xray: 'x-ray',
  'elasticache-redis': 'elasticache', redis: 'elasticache', aurora: 'aurora', 'rds-postgres': 'rds', postgres: 'rds', ec2: 'ec2', fargate: 'fargate', vpc: 'virtual-private-cloud',
};

/** The catalog id of AWS's icon for a service name ("AWS Lambda", "Amazon S3", "dynamodb"), or null. */
export function awsServiceIcon(name) {
  if (!name) return null;
  const key = short(name);
  const want = ALIASES[key] ?? ALIASES[key.replace(/-/g, '')] ?? key;
  const services = assets().filter((a) => a.id.startsWith('aws/services/') && a.id.includes('/48/'));
  const base = (a) => short(a.id.split('/').pop().replace(/-48$/, ''));
  return (services.find((a) => base(a) === want) ?? services.find((a) => base(a) === `${want}-service`) ?? services.find((a) => base(a).startsWith(want)))?.id ?? null;
}

const GROUP_ICONS = {
  'aws-cloud': 'aws/groups/aws-cloud-32', account: 'aws/groups/aws-account-32', region: 'aws/groups/region-32', vpc: 'aws/groups/virtual-private-cloud-vpc-32',
  'public-subnet': 'aws/groups/public-subnet-32', 'private-subnet': 'aws/groups/private-subnet-32', 'on-prem': 'aws/groups/corporate-data-center-32',
};

// The design system's line set: 24 by 24, drawn with currentColor at 1.5px, round joins.
export const LINE = {
  user: '<circle cx="12" cy="8" r="3.5"/><path d="M5 20c0-3.9 3.1-6.5 7-6.5s7 2.6 7 6.5"/>',
  client: '<rect x="3" y="4.5" width="18" height="15" rx="2"/><path d="M3 8.5h18M6 6.5h.01M8.5 6.5h.01"/>',
  web: '<rect x="3" y="4.5" width="18" height="15" rx="2"/><path d="M3 8.5h18M6 6.5h.01M8.5 6.5h.01"/>',
  mobile: '<rect x="7" y="3" width="10" height="18" rx="2"/><path d="M11 18h2"/>',
  cli: '<rect x="3" y="4.5" width="18" height="15" rx="2"/><path d="M7 10l3 2.5L7 15M12 15h5"/>',
  process: '<rect x="3" y="4.5" width="18" height="15" rx="2"/><path d="M7 10l3 2.5L7 15M12 15h5"/>',
  device: '<rect x="4" y="5" width="16" height="11" rx="1.5"/><path d="M2 19h20"/>',
  cdn: '<circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17M12 3.5c2.4 2.4 3.5 5.2 3.5 8.5s-1.1 6.1-3.5 8.5c-2.4-2.4-3.5-5.2-3.5-8.5s1.1-6.1 3.5-8.5z"/>',
  dns: '<circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17M12 3.5c2.4 2.4 3.5 5.2 3.5 8.5s-1.1 6.1-3.5 8.5c-2.4-2.4-3.5-5.2-3.5-8.5s1.1-6.1 3.5-8.5z"/>',
  firewall: '<path d="M12 3l7.5 3v5.5c0 4.5-3.2 8-7.5 9.5-4.3-1.5-7.5-5-7.5-9.5V6z"/>',
  gateway: '<rect x="4" y="4" width="16" height="16" rx="2"/><path d="M8 9.5h8M13.5 7l2.5 2.5-2.5 2.5M16 14.5H8M10.5 12L8 14.5l2.5 2.5"/>',
  loadbalancer: '<circle cx="5.5" cy="12" r="2"/><circle cx="18.5" cy="5.5" r="2"/><circle cx="18.5" cy="12" r="2"/><circle cx="18.5" cy="18.5" r="2"/><path d="M7.5 12h9M7.2 10.9l9.5-4.6M7.2 13.1l9.5 4.6"/>',
  service: '<rect x="4" y="4" width="16" height="6.5" rx="1.5"/><rect x="4" y="13.5" width="16" height="6.5" rx="1.5"/><path d="M7.5 7.25h.01M7.5 16.75h.01"/>',
  function: '<path d="M6 20l5.5-11M9 4h2.5L18 20"/>',
  container: '<path d="M12 3l8 4.5v9L12 21l-8-4.5v-9z"/><path d="M4 7.5l8 4.5 8-4.5M12 12v9"/>',
  worker: '<circle cx="12" cy="12" r="3"/><path d="M12 3v2.5M12 18.5V21M3 12h2.5M18.5 12H21M5.6 5.6l1.8 1.8M16.6 16.6l1.8 1.8M5.6 18.4l1.8-1.8M16.6 7.4l1.8-1.8"/>',
  scheduler: '<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/>',
  workflow: '<rect x="3" y="4" width="6" height="5" rx="1"/><rect x="15" y="4" width="6" height="5" rx="1"/><rect x="9" y="15" width="6" height="5" rx="1"/><path d="M9 6.5h6M6 9v3.5h6V15M18 9v3.5h-6"/>',
  queue: '<rect x="3" y="7" width="4" height="10" rx="1"/><rect x="10" y="7" width="4" height="10" rx="1"/><rect x="17" y="7" width="4" height="10" rx="1"/>',
  stream: '<path d="M3 8h14M3 12h18M3 16h12M15 6l2 2-2 2M19 10l2 2-2 2"/>',
  topic: '<circle cx="12" cy="12" r="2"/><path d="M8 8a5.6 5.6 0 000 8M16 8a5.6 5.6 0 010 8M5 5a9.9 9.9 0 000 14M19 5a9.9 9.9 0 010 14"/>',
  database: '<ellipse cx="12" cy="5.5" rx="7.5" ry="2.5"/><path d="M4.5 5.5v13c0 1.4 3.4 2.5 7.5 2.5s7.5-1.1 7.5-2.5v-13M4.5 12c0 1.4 3.4 2.5 7.5 2.5s7.5-1.1 7.5-2.5"/>',
  cache: '<path d="M13 3L5 13.5h6L10 21l8-10.5h-6z"/>',
  storage: '<path d="M4 7.5h16l-1.5 12.5h-13z"/><ellipse cx="12" cy="7.5" rx="8" ry="2.5"/>',
  search: '<circle cx="10.5" cy="10.5" r="6"/><path d="M15 15l5.5 5.5"/>',
  identity: '<rect x="3" y="5" width="18" height="14" rx="2"/><circle cx="9" cy="11" r="2.2"/><path d="M5.5 16.5c.5-1.8 1.8-2.8 3.5-2.8s3 1 3.5 2.8M14.5 10h4M14.5 13.5h3"/>',
  secret: '<circle cx="8" cy="15" r="4"/><path d="M11 12l8.5-8.5M16 7l2.5 2.5M14 9l2 2"/>',
  key: '<circle cx="8" cy="15" r="4"/><path d="M11 12l8.5-8.5M16 7l2.5 2.5M14 9l2 2"/>',
  llm: '<rect x="6" y="6" width="12" height="12" rx="2"/><path d="M9.5 3v3M14.5 3v3M9.5 18v3M14.5 18v3M3 9.5h3M3 14.5h3M18 9.5h3M18 14.5h3"/><circle cx="12" cy="12" r="2"/>',
  agent: '<path d="M12 3l7.8 4.5v9L12 21l-7.8-4.5v-9z"/><circle cx="12" cy="12" r="2.5"/>',
  tool: '<path d="M14.5 6.5a4 4 0 00-5.2 5.2L4 17l3 3 5.3-5.3a4 4 0 005.2-5.2L15 12l-3-3z"/>',
  external: '<rect x="4" y="6" width="14" height="14" rx="2"/><path d="M13 3h8v8M21 3l-9 9"/>',
  saas: '<rect x="4" y="6" width="14" height="14" rx="2"/><path d="M13 3h8v8M21 3l-9 9"/>',
  monitoring: '<path d="M3 12h4l2.5-6 4 12 2.5-6H21"/>',
  pipeline: '<circle cx="5" cy="12" r="2"/><circle cx="12" cy="12" r="2"/><circle cx="19" cy="12" r="2"/><path d="M7 12h3M14 12h3"/>',
  module: '<path d="M12 3l8.5 4.5L12 12 3.5 7.5z"/><path d="M3.5 12L12 16.5l8.5-4.5M3.5 16.5L12 21l8.5-4.5"/>',
  library: '<path d="M12 3l8.5 4.5L12 12 3.5 7.5z"/><path d="M3.5 12L12 16.5l8.5-4.5M3.5 16.5L12 21l8.5-4.5"/>',
  chart: '<path d="M4 20h16"/><rect x="6" y="11" width="3" height="7" rx="0.5"/><rect x="11" y="6" width="3" height="12" rx="0.5"/><rect x="16" y="9" width="3" height="9" rx="0.5"/>',
  file: '<path d="M6 3h8l4 4v14H6z"/><path d="M14 3v4h4M9 12h6M9 15.5h6"/>',
  cloud: '<path d="M7 18.5a4.5 4.5 0 01-.6-9 6 6 0 0111.4 1.6A3.8 3.8 0 0117.5 18.5z"/>',
  runtime: '<path d="M12 3l8 4.5v9L12 21l-8-4.5v-9z"/><path d="M4 7.5l8 4.5 8-4.5M12 12v9"/>',
  'trust-boundary': '<path d="M12 3l7.5 3v5.5c0 4.5-3.2 8-7.5 9.5-4.3-1.5-7.5-5-7.5-9.5V6z"/><path d="M9 12l2 2 4-4"/>',
  group: '<rect x="3.5" y="3.5" width="17" height="17" rx="2"/>',
};

function awsSymbol(id, symbolId) {
  const asset = assets().find((a) => a.id === id);
  if (!asset) return null;
  const svg = readFileSync(path.join(LIBRARY, '..', asset.path), 'utf8');
  const viewBox = /viewBox="([^"]+)"/.exec(svg)?.[1] ?? asset.viewBox;
  const inner = svg.replace(/^[\s\S]*?<svg[^>]*>/, '').replace(/<\/svg>\s*$/, '').replace(/<title>[\s\S]*?<\/title>/g, '').replace(/\sid="[^"]*"/g, '')
    .replace(/fill="(#FFFFFF|#FFF|#ffffff|white)"/g, 'fill="var(--icon-fg,#FFFFFF)"')
    .replace(/fill="(#[0-9A-Fa-f]{3,8})"/g, (_, c) => `fill="var(--icon-bg,${c})"`);
  return `<symbol id="${symbolId}" viewBox="${viewBox}">${inner}</symbol>`;
}

/** Collects the icons a page uses and writes them out once as symbols. */
export class Icons {
  constructor() { this.used = new Map(); }

  /** The symbol id for a node: its catalog `icon`, else AWS's icon for its `service`, else the line icon of its kind. */
  forNode(node) {
    const aws = node.icon && assets().some((a) => a.id === node.icon) ? node.icon : awsServiceIcon(node.service);
    if (aws) return this.#use(`aws:${aws}`, () => awsSymbol(aws, this.#sym(`aws:${aws}`)), 'aws');
    const kind = LINE[node.kind] ? node.kind : 'service';
    return this.#use(`line:${kind}`, () => `<symbol id="${this.#sym(`line:${kind}`)}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">${LINE[kind]}</symbol>`, 'line');
  }

  /** The symbol id for a zone: AWS's group icon for AWS groups, else a line icon, or null for a plain group. */
  forZone(zone) {
    const aws = GROUP_ICONS[zone.kind];
    if (aws) return this.#use(`aws:${aws}`, () => awsSymbol(aws, this.#sym(`aws:${aws}`)), 'aws');
    const kind = {saas: 'saas', cloud: 'cloud', device: 'device', client: 'client', runtime: 'runtime', process: 'process', 'trust-boundary': 'trust-boundary'}[zone.kind];
    if (!kind) return null;
    return this.#use(`line:${kind}`, () => `<symbol id="${this.#sym(`line:${kind}`)}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">${LINE[kind]}</symbol>`, 'line');
  }

  #sym(key) { return `i-${key.replace(/[^a-z0-9]+/gi, '-').replace(/^-|-$/g, '')}`; }

  #use(key, make, style) {
    if (!this.used.has(key)) this.used.set(key, {id: this.#sym(key), svg: make(), style});
    const u = this.used.get(key);
    return u.svg ? {id: u.id, style: u.style} : null;
  }

  /** All used icons, as one hidden <svg> of symbols. */
  defs() {
    return `<svg width="0" height="0" style="position:absolute" aria-hidden="true"><defs>${[...this.used.values()].map((u) => u.svg).filter(Boolean).join('')}</defs></svg>`;
  }
}
