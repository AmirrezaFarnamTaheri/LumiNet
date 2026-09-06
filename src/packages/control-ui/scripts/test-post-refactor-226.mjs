import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const daemon = path.resolve(root, '../../apps/daemon');
const rules = fs.readFileSync(path.join(root, 'src/pages/Rules.tsx'), 'utf8');
const settings = fs.readFileSync(path.join(root, 'src/pages/Settings.tsx'), 'utf8');
const health = fs.readFileSync(path.join(root, 'src/pages/Health.tsx'), 'utf8');
const connections = fs.readFileSync(path.join(root, 'src/pages/Connections.tsx'), 'utf8');
const operations = fs.readFileSync(path.join(root, 'src/pages/Operations.tsx'), 'utf8');
const planners = fs.readFileSync(path.join(root, 'src/api/planners.ts'), 'utf8');
const routes = fs.readFileSync(path.join(daemon, 'internal/adapters/api/routes_system.go'), 'utf8');
const handlers = fs.readFileSync(path.join(daemon, 'internal/adapters/api/handlers_post_refactor_226_planners.go'), 'utf8');

let checks = 0;
function ok(condition, message) { checks++; if (!condition) throw new Error(message); }

const endpoints = [
  ['local-ruleset-plan', 'PlanLocalRuleSet'],
  ['tailnet-transaction-plan', 'PlanTailnetTransaction'],
  ['browser-proxy-handoff-plan', 'PlanBrowserProxyHandoff'],
  ['worker-affinity-plan', 'PlanWorkerAffinity'],
  ['websocket-readiness-plan', 'PlanWebSocketReadiness'],
  ['gateway-composition-plan', 'PlanGatewayComposition'],
];
for (const [endpoint, handler] of endpoints) {
  ok(routes.includes(`"/${endpoint}"`), `system route missing ${endpoint}`);
  ok(handlers.includes(`func (s *Server) ${handler}`), `handler missing ${handler}`);
}

for (const parser of ['parseLocalRuleSetPlan','parseTailnetTransactionPlan','parseBrowserProxyHandoffPlan','parseWorkerAffinityPlan','parseWebSocketReadinessPlan','parseGatewayCompositionPlan']) {
  ok(planners.includes(`export function ${parser}`), `typed parser missing ${parser}`);
}

ok(rules.includes('/api/system/local-ruleset-plan'), 'Rules must own local rule-set normalization');
ok(rules.includes('Local rule-set normalization'), 'Rules must expose local rule-set normalization');
ok(rules.includes('No URL is fetched'), 'Rules must state no remote rule fetch authority');
ok(rules.includes('no converted rule is installed or activated'), 'Rules must state no rule install/activation authority');
ok(rules.includes('AdGuard') && rules.includes('Clash') && rules.includes('Surge') && rules.includes('LumiNet'), 'Rules must expose supported local formats');
ok(rules.includes('duplicate') && rules.includes('ignored'), 'Rules must expose normalization accounting');

ok(settings.includes('/api/system/tailnet-transaction-plan'), 'Settings must own Tailnet transaction planning');
ok(settings.includes('/api/system/browser-proxy-handoff-plan'), 'Settings must own browser handoff planning');
ok(settings.includes('Tailnet & browser handoff planning'), 'Settings must expose the combined planning surface');
ok(settings.includes('make no Tailnet API request'), 'Settings must state Tailnet planner has no API authority');
ok(settings.includes('register no native host'), 'Settings must state browser planner has no native-host registration authority');
ok(settings.includes('change no browser proxy'), 'Settings must state browser planner has no proxy mutation authority');
ok(settings.includes("permissions:['nativeMessaging','proxy','storage']"), 'Settings handoff must require bounded browser permissions');
ok(settings.includes("socks5://127.0.0.1:1080"), 'Settings must default to loopback-only proxy handoff');

ok(health.includes('/api/system/worker-affinity-plan'), 'Health must own worker affinity planning');
ok(health.includes('Worker affinity & recovery evidence'), 'Health must expose worker affinity/recovery evidence');
ok(health.includes('planner starts or restarts no process'), 'Health must state no process authority');
ok(health.includes('hard_deadline_ms:5000'), 'Health must send a bounded hard deadline');
ok(health.includes('max_restarts:4'), 'Health must send bounded restart attempts');
ok(health.includes("healthy:false"), 'Health must characterize unhealthy-worker exclusion');

ok(connections.includes('/api/system/websocket-readiness-plan'), 'Connections must own WebSocket readiness planning');
ok(connections.includes('WebSocket backend readiness'), 'Connections must expose protocol readiness');
ok(connections.includes('An open TCP port is not enough'), 'Connections must reject TCP-only readiness');
ok(connections.includes('HTTP 101 upgrade'), 'Connections must require HTTP 101 evidence');
ok(connections.includes('Sec-WebSocket-Accept'), 'Connections must expose accept proof');
ok(connections.includes('Strict TLS verification observed'), 'Connections must expose TLS verification evidence');
ok(connections.includes('network I/O'), 'Connections must disclose planner network authority');

ok(operations.includes('/api/system/gateway-composition-plan'), 'Operations must own gateway composition planning');
ok(operations.includes('Gateway deployment composition'), 'Operations must expose gateway composition');
ok(operations.includes('downloads nothing'), 'Operations must state gateway planner downloads nothing');
ok(operations.includes('writes no service configuration'), 'Operations must state no service-config write authority');
ok(operations.includes('rollback'), 'Operations must expose rollback ordering');
ok(operations.includes('max_restarts:4'), 'Operations must bound gateway restart planning');

ok(planners.includes('credentialAccepted'), 'Tailnet parser must expose credential-acceptance truth');
ok(planners.includes('makesAPIRequest'), 'Tailnet parser must expose API-request truth');
ok(planners.includes('registersHost'), 'browser parser must expose native-host authority truth');
ok(planners.includes('changesBrowserProxy'), 'browser parser must expose proxy-mutation authority truth');
ok(planners.includes('startsProcess'), 'worker parser must expose process authority truth');
ok(planners.includes('performsNetworkIO'), 'WebSocket parser must expose network-I/O truth');
ok(planners.includes('writesServiceConfig'), 'gateway parser must expose service-write authority truth');
ok(planners.includes('restartBackoffSeconds'), 'gateway parser must expose bounded recovery schedule');
ok(planners.includes('sourceLine'), 'rule parser must preserve source-line evidence');

ok(!handlers.includes('http.Get(') && !handlers.includes('http.Post('), '226 planner handlers must not perform direct HTTP requests');
ok(!handlers.includes('os/exec') && !handlers.includes('exec.Command'), '226 planner handlers must not execute processes');
ok(!handlers.includes('os.WriteFile') && !handlers.includes('os.Create'), '226 planner handlers must not write files');
ok(handlers.includes('BuildLocalRuleSetPlan'), 'handler must delegate to local rule owner');
ok(handlers.includes('BuildTailnetTransactionPlan'), 'handler must delegate to Tailnet planner owner');
ok(handlers.includes('BuildBrowserProxyHandoffPlan'), 'handler must delegate to browser handoff owner');
ok(handlers.includes('BuildWorkerAffinityPlan'), 'handler must delegate to worker planner owner');
ok(handlers.includes('BuildWebSocketReadinessPlan'), 'handler must delegate to WebSocket readiness owner');
ok(handlers.includes('BuildGatewayCompositionPlan'), 'handler must delegate to gateway composition owner');

if (checks !== 69) throw new Error(`characterization denominator drifted: expected 69 checks, got ${checks}`);
console.log(`post-refactor-226 UI characterization passed: ${checks} checks`);
