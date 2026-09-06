import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const daemon = path.resolve(root, '../../apps/daemon');
const rules = fs.readFileSync(path.join(root, 'src/pages/Rules.tsx'), 'utf8');
const settings = fs.readFileSync(path.join(root, 'src/pages/Settings.tsx'), 'utf8');
const health = fs.readFileSync(path.join(root, 'src/pages/Health.tsx'), 'utf8');
const operations = fs.readFileSync(path.join(root, 'src/pages/Operations.tsx'), 'utf8');
const profiles = fs.readFileSync(path.join(root, 'src/pages/Profiles.tsx'), 'utf8');
const planners = fs.readFileSync(path.join(root, 'src/api/planners.ts'), 'utf8');
const contracts = fs.readFileSync(path.join(root, 'src/api/contracts.ts'), 'utf8');
const routes = fs.readFileSync(path.join(daemon, 'internal/adapters/api/routes_system.go'), 'utf8');
const handlers = fs.readFileSync(path.join(daemon, 'internal/adapters/api/handlers_post_refactor_228_planners.go'), 'utf8');
const routing = fs.readFileSync(path.join(daemon, 'internal/analysis/diagnostics/routing_policy_group_plan.go'), 'utf8');
const browser = fs.readFileSync(path.join(daemon, 'internal/analysis/diagnostics/browser_proxy_handoff_plan.go'), 'utf8');
const gateway = fs.readFileSync(path.join(daemon, 'internal/analysis/diagnostics/gateway_composition_plan.go'), 'utf8');
const wireguard = fs.readFileSync(path.join(daemon, 'internal/analysis/diagnostics/wireguard_index_translation_plan.go'), 'utf8');
const workers = fs.readFileSync(path.join(daemon, 'internal/analysis/diagnostics/worker_affinity_plan.go'), 'utf8');
const compatibility = fs.readFileSync(path.join(daemon, 'internal/networking/proxyconfig/core_compat.go'), 'utf8');
const catalogue = fs.readFileSync(path.join(daemon, 'internal/integrations/sub/node_catalogue.go'), 'utf8');
const retry = fs.readFileSync(path.join(daemon, 'internal/foundation/config/config.go'), 'utf8');

let checks = 0;
function ok(condition, message) { checks++; if (!condition) throw new Error(message); }

for (const [endpoint, handler] of [
  ['routing-policy-group-plan', 'PlanRoutingPolicyGroup'],
  ['wireguard-index-translation-plan', 'PlanWireGuardIndexTranslation'],
]) {
  ok(routes.includes(`"/${endpoint}"`), `system route missing ${endpoint}`);
  ok(handlers.includes(`func (s *Server) ${handler}`), `handler missing ${handler}`);
}
for (const bad of ['http.Get(', 'http.Post(', 'net.Dial(', 'exec.Command(', 'os.WriteFile(']) {
  ok(!handlers.includes(bad), `228 planner handler must not gain hidden authority: ${bad}`);
}

for (const parser of [
  'parseRoutingPolicyGroupPlan',
  'parseBrowserProxyHandoffPlan',
  'parseWorkerAffinityPlan',
  'parseGatewayCompositionPlan',
  'parseWireGuardIndexTranslationPlan',
]) ok(planners.includes(`export function ${parser}`), `typed planner parser missing ${parser}`);

ok(routing.includes('"manual-select", "latency-auto", "fallback", "load-balance"'), 'routing policy modes missing');
ok(routing.includes('maxRoutingPolicyCandidates = 128'), 'routing candidate bound missing');
ok(routing.includes('LatencyMS > 120000'), 'routing latency bound missing');
ok(routing.includes('Weight > 1000'), 'routing weight bound missing');
ok(routing.includes('latency-auto uses caller-supplied observations only and performs no remote probe'), 'latency planner must be caller-evidence-only');
ok(routing.includes('unhealthy candidates never gain automatic dispatch authority'), 'routing health guard missing');
ok(rules.includes('/api/system/routing-policy-group-plan'), 'Rules must own routing policy-group preview');
ok(rules.includes('Routing policy-group preview'), 'Rules routing policy label missing');
ok(rules.includes('manual-select') && rules.includes('latency-auto') && rules.includes('fallback') && rules.includes('load-balance'), 'Rules must expose all policy modes');

ok(browser.includes('maxNativeMessageBytes = 1 << 20'), 'native message bound missing');
ok(browser.includes('chromeExtensionIDPattern'), 'Chrome extension identity validation missing');
ok(browser.includes('com.luminet.browser'), 'native host identity missing');
ok(browser.includes('"init", "get-status", "up", "down"'), 'native command contract missing');
ok(browser.includes('[]int{1000, 2000, 4000, 8000}'), 'browser reconnect backoff contract missing');
ok(browser.includes('"localhost", "127.0.0.0/8", "::1"'), 'browser loopback bypass contract missing');
ok(browser.includes('the planner registers no native host and changes no browser proxy setting'), 'browser planner must declare no native-host or browser-proxy mutation');
ok(browser.includes('RegistersHost       bool') && browser.includes('ChangesBrowserProxy bool'), 'browser authority truth fields missing');
ok(settings.includes('Tailnet & browser handoff planning'), 'Settings browser handoff surface missing');
ok(settings.includes('register no native host') && settings.includes('change no browser proxy'), 'Settings must communicate non-authority');
ok(settings.includes('native host') && settings.includes('reconnect'), 'Settings must expose native-host/reconnect evidence');

for (const preset of ['reverse-tls-relay', 'websocket-edge', 'managed-edge-tunnel']) {
  ok(gateway.includes(`"${preset}"`), `gateway preset missing ${preset}`);
  ok(operations.includes(`value="${preset}"`), `Operations preset missing ${preset}`);
}
ok(gateway.includes('gateway preset and explicit services are mutually exclusive'), 'preset/custom graph authority must be unambiguous');
ok(gateway.includes('the planner downloads nothing and writes no systemd, cron, runit, Caddy, or other service configuration'), 'gateway planner must declare no download or service-config authority');
ok(gateway.includes('Downloads             bool') && gateway.includes('WritesServiceConfig   bool'), 'gateway authority truth fields missing');
ok(operations.includes('Gateway deployment composition'), 'Operations gateway surface missing');
ok(operations.includes('no donor installer') && operations.includes('downloads nothing'), 'Operations must communicate gateway non-authority');

ok(wireguard.includes('len(req.Entries) > 1024'), 'WireGuard translation bound missing');
ok(wireguard.includes('translated receiver index'), 'WireGuard translated-index validation missing');
ok(wireguard.includes('24*time.Hour'), 'WireGuard translation lifetime bound missing');
ok(wireguard.includes('persisted mappings are recovery hints only'), 'persisted WireGuard state must require revalidation');
ok(wireguard.includes('any live receiver-index rewrite must recompute the affected WireGuard packet authentication fields before transmission'), 'live rewrite authentication invariant missing');
ok(wireguard.includes('this planner rewrites no packet and restores no mapping into a live WireGuard owner'), 'WireGuard planner must declare no packet mutation or mapping restore');
ok(wireguard.includes('MutatesPackets') && wireguard.includes('RestoresMappings'), 'WireGuard authority truth fields missing');
ok(operations.includes('/api/system/wireguard-index-translation-plan'), 'Operations WireGuard translation endpoint missing');
ok(operations.includes('WireGuard index-translation recovery'), 'Operations WireGuard recovery surface missing');
ok(operations.includes('restart revalidation') && operations.includes('packet-authentication recomputation'), 'Operations must expose WireGuard recovery invariants');

ok(workers.includes('ProtocolFraming: "ndjson"'), 'worker protocol framing missing');
ok(workers.includes('ReadyHandshake: `{"ready":true}`'), 'worker ready handshake missing');
ok(workers.includes('AffinityQueueDepth: 1'), 'worker affinity queue must stay depth-one');
ok(workers.includes('SharedQueueDepth: 0'), 'worker spillover queue must stay unbuffered');
ok(workers.includes('RecycleOnProtocolError: true'), 'worker desync recycle contract missing');
ok(workers.includes('ColdFirstCallTelemetry: true'), 'worker cold-first-call telemetry missing');
ok(workers.includes('max_protocol_frame_bytes must be'), 'worker protocol frame bound missing');
ok(health.includes('correlated NDJSON worker framing'), 'Health must expose worker framing semantics');
ok(health.includes('affinity queue') && health.includes('shared queue'), 'Health must expose worker backpressure semantics');
ok(health.includes('recycle on protocol error'), 'Health must expose worker desync recovery');

ok(compatibility.includes('case "", "obfs-local", "v2ray-plugin"'), 'sing-box supported SIP003 plugin set missing');
ok(compatibility.includes('unsupported sing-box Shadowsocks SIP003 plugin'), 'unsupported sing-box plugin must fail closed');
ok(compatibility.includes('Shadowsocks SIP003 plugins are unsupported by Xray outbound'), 'Xray plugin semantic-loss guard missing');
ok(compatibility.includes('func EvaluateExternalCoreCompatibility'), 'shared runtime compatibility owner missing');
ok(catalogue.includes('RuntimeActivatable bool'), 'node catalogue runtime truth missing');
ok(catalogue.includes('proxyconfig.EvaluateExternalCoreCompatibility(cfg)'), 'node catalogue must consume shared compatibility owner');
ok(contracts.includes('runtimeActivatable: boolean'), 'UI subscription runtime truth contract missing');
ok(contracts.includes('runtimeCores: string[]'), 'UI subscription core candidates missing');
ok(contracts.includes('runtimeReason?: string'), 'UI subscription incompatibility reason missing');
ok(profiles.includes('planning/import only'), 'Profiles must distinguish importable from activatable');
ok(profiles.includes('External-core candidates:'), 'Profiles must expose compatible external cores');
ok(profiles.includes('!node.runtimeActivatable'), 'Profiles activation must fail early for unsupported runtime nodes');

ok(retry.includes('DefaultMutationAttempts = 3'), 'automatic config mutation retry default changed');
ok(retry.includes('MaxMutationAttempts     = 8'), 'automatic config mutation retry cap changed');
ok(retry.includes('if !errors.Is(err, ErrRevisionConflict)'), 'automatic config mutation retry must remain conflict-only');
ok(retry.includes('maxAttempts = 1'), 'explicit CAS revision must remain one attempt');
ok(retry.includes('cfg, revision := m.GetWithRevision()'), 'automatic retry must use a fresh snapshot per attempt');

if (checks !== 82) throw new Error(`characterization denominator drifted: expected 82 checks, got ${checks}`);
console.log(`post-refactor-228 second-order product convergence characterization passed: ${checks} checks`);
