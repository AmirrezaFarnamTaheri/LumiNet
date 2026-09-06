import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const operations = fs.readFileSync(path.join(root, 'src/pages/Operations.tsx'), 'utf8');
const routes = fs.readFileSync(path.resolve(root, '../../apps/daemon/internal/adapters/api/routes_system.go'), 'utf8');
const handlers = fs.readFileSync(path.resolve(root, '../../apps/daemon/internal/adapters/api/handlers_seventh_planners.go'), 'utf8');
const health = fs.readFileSync(path.join(root, 'src/pages/Health.tsx'), 'utf8');
const dns = fs.readFileSync(path.join(root, 'src/pages/Dns.tsx'), 'utf8');
const connections = fs.readFileSync(path.join(root, 'src/pages/Connections.tsx'), 'utf8');
const rules = fs.readFileSync(path.join(root, 'src/pages/Rules.tsx'), 'utf8');
const settings = fs.readFileSync(path.join(root, 'src/pages/Settings.tsx'), 'utf8');
const dashboard = fs.readFileSync(path.join(root, 'src/pages/Dashboard.tsx'), 'utf8');
const logs = fs.readFileSync(path.join(root, 'src/pages/Logs.tsx'), 'utf8');
const profiles = fs.readFileSync(path.join(root, 'src/pages/Profiles.tsx'), 'utf8');
const planners = fs.readFileSync(path.join(root, 'src/api/planners.ts'), 'utf8');

const expected = [
  ['sniPath', '/api/system/sni-path-plan', 'PlanSNIPaths'],
  ['sniGateway', '/api/system/sni-gateway-plan', 'PlanSNIGateway'],
  ['relay', '/api/system/relay-inspection-plan', 'PlanRelayInspection'],
  ['artifact', '/api/system/artifact-admission-plan', 'PlanArtifactAdmission'],
  ['dnsPolicy', '/api/system/dns-resolution-policy-plan', 'PlanDNSResolutionPolicy'],
  ['muxPolicy', '/api/system/multiplex-policy-plan', 'PlanMultiplexPolicy'],
  ['routingArtifact', '/api/system/routing-artifact-plan', 'PlanRoutingArtifacts'],
  ['tlsFingerprint', '/api/system/tls-fingerprint-policy-plan', 'PlanTLSFingerprintPolicy'],
  ['incident', '/api/system/service-incident-policy-plan', 'PlanServiceIncidentPolicy'],
  ['queue', '/api/system/queue-backpressure-plan', 'PlanQueueBackpressure'],
  ['workflow', '/api/system/network-workflow-plan', 'PlanNetworkWorkflow'],
  ['wireguard', '/api/system/wireguard-device-policy-plan', 'PlanWireGuardDevicePolicy'],
];

let checks = 0;
function ok(condition, message) {
  checks++;
  if (!condition) throw new Error(message);
}

for (const [kind, endpoint, handler] of expected) {
  ok(operations.includes(`'${kind}'`) || operations.includes(`${kind}:`), `Operations missing planner kind ${kind}`);
  ok(operations.includes(`${kind}:'${endpoint}'`), `Operations missing endpoint ${endpoint}`);
  ok(routes.includes(`"${endpoint.replace('/api/system', '')}"`), `system routes missing ${endpoint}`);
  ok(handlers.includes(`func (s *Server) ${handler}`), `handler missing ${handler}`);
}
ok(operations.includes('Every surface is planning-only') || operations.includes('Read-only convergence laboratory'), 'operator copy must identify planning-only authority');
ok(operations.includes("convergencePlanner==='presets'?'Load presets':'Analyze'"), 'planner action must remain generic analyze/load');
ok(!operations.includes('InsecureSkipVerify'), 'Operations must not advertise insecure TLS');
ok(health.includes('/api/system/service-incident-policy-plan'), 'Health must own the incident/maintenance planner surface');
ok(health.includes('Incident & maintenance policy'), 'Health must explain incident lifecycle policy');
ok(health.includes('read-only') || health.includes('Read-only'), 'Health incident policy must state read-only authority');

ok(dns.includes('/api/system/dns-resolution-policy-plan'), 'DNS page must own DNS policy planning');
ok(dns.includes('Resolution policy lab'), 'DNS page must expose resolution policy lab');
ok(dns.includes('Prevent secure → plaintext fallback'), 'DNS page must expose secure downgrade guard');
ok(dns.includes('/api/presets/dns'), 'DNS page must load the existing DNS preset catalog');
ok(dns.includes('Resolver preset'), 'DNS page must expose resolver preset discovery');
ok(dns.includes('Loads resolver addresses into the draft only'), 'DNS preset loading must state draft-only authority');
ok(dns.includes('Load preset'), 'DNS page must expose a non-authoritative preset load action');
ok(dns.includes('/api/system/doh-resolver-pool-plan'), 'DNS page must own DoH resolver-pool planning');
ok(dns.includes('DoH resolver pool evidence'), 'DNS page must expose resolver-pool evidence');
ok(dns.includes('performs no DNS request and installs no resolver'), 'DNS resolver-pool UI must state read-only authority');

ok(connections.includes('/api/system/multiplex-policy-plan'), 'Connections must own multiplex admission planning');
ok(connections.includes('Multiplex capacity policy'), 'Connections must expose multiplex capacity policy');
ok(connections.includes('First Write counts application bytes'), 'Connections must explain application-byte accounting invariant');
ok(connections.includes('planning only'), 'Connections must distinguish unsupported mux protocols from runtime support');
ok(connections.includes('/api/system/endpoint-pool-plan'), 'Connections must own endpoint dispatch planning');
ok(connections.includes('Endpoint dispatch evidence'), 'Connections must expose endpoint dispatch evidence');
ok(connections.includes('may only reorder near-equivalent quality candidates'), 'Connections must expose the bounded quality-band invariant');

ok(rules.includes('/api/system/routing-artifact-plan'), 'Rules must own routing artifact provenance planning');
ok(rules.includes('Routing artifact provenance'), 'Rules must expose routing artifact provenance');
ok(rules.includes('never downloads or installs'), 'Rules provenance planner must state no fetch/install authority');
ok(rules.includes('Expected SHA-256') && rules.includes('Observed SHA-256'), 'Rules must compare immutable digest evidence');
ok(rules.includes('/api/system/l7-signature-plan'), 'Rules must own offline L7 signature admission');
ok(rules.includes('L7 signature admission'), 'Rules must expose L7 signature admission');
ok(rules.includes('never captures traffic or installs a classifier'), 'Rules must state L7 admission has no capture/classifier authority');

ok(settings.includes('Best observed'), 'Settings WARP scanner must expose best observed endpoint');
ok(settings.includes('Median RTT'), 'Settings WARP scanner must expose distribution context');
ok(settings.includes('Copy best'), 'Settings WARP scanner must support non-authoritative copy');
ok(settings.includes('Export evidence'), 'Settings WARP scanner must export scan evidence');
ok(settings.includes('does not activate, persist, or replace'), 'Settings must state WARP scan evidence is non-authoritative');

ok(!dashboard.includes('>Repeat<'), 'Dashboard must not render a fake SNI repeat dimension');
ok(dashboard.includes('raw fake-packet repetition is not implemented') || dashboard.includes('Raw fake-packet repetition is not implemented'), 'Dashboard must explain the removed fake-repeat dimension');

ok(logs.includes('Severity filter'), 'Logs must expose a local severity filter');
ok(logs.includes('Export visible'), 'Logs must support bounded export of the visible retained set');
ok(logs.includes('Broadcast drops'), 'Logs must expose websocket broadcast-drop evidence');
ok(logs.includes('Slow-client disconnects'), 'Logs must expose slow-client disconnect evidence');
ok(logs.includes('websocketBackpressure.broadcastDrops'), 'Logs must bind broadcast-drop evidence to system status');
ok(logs.includes('websocketBackpressure.slowClientDisconnects'), 'Logs must bind slow-client evidence to system status');

ok(profiles.includes('Search profiles or loaded nodes'), 'Profiles must expose bounded local profile/node search');
ok(profiles.includes('visibleProfiles'), 'Profiles search must filter locally derived visible profile state');
ok(profiles.includes('local filter only, no source fetch'), 'Profiles search must state that it has no remote-fetch authority');

ok(planners.includes('parseMultiplexPolicyPlan'), 'typed multiplex planner parser must exist');
ok(planners.includes('parseRoutingArtifactPlan'), 'typed routing artifact parser must exist');
ok(planners.includes('parseDNSResolutionPolicyPlan'), 'typed DNS policy parser must exist');
ok(planners.includes('parseServiceIncidentPolicyPlan'), 'typed incident policy parser must exist');
ok(planners.includes('parseEndpointDispatchPlan'), 'typed endpoint dispatch parser must exist');
ok(planners.includes('parseDoHResolverPoolPlan'), 'typed DoH resolver-pool parser must exist');
ok(planners.includes('parseL7SignatureAdmissionPlan'), 'typed L7 signature parser must exist');

console.log(`post-refactor-225 UI characterization passed: ${checks} checks`);
