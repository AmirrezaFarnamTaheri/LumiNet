import fs from 'node:fs';

const operations = fs.readFileSync(new URL('../src/pages/Operations.tsx', import.meta.url), 'utf8');
const dashboard = fs.readFileSync(new URL('../src/pages/Dashboard.tsx', import.meta.url), 'utf8');
const contracts = fs.readFileSync(new URL('../src/api/contracts.ts', import.meta.url), 'utf8');

const checks = [
  ['endpoint strategy state', operations.includes("useState('quality-first')") && operations.includes('endpointStrategy')],
  ['quality-first option', operations.includes('<option value="quality-first">quality-first</option>')],
  ['least-loaded option', operations.includes('<option value="least-loaded">least-loaded</option>')],
  ['weighted-quality option', operations.includes('<option value="weighted-quality">weighted-quality</option>')],
  ['sticky option', operations.includes('<option value="sticky">sticky</option>')],
  ['endpoint strategy request', operations.includes('strategy:endpointStrategy')],
  ['convergence lab title', operations.includes('Convergence policy lab')],
  ['planning-only operator copy', operations.includes('Every surface is planning-only; none installs policy or opens sockets.')],
  ['KCP planner endpoint', operations.includes("kcp:'/api/system/kcp-policy-plan'")],
  ['DoH planner endpoint', operations.includes("doh:'/api/system/doh-resolver-pool-plan'")],
  ['L7 planner endpoint', operations.includes("l7:'/api/system/l7-signature-plan'")],
  ['traffic planner endpoint', operations.includes("traffic:'/api/system/traffic-profile-plan'")],
  ['routing planner endpoint', operations.includes("routing:'/api/system/routing-corpus-plan'")],
  ['presets planner endpoint', operations.includes("presets:'/api/system/convergence-presets'")],
  ['KCP option', operations.includes('<option value="kcp">KCP policy</option>')],
  ['DoH option', operations.includes('<option value="doh">DoH resolver pool</option>')],
  ['offline L7 option', operations.includes('<option value="l7">L7 signature admission</option>')],
  ['traffic profile option', operations.includes('<option value="traffic">traffic profile</option>')],
  ['routing corpus option', operations.includes('<option value="routing">routing corpus</option>')],
  ['config mutation contract', contracts.includes('configMutationRetry: ConfigMutationRetryStats')],
  ['websocket backpressure contract', contracts.includes('websocketBackpressure: WebSocketBackpressureStats')],
  ['config retry optional version skew', contracts.includes("optionalStatsRecord(record, 'config_mutation_retry'") && contracts.includes('zeroConfigMutationRetryStats()')],
  ['websocket optional version skew', contracts.includes("optionalStatsRecord(record, 'websocket_backpressure'") && contracts.includes('zeroWebSocketBackpressureStats()')],
  ['automatic retry parser', contracts.includes("readNonNegativeNumber(record, 'automatic_retries'")],
  ['exhausted retry parser', contracts.includes("readNonNegativeNumber(record, 'exhausted_retries'")],
  ['broadcast drop parser', contracts.includes("readNonNegativeNumber(record, 'broadcast_drops'")],
  ['slow disconnect parser', contracts.includes("readNonNegativeNumber(record, 'slow_client_disconnects'")],
  ['dashboard config retries', dashboard.includes('Config auto retries') && dashboard.includes('configMutationRetry.automaticRetries')],
  ['dashboard websocket drops', dashboard.includes('WebSocket broadcast drops') && dashboard.includes('websocketBackpressure.broadcastDrops')],
  ['dashboard slow-client truth', dashboard.includes('Slow-client disconnects') && dashboard.includes('websocketBackpressure.slowClientDisconnects')],
];
let failed = 0;
for (const [name, ok] of checks) {
  if (!ok) { console.error(`FAIL ${name}`); failed++; }
  else console.log(`PASS ${name}`);
}
if (failed) process.exit(1);
console.log(`post-refactor-224 UI checks=${checks.length}`);
