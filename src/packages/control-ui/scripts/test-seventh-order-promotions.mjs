import { readFileSync } from 'node:fs';

const operations = readFileSync(new URL('../src/pages/Operations.tsx', import.meta.url), 'utf8');
const checks = [
  ['IKEv2 engine card', operations.includes("engine.id === 'ikev2'") && operations.includes('IKEv2 / strongSwan public-key profile')],
  ['IKEv2 start API', operations.includes("controlEngine('ikev2','start')") && operations.includes('private_key') && operations.includes('remote_identity')],
  ['IKEv2 traffic selectors', operations.includes('local_ts') && operations.includes('remote_ts') && operations.includes('Local traffic selector')],
  ['IKE/ESP proposal controls', operations.includes('ike_proposals') && operations.includes('esp_proposals') && operations.includes('IKE proposals')],
  ['mesh route planner action', operations.includes('/api/system/mesh-route-plan') && operations.includes('Mesh route planner')],
  ['mesh policy selector', operations.includes('latency-first') && operations.includes('least-hop')],
  ['mesh route path presentation', operations.includes("route.path.join(' → ')") && operations.includes('reliability_pct')],
  ['endpoint pool planner action', operations.includes('/api/system/endpoint-pool-plan') && operations.includes('Endpoint pool planner')],
  ['endpoint pool quality view', operations.includes('dispatch_order') && operations.includes('warm_pool') && operations.includes('row.quality')],
  ['DNS tunnel planner action', operations.includes('/api/system/dns-tunnel-plan') && operations.includes('DNS tunnel capacity')],
  ['DNS encoding controls', operations.includes('base32') && operations.includes('base64url') && operations.includes('UDP budget')],
  ['DNS plan output', operations.includes('frame_payload_bytes') && operations.includes('query_payload_bytes') && operations.includes('response_payload_bytes')],
];
const failed = checks.filter(([, ok]) => !ok);
if (failed.length) {
  for (const [name] of failed) console.error(`FAIL: ${name}`);
  process.exit(1);
}
console.log(`Seventh-order feature-promotion characterization: ${checks.length} checks passed`);
