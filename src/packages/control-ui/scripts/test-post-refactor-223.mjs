import fs from 'node:fs';

const operations = fs.readFileSync(new URL('../src/pages/Operations.tsx', import.meta.url), 'utf8');

const checks = [
  ['DNS reliability parser', operations.includes('ReliabilityPlanView') && operations.includes('recovery_probability_pct') && operations.includes('effective_goodput_kbps')],
  ['DNS reliability request', operations.includes('preset:dnsPreset') && operations.includes('observed_loss_pct:dnsObservedLossPct') && operations.includes('resolvers:dnsResolvers')],
  ['DNS reliability product surface', operations.includes('Reliability mode') && operations.includes('Resolver tiers') && operations.includes('super-fec')],
  ['Transport truth parser', operations.includes('TransportTruthPlanView') && operations.includes('location_verdict') && operations.includes('second_burst_delivery_pct')],
  ['Transport truth request', operations.includes('/api/system/transport-truth-plan') && operations.includes('advertised_country') && operations.includes('measured_egress_country')],
  ['Transport truth product rule', operations.includes('Handshake alone is not connected') && operations.includes('Measured egress') && operations.includes('Advertised country')],
  ['DNS integrity parser', operations.includes('DNSTransportIntegrityPlanView') && operations.includes('preferred_transport') && operations.includes('answer_sets_equal')],
  ['DNS integrity request', operations.includes('/api/system/dns-transport-integrity-plan') && operations.includes('injection_observed') && operations.includes('latency_ms')],
  ['DNS integrity product rule', operations.includes('UDP/TCP DNS integrity') && operations.includes('disagreement is not poisoning') && operations.includes('Preferred transport')],
];
let failed = 0;
for (const [name, ok] of checks) {
  if (!ok) { console.error(`FAIL ${name}`); failed++; }
  else console.log(`PASS ${name}`);
}
if (failed) process.exit(1);
console.log(`post-refactor-223 UI checks=${checks.length}`);
