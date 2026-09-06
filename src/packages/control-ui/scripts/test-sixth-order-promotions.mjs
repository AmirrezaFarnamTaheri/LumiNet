import { readFileSync } from 'node:fs';

const operations = readFileSync(new URL('../src/pages/Operations.tsx', import.meta.url), 'utf8');
const profiles = readFileSync(new URL('../src/pages/Profiles.tsx', import.meta.url), 'utf8');

const checks = [
  ['Tor identity action', operations.includes('/api/system/engines/tor/identity') && operations.includes('Rotate Tor identity')],
  ['onion probe action', operations.includes('/api/system/tor/probe') && operations.includes('Probe onion')],
  ['deterministic proxy pool UX', operations.includes('SOCKS5 proxy pool') && operations.includes('torProxyPool')],
  ['VPN Gate discovery', operations.includes('/api/providers/vpngate/servers') && operations.includes('VPN Gate discovery')],
  ['VPN Gate SSTP handoff', operations.includes('useVPNGateSSTP') && operations.includes('Use SSTP')],
  ['SNI repeated ranking', operations.includes('stability_runs') && operations.includes('SNI stability ranking')],
  ['SNI run ceiling UI', operations.includes('max={5}') && operations.includes('setSNIRankRuns')],
  ['XHTTP devcontainer generator', operations.includes('/api/system/provision/templates/vless-devcontainer') && operations.includes('VLESS + XHTTP devcontainer')],
  ['devcontainer pinned version input', operations.includes('devXrayVersion') && operations.includes('Xray version')],
  ['devcontainer mode controls', operations.includes('packet-up') && operations.includes('stream-up') && operations.includes('stream-one')],
  ['devcontainer reviewable file preview', operations.includes('devBundle.files.map') && operations.includes('Download bundle JSON')],
  ['profile export', profiles.includes('luminet.subscription-profiles.v1') && profiles.includes('exportProfiles')],
  ['profile import bound', profiles.includes('512 * 1024') && profiles.includes('64 entries')],
  ['SNI donor corpus loader', operations.includes('/api/sni-scans/spoof/defaults') && operations.includes('Load 285-candidate corpus')],
  ['circumvention capability catalog', operations.includes('/api/circumvention/catalog') && operations.includes('Circumvention capability catalog')],
  ['profile import mirrors retained', profiles.includes('.slice(0, 3)') && profiles.includes('record.mirrors')],
  ['onion metadata presentation', operations.includes('Onion links') && operations.includes('Same service') && operations.includes('torProbe.title') && operations.includes('torProbe.description')],
  ['circumvention catalog integration filters', operations.includes('native') && operations.includes('external-engine') && operations.includes('reference') && operations.includes('visibleCircumventionCatalog')],
  ['full SNI corpus operator affordance', operations.includes('Load 285-candidate corpus') && operations.includes('loadSNICorpus') && operations.includes('/api/sni-scans/spoof/defaults')],
];
const failed = checks.filter(([, ok]) => !ok);
if (failed.length) {
  for (const [name] of failed) console.error(`FAIL: ${name}`);
  process.exit(1);
}
console.log(`Sixth-order feature-promotion characterization: ${checks.length} checks passed`);
