import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '..');
const daemon = path.resolve(root, '../../apps/daemon');
const rules = fs.readFileSync(path.join(root, 'src/pages/Rules.tsx'), 'utf8');
const health = fs.readFileSync(path.join(root, 'src/pages/Health.tsx'), 'utf8');
const settings = fs.readFileSync(path.join(root, 'src/pages/Settings.tsx'), 'utf8');
const profiles = fs.readFileSync(path.join(root, 'src/pages/Profiles.tsx'), 'utf8');
const operations = fs.readFileSync(path.join(root, 'src/pages/Operations.tsx'), 'utf8');
const planners = fs.readFileSync(path.join(root, 'src/api/planners.ts'), 'utf8');
const routes = fs.readFileSync(path.join(daemon, 'internal/adapters/api/routes_system.go'), 'utf8');
const handlers = fs.readFileSync(path.join(daemon, 'internal/adapters/api/handlers_post_refactor_229_planners.go'), 'utf8');
const tunnel = fs.readFileSync(path.join(daemon, 'internal/analysis/diagnostics/tunnel_safety_plan.go'), 'utf8');
const split = fs.readFileSync(path.join(daemon, 'internal/analysis/diagnostics/split_tunnel_plan.go'), 'utf8');
const relay = fs.readFileSync(path.join(daemon, 'internal/analysis/diagnostics/relay_constraint_plan.go'), 'utf8');
const rollout = fs.readFileSync(path.join(daemon, 'internal/analysis/diagnostics/update_rollout_plan.go'), 'utf8');
const wg = fs.readFileSync(path.join(daemon, 'internal/analysis/diagnostics/wireguard_device_policy_plan.go'), 'utf8');
const updateAdmission = fs.readFileSync(path.join(daemon, 'internal/foundation/updateadmission/updateadmission.go'), 'utf8');
const updateStore = fs.readFileSync(path.join(daemon, 'internal/foundation/store/update_metadata.go'), 'utf8');
const migrations = fs.readFileSync(path.join(daemon, 'internal/foundation/store/migrations.go'), 'utf8');
const updateStage = fs.readFileSync(path.join(daemon, 'internal/adapters/api/handlers_update_stage.go'), 'utf8');
const updateHelper = fs.readFileSync(path.join(daemon, 'internal/adapters/api/update_metadata_admission.go'), 'utf8');
const artifact = fs.readFileSync(path.join(daemon, 'internal/analysis/diagnostics/artifact_admission_plan.go'), 'utf8');
const tlsEvidence = fs.readFileSync(path.join(daemon, 'internal/analysis/diagnostics/tls_interception_evidence_plan.go'), 'utf8');
const endpointPool = fs.readFileSync(path.join(daemon, 'internal/analysis/diagnostics/endpoint_pool_plan.go'), 'utf8');
const relayWire = fs.readFileSync(path.join(daemon, 'internal/integrations/relayclient/relay_wire.go'), 'utf8');
const gsaRelay = fs.readFileSync(path.join(daemon, 'internal/integrations/relayclient/gsa_relay.go'), 'utf8');
const httpBounds = fs.readFileSync(path.join(daemon, 'internal/integrations/relayclient/http_bounds.go'), 'utf8');

let checks = 0;
function ok(condition, message) { checks++; if (!condition) throw new Error(message); }

for (const [endpoint, handler] of [
  ['tunnel-safety-plan', 'PlanTunnelSafety'],
  ['split-tunnel-plan', 'PlanSplitTunnel'],
  ['relay-constraint-plan', 'PlanRelayConstraints'],
  ['update-rollout-plan', 'PlanUpdateRollout'],
  ['tls-interception-evidence-plan', 'PlanTLSInterceptionEvidence'],
]) {
  ok(routes.includes(`"/${endpoint}"`), `missing system route ${endpoint}`);
  ok(handlers.includes(`func (s *Server) ${handler}`), `missing handler ${handler}`);
}
for (const bad of ['http.Get(', 'http.Post(', 'net.Dial(', 'exec.Command(', 'os.WriteFile(', 'os.Remove(']) {
  ok(!handlers.includes(bad), `229 planner handlers gained hidden side effect: ${bad}`);
}
for (const parser of ['parseTunnelSafetyPlan','parseSplitTunnelPlan','parseRelayConstraintPlan','parseUpdateRolloutPlan','parseTLSInterceptionEvidencePlan']) {
  ok(planners.includes(`export function ${parser}`), `typed planner parser missing ${parser}`);
}

// Tunnel lifecycle truth.
for (const token of ['valid-secured', 'valid-unsecured', 'corrupt', 'degraded-unsafe', 'secured-lockdown', 'secured-tunnel']) ok(tunnel.includes(`"${token}"`), `tunnel safety state missing ${token}`);
ok(tunnel.includes('persisted target state is corrupt; fail-closed recovery treats the desired state as secured'), 'corrupt target state must fail closed');
ok(tunnel.includes('lockdown is required but firewall blocking failed or is not applied'), 'failed firewall block must be surfaced');
ok(tunnel.includes('maxTunnelReconnectAttempts = 20'), 'reconnect hard cap missing');
ok(/MutatesHostNetwork:\s*false/.test(tunnel), 'tunnel safety planner must not mutate host network');
ok(tunnel.includes('LAN allowance is an explicit exception'), 'allow-LAN exception truth missing');
ok(health.includes('/api/system/tunnel-safety-plan'), 'Health tunnel planner endpoint missing');
ok(health.includes('Tunnel safety lifecycle'), 'Health tunnel lifecycle surface missing');
ok(health.toLowerCase().includes('an error is never called secure when blocking failed'), 'Health must explain blocking failure truth');
ok(health.toLowerCase().includes('corrupt persisted secure intent fails closed'), 'Health fail-closed persisted intent copy missing');

// Split tunnel / per-app intent.
ok(split.includes('maxSplitTunnelEntries = 512'), 'split tunnel entry bound missing');
for (const kind of ['package', 'process', 'path']) ok(split.includes(`"${kind}"`), `split tunnel kind missing ${kind}`);
for (const mode of ['off', 'include', 'exclude']) ok(split.includes(`"${mode}"`), `split tunnel mode missing ${mode}`);
ok(split.includes('ManifestSHA256'), 'split tunnel deterministic restore identity missing');
ok(/RuntimeSupported:\s+false/.test(split), 'split tunnel must not claim unsupported runtime');
ok(/RuntimeEnforced:\s+false/.test(split), 'split tunnel must not claim enforcement');
ok(split.includes('filesystem-path exclusions are platform-bound'), 'split tunnel restore revalidation warning missing');
ok(split.includes('does not install drivers, BPF programs, firewall rules, route rules, or app exclusions'), 'split tunnel no-authority invariant missing');
ok(rules.includes('/api/system/split-tunnel-plan'), 'Rules split tunnel endpoint missing');
ok(rules.includes('Split-tunnel admission & backup identity'), 'Rules split tunnel surface missing');
ok(rules.includes('current LumiNet runtime still reports per-app enforcement unavailable'), 'Rules must preserve enforcement truth');
ok(rules.includes('manifest {plan.manifestSHA256}'), 'Rules restore identity display missing');

// Relay and multihop eligibility.
ok(relay.includes('maxRelayConstraintCandidates = 512'), 'relay candidate bound missing');
for (const mode of ['singlehop', 'multihop', 'autohop']) ok(relay.includes(`"${mode}"`), `relay path mode missing ${mode}`);
for (const ownership of ['any', 'owned', 'rented']) ok(relay.includes(`"${ownership}"`), `relay ownership mode missing ${ownership}`);
for (const mode of ['udp2tcp','shadowsocks','quic','lwo']) ok(relay.includes(`"${mode}"`), `relay obfuscation capability missing ${mode}`);
ok(relay.includes('entryID == exitID'), 'multihop identity conflict guard missing');
ok(/RequiresEndpointScoring:\s+true/.test(relay), 'relay eligibility must delegate endpoint scoring');
ok(/PerformsNetworkIO:\s+false/.test(relay), 'relay eligibility must not probe network');
ok(/InstallsTunnel:\s+false/.test(relay), 'relay planner must not launch tunnel');
ok(relay.includes('inactive relays never gain selection eligibility'), 'inactive relay guard missing');
ok(relay.includes('autohop prefers a valid singlehop path'), 'autohop preference invariant missing');
ok(profiles.includes('/api/system/relay-constraint-plan'), 'Profiles relay planner endpoint missing');
ok(profiles.includes('Relay, multihop & obfuscation constraints'), 'Profiles relay constraints surface missing');
ok(profiles.includes('endpoint scorer remains authoritative'), 'Profiles must communicate single scoring owner');
ok(profiles.includes('Multihop never reuses the same relay identity'), 'Profiles multihop identity invariant missing');

// Rollout/replay.
ok(rollout.includes('rollout must be a finite value in 0..1'), 'rollout numeric guard missing');
ok(rollout.includes('metadata_sequence must be non-zero'), 'rollout metadata sequence guard missing');
ok(rollout.includes('MetadataReplayRejected'), 'rollout replay verdict missing');
ok(/RequiresPersistedHighWaterMark:\s*true/.test(rollout), 'rollout high-water requirement missing');
ok(/PersistsHighWaterMark:\s*false/.test(rollout), 'rollout planner must not persist high-water state');
ok(/DownloadsArtifact:\s*false/.test(rollout) && /InstallsUpdate:\s*false/.test(rollout), 'rollout planner gained update authority');
ok(settings.includes('/api/system/update-rollout-plan'), 'Settings rollout endpoint missing');
ok(settings.includes('Update rollout & metadata replay posture'), 'Settings rollout surface missing');
ok(settings.includes('persists no high-water mark and installs nothing'), 'Settings rollout non-authority copy missing');

// Signed schema-v2 persistent replay hardening.
ok(updateAdmission.includes('LegacyManifestSchemaVersion = 1'), 'legacy update schema compatibility missing');
ok(updateAdmission.includes('ManifestSchemaVersion       = 2'), 'signed update schema v2 missing');
ok(updateAdmission.includes('MetadataSequence uint64'), 'signed update metadata sequence missing');
ok(updateAdmission.includes('Rollout          *float64'), 'signed update rollout field missing');
ok(updateAdmission.includes('VerifyWithMinimumSequence'), 'high-water-aware signature verification missing');
ok(updateAdmission.includes('below persisted high-water mark'), 'stale metadata rejection missing');
ok(updateAdmission.includes('schema-v2 update manifest requires non-zero metadata_sequence'), 'schema-v2 sequence requirement missing');
ok(updateAdmission.includes('schema-v2 update manifest rollout must be finite and within 0..1'), 'schema-v2 rollout guard missing');
ok(migrations.includes('CREATE TABLE IF NOT EXISTS update_metadata_state'), 'update high-water migration missing');
ok(updateStore.includes('HighestUpdateMetadataSequence'), 'update high-water read owner missing');
ok(updateStore.includes('AcceptUpdateMetadataSequence'), 'update high-water CAS/advance owner missing');
ok(updateStore.includes('excluded.highest_sequence > update_metadata_state.highest_sequence'), 'SQLite-atomic monotonic advance predicate missing');
ok(updateStore.includes('sequence < uint64(current)'), 'stale persistent sequence classification missing');
ok(updateStore.includes('ON CONFLICT(product) DO UPDATE'), 'update high-water UPSERT owner missing');
ok(updateHelper.includes('verifySignedUpdateAgainstHighWater'), 'API high-water verification helper missing');
ok(updateHelper.includes('acceptSignedUpdateSequence'), 'API high-water acceptance helper missing');
ok(updateHelper.toLowerCase().includes('schema-v1 remains predecessor-compatible'), 'legacy replay claim boundary missing');
ok(updateStage.includes('acceptSignedUpdateSequence'), 'staging must atomically accept metadata sequence before artifact action');

// WireGuard ephemeral peer detail.
ok(wg.includes('EphemeralPeerRetryAttempt'), 'WireGuard ephemeral retry input missing');
ok(wg.includes('EphemeralPeerTimeoutSeconds'), 'WireGuard ephemeral timeout output missing');
ok(wg.includes('timeout := 8'), 'WireGuard initial ephemeral timeout must be 8 seconds');
ok(wg.includes('timeout > 48'), 'WireGuard timeout cap missing');
ok(wg.includes('ephemeral peer negotiation uses exponential timeout growth from 8 seconds capped at 48 seconds'), 'WireGuard ephemeral retry invariant missing');


// Artifact type/magic admission: filename is evidence, never authority.
ok(artifact.includes('Filename       string `json:"filename,omitempty"`') || artifact.includes('Filename       string'), 'artifact filename evidence missing');
ok(artifact.includes('ClaimedFormat'), 'artifact claimed format field missing');
ok(artifact.includes('DetectedFormat'), 'artifact detected format output missing');
ok(artifact.includes('FormatMatchesClaim'), 'artifact format match verdict missing');
ok(artifact.includes('maxArtifactAdmissionSampleBytes = 1 << 20'), 'artifact sample bound missing');
ok(artifact.includes('!<arch>\\n'), 'Debian ar magic detection missing');
ok(artifact.includes('artifact format mismatch: claimed %s but supplied bytes are %s'), 'format mismatch quarantine reason missing');
ok(artifact.includes('artifact format claim cannot be verified without supplied bytes'), 'unverified format claim reason missing');
ok(artifact.includes('secret-bearing artifact material detected'), 'secret-bearing artifact quarantine missing');
ok(operations.includes('claimed_format'), 'Operations artifact example missing claimed format');
ok(operations.includes('content_base64'), 'Operations artifact example must supply bytes for format admission');

// Read-only TLS interception evidence derived from the nested historical corpus.
ok(tlsEvidence.includes('maxTLSInterceptionEvidenceComponents = 32'), 'TLS evidence component bound missing');
for (const match of ['empty', 'possible', 'unlikely', 'impossible']) ok(tlsEvidence.includes(`"${match}"`), `TLS evidence match grade missing ${match}`);
ok(tlsEvidence.includes('GradeRegressed'), 'TLS grade regression verdict missing');
ok(tlsEvidence.includes('PFSLost'), 'TLS PFS-loss verdict missing');
ok(tlsEvidence.includes('WeakCiphersDetected'), 'TLS weak-cipher verdict missing');
ok(tlsEvidence.includes('UsesFingerprintDatabase'), 'TLS fingerprint-database truth field missing');
ok(tlsEvidence.includes('IdentifiesInterceptionProduct'), 'TLS product-identification truth field missing');
ok(tlsEvidence.includes('PerformsNetworkIO'), 'TLS network-I/O truth field missing');
ok(health.includes('/api/system/tls-interception-evidence-plan'), 'Health TLS evidence endpoint missing');
ok(health.includes('TLS interception evidence'), 'Health TLS evidence surface missing');
ok(health.includes('identify a specific interception product') && health.includes('does not capture traffic'), 'Health must explain non-attribution boundary');

// Explicit leak-guard evidence rather than connected==safe inference.
for (const token of ['QUICGuardApplied','STUNGuardApplied','DoHGuardApplied','IPv6GuardApplied','RequiredGuards','MissingOrFailedGuards']) ok(tunnel.includes(token), `tunnel guard field missing ${token}`);
for (const guard of ['dns','quic','stun','doh','ipv6']) ok(tunnel.includes(`"${guard}"`), `tunnel guard vocabulary missing ${guard}`);
ok(health.includes('required_guards') || health.includes('requiredGuards'), 'Health required-guard request missing');
ok(health.includes('missingOrFailedGuards'), 'Health missing/failed guard display missing');

// Per-endpoint quota reserve/headroom integrates with the existing scorer.
for (const token of ['QuotaSafetyBuffer','QuotaHeadroom','QuotaHeadroomPct','QuotaGuarded','QuotaResetAt']) ok(endpointPool.includes(token), `endpoint quota field missing ${token}`);
ok(endpointPool.includes('quota-guarded'), 'endpoint quota-guarded quality missing');
ok(endpointPool.includes('quota-safety-buffer'), 'endpoint selection-basis safety-buffer evidence missing');
ok(endpointPool.includes('quota-reset-evidence'), 'endpoint selection-basis reset evidence missing');
ok(operations.includes('quota_safety_buffer'), 'Operations quota safety buffer example missing');
ok(operations.includes('quota headroom'), 'Operations quota headroom display missing');
ok(operations.includes('quota guarded'), 'Operations quota-guarded display missing');

// Relay sequence correlation and retry identity use one shared wire rule.
ok(relayWire.includes('validateRelayResponseSequence'), 'shared relay response sequence validator missing');
ok(relayWire.includes('sequence mismatch'), 'relay sequence mismatch error missing');
ok(gsaRelay.includes('seqMu'), 'GSA sequence mutex missing');
ok(gsaRelay.includes('writeSeq'), 'GSA write sequence owner missing');
ok(gsaRelay.includes('querySeq'), 'GSA query sequence owner missing');
ok(gsaRelay.includes('validateRelayResponseSequence'), 'GSA must use shared sequence validator');
ok(gsaRelay.includes('s.writeSeq--') || gsaRelay.includes('writeSeq--'), 'failed GSA write must roll sequence back');

// Non-JSON relay responses preserve diagnostic uncertainty.
ok(httpBounds.includes('relayControlDecodeError'), 'relay control decode classifier missing');
ok(httpBounds.includes('returned HTML instead of JSON control data'), 'HTML relay classifier missing');
for (const cause of ['deployment', 'authentication', 'quota', 'intermediary']) ok(httpBounds.includes(cause), `ambiguous relay cause missing ${cause}`);
ok(httpBounds.includes('cause is ambiguous'), 'relay diagnosis must state ambiguity');

if (checks !== 168) throw new Error(`characterization denominator drifted: expected 168 checks, got ${checks}`);
console.log(`post-refactor-229 product/security convergence characterization passed: ${checks} checks`);
