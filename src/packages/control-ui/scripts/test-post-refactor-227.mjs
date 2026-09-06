import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const daemon = path.resolve(root, '../../apps/daemon');
const operations = fs.readFileSync(path.join(root, 'src/pages/Operations.tsx'), 'utf8');
const planners = fs.readFileSync(path.join(root, 'src/api/planners.ts'), 'utf8');
const routes = fs.readFileSync(path.join(daemon, 'internal/adapters/api/routes_system.go'), 'utf8');
const handler = fs.readFileSync(path.join(daemon, 'internal/adapters/api/handlers_post_refactor_227_sni.go'), 'utf8');
const plan = fs.readFileSync(path.join(daemon, 'internal/analysis/diagnostics/sni_decoy_handshake_plan.go'), 'utf8');
const tlsDecoy = fs.readFileSync(path.join(daemon, 'internal/networking/tlsdecoy/decoy.go'), 'utf8');
const diagnostic = fs.readFileSync(path.join(daemon, 'internal/analysis/diagnostics/sni_spoof_scan.go'), 'utf8');
const tunnel = fs.readFileSync(path.join(daemon, 'internal/runtime/proxy/evasion_tunnel_conn.go'), 'utf8');
const divert = fs.readFileSync(path.join(daemon, 'internal/runtime/proxy/evasion_divert.go'), 'utf8');
const rustSpoof = fs.readFileSync(path.resolve(root, '../lumicore/src/evasion/sni_spoof.rs'), 'utf8');
const rustBypass = fs.readFileSync(path.resolve(root, '../lumicore/src/evasion/sni_bypass.rs'), 'utf8');

let checks = 0;
function ok(condition, message) { checks++; if (!condition) throw new Error(message); }

ok(routes.includes('"/sni-decoy-handshake-plan"'), 'system route must expose SNI decoy handshake planner');
ok(handler.includes('func (s *Server) PlanSNIDecoyHandshake'), '227 handler missing');
ok(handler.includes('BuildSNIDecoyHandshakePlan'), '227 handler must delegate to diagnostics owner');
ok(!handler.includes('http.Get(') && !handler.includes('http.Post('), '227 handler must not initiate HTTP');
ok(!handler.includes('os/exec') && !handler.includes('exec.Command'), '227 handler must not execute processes');
ok(!handler.includes('net.Dial') && !handler.includes('Listen('), '227 handler must not open network sockets');

ok(planners.includes('export interface SNIDecoyHandshakePlan'), 'typed 227 plan interface missing');
ok(planners.includes('export function parseSNIDecoyHandshakePlan'), 'typed 227 parser missing');
ok(planners.includes('readyToInject'), 'parser must expose injection eligibility');
ok(planners.includes('readyToRelay'), 'parser must expose relay eligibility');
ok(planners.includes('expectedFakeSeq'), 'parser must expose computed fake sequence');
ok(planners.includes('performsNetworkIO'), 'parser must expose network authority truth');
ok(planners.includes('requiresRawPacketAuthority'), 'parser must expose raw-packet authority boundary');

ok(operations.includes('/api/system/sni-decoy-handshake-plan'), 'Operations must own handshake evidence surface');
ok(operations.includes('SNI decoy handshake evidence'), 'Operations must label handshake evidence');
ok(operations.includes('captures no packets'), 'Operations must state no capture authority');
ok(operations.includes('injects no traffic'), 'Operations must state no injection authority');
ok(operations.includes('raw-packet authority'), 'Operations must state raw authority remains external');
ok(operations.includes('fake_payload_bytes:517'), 'Operations must model canonical 517-byte decoy');
ok(operations.includes('server_ack_seen:serverConfirmed'), 'Operations must expose server confirmation evidence');
ok(operations.includes('rst_seen:rstSeen'), 'Operations must expose RST failure evidence');

ok(plan.includes('fake_payload_bytes must be in 1..'), 'handshake planner must bound payload size');
ok(plan.includes('SYN-ACK acknowledgement does not match client ISN+1'), 'planner must validate SYN-ACK');
ok(plan.includes('third ACK sequence does not match client ISN+1'), 'planner must validate third ACK sequence');
ok(plan.includes('third ACK acknowledgement does not match server ISN+1'), 'planner must validate third ACK acknowledgement');
ok(plan.includes('server acknowledgement advanced or differs from client ISN+1'), 'planner must require fake-ignore confirmation');
ok(plan.includes('failed-rst'), 'planner must fail closed on RST');
ok(plan.includes('PerformsNetworkIO:          false'), 'planner must declare no network I/O');
ok(plan.includes('RequiresRawPacketAuthority: true'), 'planner must not grant raw authority');

ok(tlsDecoy.includes('ClientHelloSize = 517'), 'canonical TLS decoy must be 517 bytes');
ok(tlsDecoy.includes('MaxSNIBytes     = 219'), 'canonical SNI bound missing');
ok(tlsDecoy.includes('io.ReadFull(rand.Reader'), 'canonical builder must use checked entropy reads');
ok(tlsDecoy.includes('0x00, 0x15'), 'canonical builder must emit TLS padding extension');
ok(tlsDecoy.includes('func ValidSNI'), 'canonical lower-layer SNI validator missing');
ok(diagnostic.includes('tlsdecoy.BuildPaddedClientHello'), 'diagnostic must use canonical lower-layer builder');
ok(tunnel.includes('tlsdecoy.BuildPaddedClientHello'), 'live tunnel must use canonical lower-layer builder');
ok(!tunnel.includes('16030100ba010000b60303'), 'legacy tunnel-only ClientHello template must be retired');
ok(tunnel.includes('out-of-window fake injection requires a fresh captured SYN sequence for the exact TCP four-tuple'), 'out-of-window injection must fail closed without SYN evidence');

ok(divert.includes('type connSeqKey struct'), 'sequence registry must use structured identity');
ok(divert.includes('SrcIP   string') && divert.includes('DstIP   string'), 'sequence registry key must include IP identity');
ok(divert.includes('SrcPort uint16') && divert.includes('DstPort uint16'), 'sequence registry key must include ports');
ok(divert.includes('connSeqTTL         = 30 * time.Second'), 'sequence evidence must expire');
ok(divert.includes('maxConnSeqRegistry = 4096'), 'sequence registry must be bounded');
ok(divert.includes('func TakeConnSeq'), 'sequence evidence must support atomic consume');
ok(divert.includes('delete(connSeqRegistry, key)'), 'consumption/clear must delete exact key');
ok(divert.includes('case 6:'), 'handshake parser must recognize base IPv6 TCP');

ok(rustSpoof.includes('FAKE_CLIENTHELLO_SIZE: usize = 517'), 'Rust decoy size must match canonical semantics');
ok(rustSpoof.includes('const TEMPLATE_HEX'), 'Rust decoy must use realistic template');
ok(rustSpoof.includes('compute_fake_seq_from_next'), 'Rust must support real-next-sequence decoy computation');
ok(rustSpoof.includes('build_fake_clienthello(decoy_domain'), 'Rust high-level builder must delegate to canonical Rust builder');
ok(!rustSpoof.includes('produces a compact\n    /// variable-length packet'), 'stale compact-builder contract must be gone');
ok(rustBypass.includes('compute_fake_seq_from_next'), 'WinDivert Rust path must use corrected sequence semantics');
ok(rustBypass.includes('fake_hello.len()'), 'Rust fake sequence must use actual decoy length');
ok(rustBypass.includes('is_valid_sni_hostname'), 'Rust bypass must reject malformed decoy SNI');

if (checks !== 54) throw new Error(`characterization denominator drifted: expected 54 checks, got ${checks}`);
console.log(`post-refactor-227 SNI convergence characterization passed: ${checks} checks`);
