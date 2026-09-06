import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const here=path.dirname(fileURLToPath(import.meta.url));
const root=path.resolve(here,'..');
const daemon=path.resolve(root,'../../apps/daemon');
const read=(...p)=>fs.readFileSync(path.join(...p),'utf8');
const operations=read(root,'src/pages/Operations.tsx');
const planners=read(root,'src/api/planners.ts');
const routes=read(daemon,'internal/adapters/api/routes_system.go');
const handlers=read(daemon,'internal/adapters/api/handlers_post_refactor_230_planners.go');
const bridge=read(daemon,'internal/analysis/diagnostics/tor_bridge_selection_plan.go');
const tor=read(daemon,'internal/analysis/diagnostics/tor_bootstrap_evidence_plan.go');
const censor=read(daemon,'internal/analysis/diagnostics/censorship_measurement_plan.go');
const dtls=read(daemon,'internal/analysis/diagnostics/dtls_session_policy_plan.go');
const phantom=read(daemon,'internal/analysis/diagnostics/phantom_pool_plan.go');
const flow=read(daemon,'internal/analysis/diagnostics/flow_filter_plan.go');
const mux=read(daemon,'internal/analysis/diagnostics/multiplex_policy_plan.go');
const cdn=read(daemon,'internal/analysis/diagnostics/cdn_candidates.go');
const jobs=read(daemon,'internal/workflows/jobs/runners.go');
const kcp=read(daemon,'internal/runtime/proxy/kcp_transport.go');
const gateway=read(daemon,'internal/analysis/diagnostics/gateway_composition_plan.go');
let checks=0; function ok(c,m){checks++;if(!c)throw new Error(m)}
for(const [ep,h] of [
 ['tor-bridge-selection-plan','PlanTorBridgeSelection'],['tor-bootstrap-evidence-plan','PlanTorBootstrapEvidence'],['censorship-measurement-plan','PlanCensorshipMeasurement'],['dtls-session-policy-plan','PlanDTLSSessionPolicy'],['phantom-pool-plan','PlanPhantomPool'],['flow-filter-plan','PlanFlowFilter'],
]){ok(routes.includes(`"/${ep}"`),`route ${ep}`);ok(handlers.includes(`func (s *Server) ${h}`),`handler ${h}`)}
for(const bad of ['http.Get(','http.Post(','net.Dial(','exec.Command(','os.WriteFile(','os.Remove(']) ok(!handlers.includes(bad),`hidden side effect ${bad}`)
for(const parser of ['parseTorBridgeSelectionPlan','parseTorBootstrapEvidencePlan','parseCensorshipMeasurementPlan','parseDTLSSessionPolicyPlan','parsePhantomPoolPlan','parseFlowFilterPlan']) ok(planners.includes(`export function ${parser}`),`parser ${parser}`)
for(const token of ['blocked-in-country','transport-mismatch','not-running','not-stable','selection operates only on caller-supplied bridge evidence','persists_client_key']) ok(bridge.toLowerCase().includes(token.toLowerCase()),`bridge ${token}`)
ok(bridge.includes('count = 3'), 'bridge adaptive upper response size'); ok(bridge.includes('count > 8'),'bridge explicit count cap');
for(const state of ['control-unavailable','authentication-required','network-disabled','bootstrapping','circuit-pending','socks-unavailable','ready']) ok(tor.includes(`"${state}"`),`Tor state ${state}`)
ok(tor.includes('SAFECOOKIE capability is represented as evidence only'),'SAFECOOKIE boundary'); ok(/ControlsTor:\s*false/.test(tor),'Tor planner control authority');
for(const kind of ['dns','tcp','tls','http','quic','stun']) ok(censor.includes(`"${kind}"`),`measurement kind ${kind}`)
for(const strength of ['strong','moderate','weak']) ok(censor.includes(`"${strength}"`),`measurement strength ${strength}`)
ok(censor.includes('control succeeded while experiment failed'),'differential anomaly'); ok(censor.includes('strong anomaly claims require a comparable control observation'),'control requirement');
for(const token of ['InsecureSkipVerify','InsecureSkipVerifyHello','InsecureHashes','KeyLogEnabled','ReplayProtectionWindow','FlightIntervalMillis','ConnectionIDLength','MaxPaddingBytes']) ok(dtls.includes(token),`DTLS field ${token}`)
ok(dtls.includes('DTLS MTU must be 576..9000'),'DTLS MTU bound'); ok(dtls.includes('replay protection window must be 1..4096'),'DTLS replay bound'); ok(dtls.includes('retransmit backoff cannot be disabled'),'DTLS backoff'); ok(dtls.includes('master-secret key logging is not admitted'),'DTLS keylog boundary');
for(const reason of ['non-public-address','liveness-not-confirmed-free','stale-liveness-evidence','transport-mismatch']) ok(phantom.includes(`"${reason}"`),`phantom reason ${reason}`)
ok(phantom.includes('netpolicy.IsPublicAddress'),'phantom public-address gate'); ok(/PerformsLivenessProbe:\s*false/.test(phantom),'phantom probe authority'); ok(/RegistersPhantom:\s*false/.test(phantom),'phantom registration authority');
for(const field of ['owner','protocol','network','destination','state','provider']) ok(flow.includes(`"${field}"`),`flow field ${field}`)
for(const op of ['eq','contains','prefix']) ok(flow.includes(`"${op}"`),`flow op ${op}`)
ok(flow.includes('body bytes, credentials, TLS secrets'),'flow body boundary'); ok(/ModifiesFlows\s+bool/.test(flow) && flow.includes('cannot modify, replay, intercept, or close'),'flow modify authority');
for(const token of ['KeepAliveIntervalMS','KeepAliveTimeoutMS','MaxFrameSize','MaxReceiveBuffer','MaxStreamBuffer']) ok(mux.includes(token),`mux ${token}`)
ok(mux.includes('version != 1 && version != 2'),'smux v1/v2'); ok(mux.includes('maxMuxFrameBytes           = 65535'),'smux frame cap'); ok(mux.includes('keep-alive timeout must be >= interval'),'smux keepalive ordering');
ok(cdn.includes('GeneratePublicCdnIPs'),'public CDN generator'); ok(cdn.includes('netpolicy.IsPublicAddress'),'public CDN netpolicy gate'); ok(jobs.includes('diagnostics.GeneratePublicCdnIPs'),'active scan uses public-only admission');
for(const token of ['smuxConfig.Version = 1','smuxConfig.MaxFrameSize = 32768','smuxConfig.MaxReceiveBuffer = 4 << 20','smuxConfig.MaxStreamBuffer = 64 << 10']) ok(kcp.includes(token),`KCP smux explicit ${token}`)
ok(gateway.includes('layered-fronted-egress'),'Hiddify-inspired topology preset'); ok(gateway.includes('built-in presets describe topology only'),'gateway preset authority boundary');
for(const option of ['torBridgeSelect','torBootstrap','censorshipEvidence','dtlsPolicy','phantomPool','flowFilter']) { ok(operations.includes(`value="${option}"`),`Operations option ${option}`); ok(operations.includes(`${option}:`),`Operations example ${option}`) }
for(const ep of ['/api/system/tor-bridge-selection-plan','/api/system/tor-bootstrap-evidence-plan','/api/system/censorship-measurement-plan','/api/system/dtls-session-policy-plan','/api/system/phantom-pool-plan','/api/system/flow-filter-plan']) ok(operations.includes(ep),`Operations endpoint ${ep}`)
ok(operations.includes('Tor bridge/bootstrap'),'Operations explanatory copy');
if (checks !== 118) throw new Error(`unexpected post-refactor-230 characterization count: ${checks}`);
console.log(`post-refactor-230 product/security convergence characterization passed: ${checks} checks`);
