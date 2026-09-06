import { useEffect, useMemo, useState, type ReactNode } from 'react';
import {
  Activity, Cable, CircleCheck, CircleX, Download, FileJson, Gauge, Play,
  RefreshCw, ServerCog, ShieldCheck, Stethoscope, Upload, Wifi,
} from 'lucide-react';
import { controlTransport } from '../api/ControlTransport';
import {
  errorMessage,
  parseDiagnosticPhases,
  parseDiagnosticStatus,
  parseDoctorReport,
  parsePortPreflight,
  parseRuntimeEngines,
  parseUpdateDiscovery,
  parseUpdatePlan,
  parseUpdateStage,
  type DiagnosticPhase,
  type DiagnosticStatus,
  type DoctorReport,
  type RuntimeEngineStatus,
  type UpdatePlan,
  type UpdateStageResult,
} from '../api/contracts';
import { parseTransportTrace, type TransportTraceSummary } from '../api/qlog';
import { parseInterruptedJobHistory, parseRecoveryInfo, parseRecoveryRequeueResult, type InterruptedJobSummary, type RecoveryInfo, type RecoveryRequeueResult } from '../api/recovery';
import { parseGatewayCompositionPlan, parseSNIDecoyHandshakePlan, parseWireGuardIndexTranslationPlan, type GatewayCompositionPlan, type SNIDecoyHandshakePlan, type WireGuardIndexTranslationPlan } from '../api/planners';

const terminalDiagnosticStates = new Set(['completed', 'failed', 'cancelled', 'canceled']);


type OnionProbeView = { url: string; onion_host: string; proxy: string; status_code: number; latency_ms: number; content_type?: string; sample_bytes: number; text_sample?: string; title?: string; description?: string; onion_links: number; same_service_links: number };
type VPNGateServerView = { hostname: string; ip: string; score: number; ping_ms: number; speed_bps: number; country: string; country_code: string; sessions: number; sstp_server: string; sstp_username: string; sstp_password: string };
type SNIStabilityView = { sni: string; target: string; attempts: number; successes: number; stability_pct: number; avg_latency_ms: number; score: number; outcomes: Record<string, number>; last_detail?: string };
type DevcontainerFileView = { path: string; content: string };
type DevcontainerBundleView = { files: DevcontainerFileView[]; notes: string[] };
type CircumventionCapabilityView = { id: string; name: string; category: string; integration: string; operator_surface?: string; description: string; tags: string[] };
type MeshRouteView = { destination: string; path: string[]; next_hop: string; hops: number; total_latency_ms: number; reliability_pct: number; cost: number };
type MeshRoutePlanView = { source: string; policy: string; routes: MeshRouteView[] };
type EndpointPoolRankView = { endpoint: string; score: number; quality: string; success_rate_pct: number; quota_pct?: number; quota_headroom?: number; quota_headroom_pct?: number; quota_safety_buffer?: number; quota_guarded: boolean; quota_reset_at?: string; latency_ms?: number; jitter_ms?: number; packet_loss_pct?: number; recent_failure: boolean; health_state: string; circuit_open: boolean; consecutive_failures: number; load_pct?: number; weight: number; eligible: boolean };
type EndpointPoolPlanView = { ranked: EndpointPoolRankView[]; dispatch_order: string[]; warm_pool: number; preferred_endpoint?: string; reused_previous_success: boolean; diversity_applied: boolean; selection_basis: string[] };
type PeerDiscoveryAcceptedView = { node_id: string; address: string; port: number; distance: string; trust_observed: boolean; trust_score?: number; shared_address_observed: boolean; shared_address_count?: number };
type PeerDiscoveryRejectedView = { node_id?: string; address?: string; port?: number; reason: string; detail: string };
type PeerDiscoveryPlanView = { local_node_id: string; accepted: PeerDiscoveryAcceptedView[]; rejected: PeerDiscoveryRejectedView[]; eligible_count: number; returned_count: number; rejected_count: number; blocked_prefix_count: number; max_results: number; selection_model: string; identity_model: string; safety_boundary: string };
type DNSResolverPlanView = { name: string; tier: string; mtu: number; loss_pct: number; rtt_ms: number; throughput_kbps?: number; effective_goodput_kbps: number };
type ReliabilityPlanView = { preset: string; mode: string; preferred_transport: string; observed_loss_pct?: number; loss_threshold_pct: number; super_loss_floor_pct: number; super_loss_ceil_pct: number; target_recovery_pct: number; data_shards: number; base_parity_shards: number; parity_shards: number; recovery_probability_pct: number; operating_mtu?: number; resolvers: DNSResolverPlanView[] };
type DNSTunnelPlanView = { suffix: string; encoding: string; udp_budget: number; query_encoded_chars: number; query_payload_bytes: number; response_payload_bytes: number; frame_payload_bytes: number; fragments: number; estimated_queries: number; reliability: ReliabilityPlanView };
type TransportTruthPlanView = { verdict: string; connected: boolean; handshake_ok: boolean; first_burst_delivery_pct: number; second_burst_delivery_pct: number; minimum_delivery_pct: number; advertised_country?: string; measured_egress_country?: string; location_verdict: string; evidence: string[]; safety_boundary: string };
type DNSTransportIntegrityPlanView = { verdict: string; preferred_transport: string; answer_sets_equal: boolean; poisoning_observed: boolean; udp_answers: string[]; tcp_answers: string[]; evidence: string[]; safety_boundary: string };
type TorBridgeProbeView = { raw_line: string; transport: string; target_host?: string; target_port?: number; latency_ms?: number; reachability: string; fronted: boolean; detail?: string };
type IperfDirectionView = { direction: string; bytes: number; seconds: number; bandwidth_mbps: number; retransmits?: number; jitter_ms?: number; lost_packets?: number; packets?: number; lost_percent?: number };
type IperfProbeView = { protocol: string; bytes_transferred: number; duration: number; bandwidth_mbps: number; directions: IperfDirectionView[]; cpu_host_percent?: number; cpu_remote_percent?: number; iperf_version?: string };
type STUNMappingProbeView = { primary_server: string; primary_mapped_address: string; response_origin?: string; other_address?: string; secondary_server?: string; secondary_mapped_address?: string; mapping_behavior: string; attempts: number; evidence: string[] };

function asRecord(value: unknown): Record<string, unknown> { if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error('expected object'); return value as Record<string, unknown>; }
function asString(value: unknown, key: string): string { if (typeof value !== 'string') throw new Error(`expected ${key}`); return value; }
function asNumber(value: unknown, key: string): number { if (typeof value !== 'number' || !Number.isFinite(value)) throw new Error(`expected ${key}`); return value; }
function parseOnionProbe(value: unknown): OnionProbeView { const r=asRecord(value); return { url:asString(r.url,'url'), onion_host:asString(r.onion_host,'onion_host'), proxy:asString(r.proxy,'proxy'), status_code:asNumber(r.status_code,'status_code'), latency_ms:asNumber(r.latency_ms,'latency_ms'), ...(typeof r.content_type==='string'?{content_type:r.content_type}:{}), sample_bytes:asNumber(r.sample_bytes,'sample_bytes'), ...(typeof r.text_sample==='string'?{text_sample:r.text_sample}:{}), ...(typeof r.title==='string'?{title:r.title}:{}), ...(typeof r.description==='string'?{description:r.description}:{}), onion_links:typeof r.onion_links==='number'?r.onion_links:0, same_service_links:typeof r.same_service_links==='number'?r.same_service_links:0 }; }
function parseVPNGate(value: unknown): VPNGateServerView[] { const r=asRecord(value); if(!Array.isArray(r.servers)) throw new Error('expected VPN Gate servers'); return r.servers.map((item)=>{const v=asRecord(item); return {hostname:asString(v.hostname,'hostname'),ip:asString(v.ip,'ip'),score:asNumber(v.score,'score'),ping_ms:asNumber(v.ping_ms,'ping_ms'),speed_bps:asNumber(v.speed_bps,'speed_bps'),country:asString(v.country,'country'),country_code:asString(v.country_code,'country_code'),sessions:asNumber(v.sessions,'sessions'),sstp_server:asString(v.sstp_server,'sstp_server'),sstp_username:asString(v.sstp_username,'sstp_username'),sstp_password:asString(v.sstp_password,'sstp_password')};}); }
function parseSNIStability(value: unknown): SNIStabilityView[] { const r=asRecord(value); if(!Array.isArray(r.results)) throw new Error('expected SNI results'); return r.results.map((item)=>{const v=asRecord(item); return {sni:asString(v.sni,'sni'),target:asString(v.target,'target'),attempts:asNumber(v.attempts,'attempts'),successes:asNumber(v.successes,'successes'),stability_pct:asNumber(v.stability_pct,'stability_pct'),avg_latency_ms:asNumber(v.avg_latency_ms,'avg_latency_ms'),score:asNumber(v.score,'score'),outcomes:(typeof v.outcomes==='object'&&v.outcomes!==null?v.outcomes:{}) as Record<string,number>,...(typeof v.last_detail==='string'?{last_detail:v.last_detail}:{})};}); }
function parseSNIDefaults(value: unknown): { candidates: string[]; target: string } { const r=asRecord(value); if(!Array.isArray(r.default_snis)) throw new Error('expected SNI default corpus'); return {candidates:r.default_snis.map((item)=>asString(item,'candidate')),target:asString(r.default_target,'default_target')}; }
function parseDevcontainerBundle(value: unknown): DevcontainerBundleView { const r=asRecord(value); if(!Array.isArray(r.files)||!Array.isArray(r.notes)) throw new Error('expected generated bundle'); return {files:r.files.map((item)=>{const v=asRecord(item); return {path:asString(v.path,'path'),content:asString(v.content,'content')};}),notes:r.notes.map((note)=>asString(note,'note'))}; }
function parseCircumventionCatalog(value: unknown): CircumventionCapabilityView[] { const r=asRecord(value); if(!Array.isArray(r.items)) throw new Error('expected circumvention catalog'); return r.items.map((item)=>{const v=asRecord(item); return {id:asString(v.id,'id'),name:asString(v.name,'name'),category:asString(v.category,'category'),...(typeof v.operator_surface==='string'?{operator_surface:v.operator_surface}:{}),integration:asString(v.integration,'integration'),description:asString(v.description,'description'),tags:Array.isArray(v.tags)?v.tags.map((tag)=>asString(tag,'tag')):[]};}); }
function parseMeshRoutePlan(value: unknown): MeshRoutePlanView { const r=asRecord(value); if(!Array.isArray(r.routes)) throw new Error('expected mesh routes'); return {source:asString(r.source,'source'),policy:asString(r.policy,'policy'),routes:r.routes.map((item)=>{const v=asRecord(item); return {destination:asString(v.destination,'destination'),path:Array.isArray(v.path)?v.path.map((part)=>asString(part,'path')):[],next_hop:asString(v.next_hop,'next_hop'),hops:asNumber(v.hops,'hops'),total_latency_ms:asNumber(v.total_latency_ms,'total_latency_ms'),reliability_pct:asNumber(v.reliability_pct,'reliability_pct'),cost:asNumber(v.cost,'cost')};})}; }
function parseEndpointPoolPlan(value: unknown): EndpointPoolPlanView { const r=asRecord(value); if(!Array.isArray(r.ranked)||!Array.isArray(r.dispatch_order)) throw new Error('expected endpoint pool plan'); return {ranked:r.ranked.map((item)=>{const v=asRecord(item); return {endpoint:asString(v.endpoint,'endpoint'),score:asNumber(v.score,'score'),quality:asString(v.quality,'quality'),success_rate_pct:asNumber(v.success_rate_pct,'success_rate_pct'),...(typeof v.quota_pct==='number'?{quota_pct:v.quota_pct}:{}),...(typeof v.quota_headroom==='number'?{quota_headroom:v.quota_headroom}:{}),...(typeof v.quota_headroom_pct==='number'?{quota_headroom_pct:v.quota_headroom_pct}:{}),...(typeof v.quota_safety_buffer==='number'?{quota_safety_buffer:v.quota_safety_buffer}:{}),quota_guarded:v.quota_guarded===true,...(typeof v.quota_reset_at==='string'?{quota_reset_at:v.quota_reset_at}:{}),...(typeof v.latency_ms==='number'?{latency_ms:v.latency_ms}:{}),...(typeof v.jitter_ms==='number'?{jitter_ms:v.jitter_ms}:{}),...(typeof v.packet_loss_pct==='number'?{packet_loss_pct:v.packet_loss_pct}:{}),recent_failure:v.recent_failure===true,health_state:typeof v.health_state==='string'?v.health_state:'unknown',circuit_open:v.circuit_open===true,consecutive_failures:typeof v.consecutive_failures==='number'?v.consecutive_failures:0,...(typeof v.load_pct==='number'?{load_pct:v.load_pct}:{}),weight:typeof v.weight==='number'?v.weight:1,eligible:v.eligible===true};}),dispatch_order:r.dispatch_order.map((item)=>asString(item,'dispatch_order')),warm_pool:asNumber(r.warm_pool,'warm_pool'),...(typeof r.preferred_endpoint==='string'?{preferred_endpoint:r.preferred_endpoint}:{}),reused_previous_success:r.reused_previous_success===true,diversity_applied:r.diversity_applied===true,selection_basis:Array.isArray(r.selection_basis)?r.selection_basis.map((item)=>asString(item,'selection_basis')):[]}; }
function parsePeerDiscoveryPlan(value: unknown): PeerDiscoveryPlanView {
  const r = asRecord(value);
  if (!Array.isArray(r.accepted) || !Array.isArray(r.rejected)) throw new Error('expected peer discovery plan');
  return {
    local_node_id: asString(r.local_node_id, 'local_node_id'),
    accepted: r.accepted.map((item) => {
      const v = asRecord(item);
      return {
        node_id: asString(v.node_id, 'node_id'),
        address: asString(v.address, 'address'),
        port: asNumber(v.port, 'port'),
        distance: asString(v.distance, 'distance'),
        trust_observed: Boolean(v.trust_observed),
        ...(typeof v.trust_score === 'number' ? { trust_score: v.trust_score } : {}),
        shared_address_observed: Boolean(v.shared_address_observed),
        ...(typeof v.shared_address_count === 'number' ? { shared_address_count: v.shared_address_count } : {}),
      };
    }),
    rejected: r.rejected.map((item) => {
      const v = asRecord(item);
      return {
        ...(typeof v.node_id === 'string' ? { node_id: v.node_id } : {}),
        ...(typeof v.address === 'string' ? { address: v.address } : {}),
        ...(typeof v.port === 'number' ? { port: v.port } : {}),
        reason: asString(v.reason, 'reason'),
        detail: asString(v.detail, 'detail'),
      };
    }),
    eligible_count: asNumber(r.eligible_count, 'eligible_count'),
    returned_count: asNumber(r.returned_count, 'returned_count'),
    rejected_count: asNumber(r.rejected_count, 'rejected_count'),
    blocked_prefix_count: asNumber(r.blocked_prefix_count, 'blocked_prefix_count'),
    max_results: asNumber(r.max_results, 'max_results'),
    selection_model: asString(r.selection_model, 'selection_model'),
    identity_model: asString(r.identity_model, 'identity_model'),
    safety_boundary: asString(r.safety_boundary, 'safety_boundary'),
  };
}
function parseDNSTunnelPlan(value: unknown): DNSTunnelPlanView { const r=asRecord(value); const reliability=asRecord(r.reliability); const resolverRows=Array.isArray(reliability.resolvers)?reliability.resolvers:[]; return {suffix:asString(r.suffix,'suffix'),encoding:asString(r.encoding,'encoding'),udp_budget:asNumber(r.udp_budget,'udp_budget'),query_encoded_chars:asNumber(r.query_encoded_chars,'query_encoded_chars'),query_payload_bytes:asNumber(r.query_payload_bytes,'query_payload_bytes'),response_payload_bytes:asNumber(r.response_payload_bytes,'response_payload_bytes'),frame_payload_bytes:asNumber(r.frame_payload_bytes,'frame_payload_bytes'),fragments:asNumber(r.fragments,'fragments'),estimated_queries:asNumber(r.estimated_queries,'estimated_queries'),reliability:{preset:asString(reliability.preset,'preset'),mode:asString(reliability.mode,'mode'),preferred_transport:asString(reliability.preferred_transport,'preferred_transport'),...(typeof reliability.observed_loss_pct==='number'?{observed_loss_pct:reliability.observed_loss_pct}:{}),loss_threshold_pct:asNumber(reliability.loss_threshold_pct,'loss_threshold_pct'),super_loss_floor_pct:asNumber(reliability.super_loss_floor_pct,'super_loss_floor_pct'),super_loss_ceil_pct:asNumber(reliability.super_loss_ceil_pct,'super_loss_ceil_pct'),target_recovery_pct:asNumber(reliability.target_recovery_pct,'target_recovery_pct'),data_shards:asNumber(reliability.data_shards,'data_shards'),base_parity_shards:asNumber(reliability.base_parity_shards,'base_parity_shards'),parity_shards:asNumber(reliability.parity_shards,'parity_shards'),recovery_probability_pct:asNumber(reliability.recovery_probability_pct,'recovery_probability_pct'),...(typeof reliability.operating_mtu==='number'?{operating_mtu:reliability.operating_mtu}:{}),resolvers:resolverRows.map((item)=>{const row=asRecord(item);return {name:asString(row.name,'resolver.name'),tier:asString(row.tier,'resolver.tier'),mtu:asNumber(row.mtu,'resolver.mtu'),loss_pct:asNumber(row.loss_pct,'resolver.loss_pct'),rtt_ms:asNumber(row.rtt_ms,'resolver.rtt_ms'),...(typeof row.throughput_kbps==='number'?{throughput_kbps:row.throughput_kbps}:{}),effective_goodput_kbps:asNumber(row.effective_goodput_kbps,'resolver.effective_goodput_kbps')};})}}; }
function parseTransportTruthPlan(value: unknown): TransportTruthPlanView { const r=asRecord(value); return {verdict:asString(r.verdict,'verdict'),connected:r.connected===true,handshake_ok:r.handshake_ok===true,first_burst_delivery_pct:asNumber(r.first_burst_delivery_pct,'first_burst_delivery_pct'),second_burst_delivery_pct:asNumber(r.second_burst_delivery_pct,'second_burst_delivery_pct'),minimum_delivery_pct:asNumber(r.minimum_delivery_pct,'minimum_delivery_pct'),...(typeof r.advertised_country==='string'?{advertised_country:r.advertised_country}:{}),...(typeof r.measured_egress_country==='string'?{measured_egress_country:r.measured_egress_country}:{}),location_verdict:asString(r.location_verdict,'location_verdict'),evidence:Array.isArray(r.evidence)?r.evidence.map((item)=>asString(item,'evidence')):[],safety_boundary:asString(r.safety_boundary,'safety_boundary')}; }
function parseDNSTransportIntegrityPlan(value: unknown): DNSTransportIntegrityPlanView { const r=asRecord(value); return {verdict:asString(r.verdict,'verdict'),preferred_transport:asString(r.preferred_transport,'preferred_transport'),answer_sets_equal:r.answer_sets_equal===true,poisoning_observed:r.poisoning_observed===true,udp_answers:Array.isArray(r.udp_answers)?r.udp_answers.map((item)=>asString(item,'udp_answers')):[],tcp_answers:Array.isArray(r.tcp_answers)?r.tcp_answers.map((item)=>asString(item,'tcp_answers')):[],evidence:Array.isArray(r.evidence)?r.evidence.map((item)=>asString(item,'evidence')):[],safety_boundary:asString(r.safety_boundary,'safety_boundary')}; }
function parseTorBridgeProbe(value: unknown): TorBridgeProbeView[] { const r=asRecord(value); if(!Array.isArray(r.results)) throw new Error('expected bridge probe results'); return r.results.map((item)=>{const v=asRecord(item); return {raw_line:asString(v.raw_line,'raw_line'),transport:asString(v.transport,'transport'),...(typeof v.target_host==='string'?{target_host:v.target_host}:{}),...(typeof v.target_port==='number'?{target_port:v.target_port}:{}),...(typeof v.latency_ms==='number'?{latency_ms:v.latency_ms}:{}),reachability:asString(v.reachability,'reachability'),fronted:v.fronted===true,...(typeof v.detail==='string'?{detail:v.detail}:{})};}); }
function parseIperfProbe(value: unknown): IperfProbeView { const r=asRecord(value); if(!Array.isArray(r.directions)) throw new Error('expected iperf directions'); return {protocol:asString(r.protocol,'protocol'),bytes_transferred:asNumber(r.bytes_transferred,'bytes_transferred'),duration:asNumber(r.duration,'duration'),bandwidth_mbps:asNumber(r.bandwidth_mbps,'bandwidth_mbps'),directions:r.directions.map((item)=>{const v=asRecord(item); return {direction:asString(v.direction,'direction'),bytes:asNumber(v.bytes,'bytes'),seconds:asNumber(v.seconds,'seconds'),bandwidth_mbps:asNumber(v.bandwidth_mbps,'bandwidth_mbps'),...(typeof v.retransmits==='number'?{retransmits:v.retransmits}:{}),...(typeof v.jitter_ms==='number'?{jitter_ms:v.jitter_ms}:{}),...(typeof v.lost_packets==='number'?{lost_packets:v.lost_packets}:{}),...(typeof v.packets==='number'?{packets:v.packets}:{}),...(typeof v.lost_percent==='number'?{lost_percent:v.lost_percent}:{})};}),...(typeof r.cpu_host_percent==='number'?{cpu_host_percent:r.cpu_host_percent}:{}),...(typeof r.cpu_remote_percent==='number'?{cpu_remote_percent:r.cpu_remote_percent}:{}),...(typeof r.iperf_version==='string'?{iperf_version:r.iperf_version}:{})}; }
function parseSTUNMappingProbe(value: unknown): STUNMappingProbeView { const r=asRecord(value); if(!Array.isArray(r.evidence)) throw new Error('expected STUN evidence'); return {primary_server:asString(r.primary_server,'primary_server'),primary_mapped_address:asString(r.primary_mapped_address,'primary_mapped_address'),...(typeof r.response_origin==='string'?{response_origin:r.response_origin}:{}),...(typeof r.other_address==='string'?{other_address:r.other_address}:{}),...(typeof r.secondary_server==='string'?{secondary_server:r.secondary_server}:{}),...(typeof r.secondary_mapped_address==='string'?{secondary_mapped_address:r.secondary_mapped_address}:{}),mapping_behavior:asString(r.mapping_behavior,'mapping_behavior'),attempts:asNumber(r.attempts,'attempts'),evidence:r.evidence.map((item)=>asString(item,'evidence'))}; }

type ConvergencePlannerKind = 'presets' | 'kcp' | 'doh' | 'l7' | 'traffic' | 'routing' | 'sniPath' | 'sniGateway' | 'relay' | 'artifact' | 'dnsPolicy' | 'muxPolicy' | 'routingArtifact' | 'tlsFingerprint' | 'incident' | 'queue' | 'workflow' | 'wireguard' | 'torBridgeSelect' | 'torBootstrap' | 'censorshipEvidence' | 'dtlsPolicy' | 'phantomPool' | 'flowFilter' | 'ptLifecycle' | 'circumventionFallback' | 'naivePolicy' | 'stegoScheme' | 'multipathTransport' | 'dnsResolverCampaign' | 'outlineAccess' | 'dnsTunnelDeployment' | 'dnsRefiner' | 'httpsUpgradeAudit' | 'torExitScan' | 'mobileTorLifecycle' | 'securityPosture' | 'trafficShaper' | 'endpointLocation' | 'dnsBlocklistAudit' | 'apiTraceSchema' | 'torDescriptorEvidence' | 'processProxyRules' | 'evidenceChain' | 'dnscryptResolver' | 'scanLoadPolicy' | 'mobileConnectionReadiness' | 'configFallback' | 'dnsInterceptSafety' | 'torConsensusEvidence' | 'dnscryptTopology' | 'evidenceReceiptTopology' | 'dnsFilterPreset' | 'networkEvidenceBundle' | 'clientHelloEvidence' | 'encryptedDNSPolicy' | 'torLabRelay' | 'proxyChainSafety' | 'transportReplay' | 'secretRefreshPolicy' | 'realityAdmission' | 'serviceRecoveryPolicy' | 'networkTrustBundle';
const convergencePlannerExamples: Record<ConvergencePlannerKind, string> = {
  presets: '{}',
  kcp: '{"intent":"loss-recovery","observed_loss_percent":8,"overrides":{"ack_no_delay":true}}',
  doh: '{"max_fallbacks":3,"candidates":[{"id":"primary","url":"https://dns.example/dns-query","bootstrap_ips":["1.1.1.1"],"priority":10,"rtt_ms":30,"canary_status":"pass"}]}',
  l7: '{"signatures":[{"name":"tls-record","expression":"^\\\\x16\\\\x03"}]}',
  traffic: '{"version":"1","entry":"start","states":[{"id":"start","actions":[{"kind":"delay","delay_ms":20}],"transitions":[{"to":"done","probability":1}]},{"id":"done","terminal":true}]}',
  routing: '{"files":[{"name":"security","rules":[{"action":"block","value":"bad.example"}]},{"name":"direct","rules":[{"action":"direct","value":"private"}]}]}',
  sniPath: '{"active_pool_size":1,"candidates":[{"ip":"203.0.113.3","sni":"edge.example","tcp_connected":true,"tls_verified":true,"first_response":true,"successes":8,"latency_ms":30,"path_mtu":1500}]}',
  sniGateway: '{"public_ip":"203.0.113.8","require_public_ip":true,"dns_port":53,"tls_router_port":443,"http_redirect_port":80,"dns_configured":true,"tls_router_configured":true,"listener_endpoint":"0.0.0.0:40443","upstream_endpoint":"203.0.113.20:443"}',
  relay: '{"transport":"starttls","trust_mode":"strict","starttls_detection":"protocol-aware"}',
  artifact: '{"id":"bundle-v1","kind":"download","filename":"bundle.zip","claimed_format":"zip","source_url":"https://example.test/bundle.zip","expected_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","content_base64":"UEsDBA=="}',
  dnsPolicy: '{"primary_transport":"doh","require_secure_transport":true,"transports":[{"id":"doh","kind":"https","server":"https://dns.example/dns-query"}]}',
  muxPolicy: '{"protocol":"smux","version":1,"max_connections":4,"max_streams_per_connection":32,"padding":true,"max_padding_bytes":768}',
  routingArtifact: '{"artifacts":[{"id":"geo","kind":"geosite","format":"srs","source_url":"https://example.test/geosite.srs","expected_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","actual_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bytes":1234,"source_version":"v1"}]}',
  tlsFingerprint: '{"candidates":["chrome","firefox","randomized"],"known_good":"firefox","reuse_known_good":true,"max_trials":2,"required_alpn":["h2","http/1.1"]}',
  incident: '{"previous_status":"up","current_status":"down","notification_grace_seconds":60,"write_cooldown_seconds":180}',
  queue: '{"capacity":256,"current_depth":240,"incoming_items":32,"strategy":"drop-oldest","max_batch_items":64,"max_batch_bytes":262144,"average_item_bytes":1200}',
  workflow: '{"actions":[{"id":"edge","kind":"endpoint","target":"tcp://edge.example:443"},{"id":"remote","kind":"remote","target":"remote.example:443","depends_on":["edge"]},{"id":"trigger","kind":"child","phase":"trigger","depends_on":["remote"]}]}',
  wireguard: '{"peers":[{"id":"default","public_key":"peer-a","allowed_ips":["0.0.0.0/0","::/0"]},{"id":"corp","public_key":"peer-b","allowed_ips":["10.0.0.0/8"],"persistent_keepalive_seconds":25}],"under_load":true,"cookie_gate_enabled":true}',
  torBridgeSelect: '{"country":"ir","transport":"obfs4","require_stable":true,"selection_key":"local-cohort","candidates":[{"id":"bridge-a","transport":"obfs4","address":"1.1.1.1:443","address_family":"4","running":true,"stable":true}]}',
  torBootstrap: '{"control_connected":true,"authenticated":true,"safe_cookie_available":true,"network_enabled":true,"bootstrap_progress":100,"circuit_established":true,"socks_listeners":1,"stream_isolation":true}',
  censorshipEvidence: '{"observations":[{"id":"dns-a","kind":"dns","subject":"example.test","experiment_observed":true,"experiment_success":false,"control_observed":true,"control_success":true}]}',
  dtlsPolicy: '{"role":"server","identity_mode":"certificate","certificate_configured":true,"mtu":1200,"replay_protection_window":64,"flight_interval_ms":1000,"extended_master_secret":"require","supported_protocols":["h3"]}',
  phantomPool: '{"now_unix":1900000000,"max_age_seconds":300,"selection_key":"local-cohort","candidates":[{"id":"candidate-a","address":"1.1.1.1","transport":"min","liveness":"not-live","checked_at_unix":1899999900,"weight":2}]}',
  flowFilter: '{"match":"all","clauses":[{"field":"protocol","operator":"eq","value":"tls"},{"field":"destination","operator":"contains","value":"example.com"}]}',
  ptLifecycle: '{"transport":"snowflake","platform":"android","observed_state":"listening","state_dir_configured":true,"state_dir_writable":true,"local_port":12000,"max_peers":2}',
  circumventionFallback: '{"enabled":true,"current_transport":"direct","bootstrap_progress":45,"seconds_since_progress":45,"timeout_seconds":30,"custom_bridges_available":false}',
  naivePolicy: '{"platform":"linux","listeners":[{"scheme":"socks","port":1080}],"proxy_chain":[{"scheme":"https","has_auth":true}],"padding":"variant1","fast_open_requested":true}',
  stegoScheme: '{"direction":"client","payload_bytes":220,"selection_key":"policy-lab","candidates":[{"name":"uri-transmit","enabled":true,"usable":true,"capacity_bytes":500},{"name":"cookie-transmit","enabled":true,"usable":true,"capacity_bytes":900},{"name":"json-post","enabled":true,"usable":true,"capacity_bytes":1200}]}',
  multipathTransport: '{"algorithm":"round-robin","queue_packets":32,"overflow_policy":"backpressure","preview_packets":8,"paths":[{"id":"obfs4-a","transport":"obfs4","healthy":true,"ready":true,"latency_ms":45},{"id":"webtunnel-b","transport":"webtunnel","healthy":true,"ready":true,"latency_ms":70}]}',
  dnsResolverCampaign: '{"mode":"dns","platform":"linux","observed_state":"running","requested_action":"pause","domain":"example.com","query_type":"A","candidate_count":1024,"concurrency":100,"timeout_ms":2000,"random_subdomain":true}',
  outlineAccess: '{"candidate":"ssconf://provider.example/key"}',
  dnsTunnelDeployment: '{"tunnel_subdomain":"t.example.com","nameserver_host":"tns.example.net","server_ipv4":"1.2.3.4","mtu":1232,"tunnel_mode":"socks"}',

  dnsRefiner: '{"allowed_schemes":["dns","slipnet","dnstt"],"output_order":"ASC","observations":[{"source_key":"resolver-a","scheme":"dns","name_server":"dns.example","address":"1.1.1.1"},{"source_key":"tunnel-b","scheme":"dnstt","name_server":"ns.example","address":"203.0.113.10:53","has_public_key":true}]}',
  httpsUpgradeAudit: '{"rules":[{"name":"example-upgrade","targets":["example.com","*.cdn.example.com"]},{"name":"duplicate-demo","targets":["example.com"],"disabled":true}]}',
  torExitScan: '{"candidate_exits":120,"requested_exits":20,"country":"DE","build_delay_ms":100,"parallelism":4,"per_probe_timeout_ms":10000,"modules":["rtt","dnspoison"]}',
  mobileTorLifecycle: '{"observed_state":"ready","app_state":"background","requested_action":"none","network_available":true,"on_demand":true,"bridge_configured":true}',
  securityPosture: '{"checks":[{"id":"disk-encryption","category":"device","status":"pass","severity":"critical"},{"id":"dns-integrity","category":"network","status":"unknown","severity":"high"},{"id":"os-updates","category":"os","status":"fail","severity":"medium"}]}',
  trafficShaper: '{"rate_bytes_per_second":1048576,"burst_bytes":262144,"queue_bytes":1048576,"padding_min_bytes":16,"padding_max_bytes":256,"overhead_percent":10}',
  endpointLocation: '{"minimum_confidence":0.8,"observations":[{"endpoint_id":"edge-a","advertised_country":"SE","measured_country":"SE","source":"caller","confidence":0.95},{"endpoint_id":"edge-b","advertised_country":"US","measured_country":"DE","source":"caller","confidence":0.9}]}',
  dnsBlocklistAudit: '{"lists":[{"name":"multi","category":"security","format":"domains","entries":120000,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}',
  apiTraceSchema: '{"observations":[{"method":"GET","path":"/users/123?token=redacted","status":200,"contentType":"application/json","query_keys":["page"],"header_keys":["Accept","Authorization"],"body_fields":["name"]},{"method":"GET","path":"/users/456","status":404,"contentType":"application/json","header_keys":["Cookie"]}]}',
  torDescriptorEvidence: '{"relays":[{"fingerprint":"0123456789abcdef0123456789abcdef01234567","country":"SE","flags":["Running","Valid","Exit"],"advertisedBandwidthKBPS":1000}]}',
  processProxyRules: '{"proxy_process":"proxy.exe","rules":[{"process":"browser.exe","protocol":"both","target":"*","action":"proxy","portStart":1,"portEnd":65535,"priority":10},{"process":"browser.exe","protocol":"tcp","target":"203.0.113.10","action":"direct","portStart":443,"portEnd":443,"priority":20}]}',
  evidenceChain: '{"artifacts":[{"id":"capture","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","signatureStatus":"pass","timestampStatus":"unknown"}]}',
  dnscryptResolver: '{"requireDNSSEC":true,"requireNoLog":true,"maxLatencyMS":500,"resolvers":[{"name":"resolver-a","protocol":"dnscrypt","dnssec":true,"noLog":true,"noFilter":true,"supportsRelay":true,"latencyMS":45}]}',
  scanLoadPolicy: '{"current_concurrency":100,"min_concurrency":3,"max_concurrency":400,"gateway_rtt_ms":24,"baseline_rtt_ms":20,"timeout_rate_pct":65,"sample_count":120,"candidate_count":1000,"requested_workers":32}',
  mobileConnectionReadiness: '{"phase":"connected","completed":100,"total":100,"valid":3,"rejected":1,"active_resolvers":["1.1.1.1"],"standby_resolvers":["9.9.9.9"],"valid_resolvers":["1.1.1.1","9.9.9.9"],"runtime_healthy":true,"warmup_completed":true}',
  configFallback: '{"candidates":[{"id":"ws","kind":"websocket","status":"unsupported"},{"id":"ss","kind":"shadowsocks","status":"supported"}]}',
  dnsInterceptSafety: '{"destination_port":53,"destination_is_local_resolver":true,"transport":"udp","base_session_exists":false,"packet_bytes":96}',
  torConsensusEvidence: '{"now_unix":1900000000,"valid_after_unix":1899999900,"fresh_until_unix":1900000300,"relays":[{"fingerprint":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","ipv4":"1.2.3.4","flags":["Running","Valid","Exit"],"family":["$BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"],"bandwidth_weight":100,"exit_allowed_ports":[80,443]},{"fingerprint":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","ipv4":"1.2.8.9","flags":["Running","Valid"],"family":["$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],"bandwidth_weight":80}]}',
  dnscryptTopology: '{"max_source_age_hours":168,"resolvers":[{"name":"resolver-a","protocol":"dnscrypt","source_signed":true,"source_age_hours":6,"requires_relay":true}],"relays":[{"name":"relay-a","protocols":["dnscrypt"],"source_signed":true,"source_age_hours":4,"available":true}]}',
  evidenceReceiptTopology: '{"artifacts":[{"id":"root","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","signature_status":"pass","timestamp_status":"pass","metadata_consent":true},{"id":"derived","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","parent_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","signature_status":"pass","timestamp_status":"unknown","metadata_consent":true}]}',
  dnsFilterPreset: '{"intent":"anti-bypass","lists":[{"name":"doh-vpn-proxy-bypass","category":"doh","format":"adblock","entries":12000},{"name":"exceptions","category":"allow","format":"hosts","entries":100,"allow_exceptions":true}]}',
  networkEvidenceBundle: '{"scan_load":{"current_concurrency":10,"min_concurrency":3,"max_concurrency":50,"samples":40,"gateway_rtt_ms":15,"baseline_gateway_rtt_ms":10},"dns_filter":{"intent":"security","lists":[{"name":"threat-intelligence","category":"security","format":"adblock","entries":5000}]}}',
  clientHelloEvidence: '{"transport":"quic","server_name":"example.com","quic_version":1,"extension_ids":[4865,2570],"supported_groups":[29,6682],"fragments":[{"offset":0,"length":120},{"offset":120,"length":80}],"captured_bytes":200}',
  encryptedDNSPolicy: '{"transport":"odoh","packet_bytes":317,"observed_ttl":120,"min_ttl":30,"max_ttl":3600,"error_ttl":60,"padding_block_bytes":128,"existing_ecs":"203.0.113.0/24","requested_ecs":"198.51.100.0/24","cache_enabled":true}',
  torLabRelay: '{"minimum_consensus_relays":2,"allowed_failures":1,"verification_rounds":3,"nodes":[{"id":"auth-1","role":"authority","running":true,"bootstrap_percent":100,"bandwidth_kbps":1000,"metrics_enabled":true},{"id":"exit-1","role":"exit","running":true,"bootstrap_percent":100,"bandwidth_kbps":800,"exit_allowed_ports":[80,443]}]}',
  proxyChainSafety: '{"mode":"dynamic","chain_length":2,"destination_kind":"hostname","remote_dns":true,"hops":[{"id":"socks-a","protocol":"socks5","reachable":true,"supports_ipv6":true},{"id":"http-b","protocol":"http","reachable":false,"supports_ipv6":false},{"id":"socks-c","protocol":"socks5","reachable":true,"supports_ipv6":true}]}',
  transportReplay: '{"window_capacity":1024,"max_age_seconds":600,"nat_idle_seconds":120,"queue_capacity":4096,"observations":[{"key_id":"tenant-a","salt_hex":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","age_seconds":10},{"key_id":"tenant-a","salt_hex":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","age_seconds":12}]}',
  secretRefreshPolicy: '{"name":"relay-token","declared":true,"allow_lookup":false,"persist_cache":false,"cached_version":4,"remote_version":5,"cache_age_seconds":60,"max_cache_age_seconds":300,"poll_interval_seconds":30,"poll_jitter_pct":10,"watchers":2}',
  realityAdmission: '{"server_names":["www.example.com"],"short_ids":["","a1b2c3d4"],"max_time_diff_seconds":60,"limit_fallback_upload_mbps":20,"limit_fallback_download_mbps":100,"ech_enabled":false}',
  serviceRecoveryPolicy: '{"service":"luminet-daemon","operation":"update","backup_exists":true,"config_validated":true,"health_before":"healthy","health_after":"healthy","rollback_available":true,"log_tail_lines":100}',
  networkTrustBundle: '{"client_hello":{"transport":"tls","server_name":"example.com","extension_ids":[0,2570]},"encrypted_dns":{"transport":"dnscrypt","packet_bytes":256,"observed_ttl":300,"min_ttl":30,"max_ttl":3600,"error_ttl":60,"cache_enabled":true},"reality":{"server_names":["example.com"],"short_ids":["a1b2"]}}',
};
function parseConvergencePlannerResult(value: unknown): Record<string, unknown> { return asRecord(value); }

export function Operations() {
  const [doctor, setDoctor] = useState<DoctorReport | null>(null);
  const [phases, setPhases] = useState<DiagnosticPhase[]>([]);
  const [engines, setEngines] = useState<RuntimeEngineStatus[]>([]);
  const [loadingOverview, setLoadingOverview] = useState(false);
  const [overviewError, setOverviewError] = useState<string | null>(null);

  const [diagnosticTarget, setDiagnosticTarget] = useState('1.1.1.1');
  const [diagnosticType, setDiagnosticType] = useState('connectivity');
  const [diagnosticID, setDiagnosticID] = useState<string | null>(null);
  const [lastDiagnosticID, setLastDiagnosticID] = useState<string | null>(null);
  const [diagnosticStatus, setDiagnosticStatus] = useState<DiagnosticStatus | null>(null);
  const [diagnosticBusy, setDiagnosticBusy] = useState(false);

  const [preflightHost, setPreflightHost] = useState('127.0.0.1');
  const [preflightPort, setPreflightPort] = useState(1080);
  const [preflightResult, setPreflightResult] = useState<ReturnType<typeof parsePortPreflight> | null>(null);
  const [preflightBusy, setPreflightBusy] = useState(false);

  const [sstpServer, setSSTPServer] = useState('');
  const [sstpUsername, setSSTPUsername] = useState('');
  const [sstpPassword, setSSTPPassword] = useState('');
  const [sstpProxy, setSSTPProxy] = useState('');
  const [sstpCACert, setSSTPCACert] = useState('');
  const [sstpCertWarn, setSSTPCertWarn] = useState(false);
  const [sstpPPPOptions, setSSTPPPPOptions] = useState('');
  const [ikeServer, setIKEServer] = useState('');
  const [ikeIdentity, setIKEIdentity] = useState('');
  const [ikeRemoteIdentity, setIKERemoteIdentity] = useState('');
  const [ikeCertificate, setIKECertificate] = useState('');
  const [ikePrivateKey, setIKEPrivateKey] = useState('');
  const [ikeLocalTS, setIKELocalTS] = useState('');
  const [ikeRemoteTS, setIKERemoteTS] = useState('');
  const [ikeProposals, setIKEProposals] = useState('');
  const [espProposals, setESPProposals] = useState('');
  const [engineBusy, setEngineBusy] = useState<string | null>(null);
  const [torOnionURL, setTorOnionURL] = useState('');
  const [torProxyPool, setTorProxyPool] = useState('');
  const [torProbe, setTorProbe] = useState<OnionProbeView | null>(null);
  const [torBusy, setTorBusy] = useState<'rotate' | 'probe' | null>(null);
  const [torBridgeInput, setTorBridgeInput] = useState('');
  const [torBridgeWorkers, setTorBridgeWorkers] = useState(8);
  const [torBridgeTimeoutMs, setTorBridgeTimeoutMs] = useState(4000);
  const [torBridgeResults, setTorBridgeResults] = useState<TorBridgeProbeView[]>([]);
  const [torBridgeBusy, setTorBridgeBusy] = useState(false);
  const [iperfAddress, setIperfAddress] = useState('');
  const [iperfProtocol, setIperfProtocol] = useState<'tcp' | 'udp'>('tcp');
  const [iperfDurationSecs, setIperfDurationSecs] = useState(5);
  const [iperfParallel, setIperfParallel] = useState(1);
  const [iperfUDPBitrateMbps, setIperfUDPBitrateMbps] = useState(10);
  const [iperfReverse, setIperfReverse] = useState(false);
  const [iperfAuthorization, setIperfAuthorization] = useState(false);
  const [iperfResult, setIperfResult] = useState<IperfProbeView | null>(null);
  const [iperfBusy, setIperfBusy] = useState(false);
  const [stunPrimary, setSTUNPrimary] = useState('');
  const [stunSecondary, setSTUNSecondary] = useState('');
  const [stunResult, setSTUNResult] = useState<STUNMappingProbeView | null>(null);
  const [stunBusy, setSTUNBusy] = useState(false);
  const [vpnGateCountry, setVPNGateCountry] = useState('');
  const [vpnGateServers, setVPNGateServers] = useState<VPNGateServerView[]>([]);
  const [vpnGateBusy, setVPNGateBusy] = useState(false);
  const [sniRankTarget, setSNIRankTarget] = useState('104.18.4.130:443');
  const [sniRankCandidates, setSNIRankCandidates] = useState('www.cloudflare.com\nwww.microsoft.com\nwww.apple.com');
  const [sniRankRuns, setSNIRankRuns] = useState(3);
  const [sniRankResults, setSNIRankResults] = useState<SNIStabilityView[]>([]);
  const [sniRankBusy, setSNIRankBusy] = useState(false);
  const [devUUID, setDevUUID] = useState('123e4567-e89b-42d3-a456-426614174000');
  const [devXrayVersion, setDevXrayVersion] = useState('v26.3.27');
  const [devPort, setDevPort] = useState(443);
  const [devPath, setDevPath] = useState('/xhttp');
  const [devMode, setDevMode] = useState('packet-up');
  const [devBundle, setDevBundle] = useState<DevcontainerBundleView | null>(null);
  const [devBusy, setDevBusy] = useState(false);
  const [circumventionCatalog, setCircumventionCatalog] = useState<CircumventionCapabilityView[]>([]);
  const [circumventionFilter, setCircumventionFilter] = useState('all');
  const [circumventionBusy, setCircumventionBusy] = useState(false);

  const [meshSource, setMeshSource] = useState('local');
  const [meshPolicy, setMeshPolicy] = useState('latency-first');
  const [meshNodes, setMeshNodes] = useState('["local","edge-a","edge-b"]');
  const [meshEdges, setMeshEdges] = useState('[{"from":"local","to":"edge-a","latency_ms":35,"loss_pct":0},{"from":"edge-a","to":"edge-b","latency_ms":30,"loss_pct":1},{"from":"local","to":"edge-b","latency_ms":90,"loss_pct":0}]');
  const [meshPlan, setMeshPlan] = useState<MeshRoutePlanView | null>(null);
  const [meshBusy, setMeshBusy] = useState(false);
  const [endpointPoolInput, setEndpointPoolInput] = useState('[{"endpoint":"relay-a.example:443","successes":20,"failures":1,"latency_ms":60,"remaining_quota":900,"quota_limit":1000,"quota_safety_buffer":100,"jitter_ms":8,"packet_loss_pct":0.2},{"endpoint":"relay-b.example:443","successes":8,"failures":2,"latency_ms":180,"remaining_quota":100,"quota_limit":1000,"quota_safety_buffer":100,"jitter_ms":42,"packet_loss_pct":2.5}]');
  const [endpointPoolScope, setEndpointPoolScope] = useState('operations-preview');
  const [endpointPreviousSuccessful, setEndpointPreviousSuccessful] = useState('');
  const [endpointStrategy, setEndpointStrategy] = useState('quality-first');
  const [endpointPlan, setEndpointPlan] = useState<EndpointPoolPlanView | null>(null);
  const [endpointBusy, setEndpointBusy] = useState(false);
  const [convergencePlanner, setConvergencePlanner] = useState<ConvergencePlannerKind>('kcp');
  const [convergencePlannerInput, setConvergencePlannerInput] = useState(convergencePlannerExamples.kcp);
  const [convergencePlannerResult, setConvergencePlannerResult] = useState<Record<string, unknown> | null>(null);
  const [convergencePlannerBusy, setConvergencePlannerBusy] = useState(false);
  const [peerLocalNodeID, setPeerLocalNodeID] = useState('5fbfbe7519910c34ae7026c3e64eacc13c515901');
  const [peerCandidatesInput, setPeerCandidatesInput] = useState('[{"node_id":"5a3ce91f3dc70a057e9a9fe0cc900d52b4e61e56","address":"21.75.31.124","port":443},{"node_id":"a5d43396da271c1a4d1dc7149247f021eabc3416","address":"65.23.51.170","port":8443}]');
  const [peerBlockedCIDRs, setPeerBlockedCIDRs] = useState('');
  const [peerMaxResults, setPeerMaxResults] = useState(20);
  const [peerPlan, setPeerPlan] = useState<PeerDiscoveryPlanView | null>(null);
  const [peerBusy, setPeerBusy] = useState(false);
  const [dnsSuffix, setDNSSuffix] = useState('tunnel.example.com');
  const [dnsPayloadBytes, setDNSPayloadBytes] = useState(4096);
  const [dnsBudget, setDNSBudget] = useState(1232);
  const [dnsEncoding, setDNSEncoding] = useState('base32');
  const [dnsPreset, setDNSPreset] = useState('balanced');
  const [dnsObservedLossPct, setDNSObservedLossPct] = useState(5);
  const [dnsResolvers, setDNSResolvers] = useState('[{"name":"resolver-a","reachable":true,"mtu":1232,"loss_pct":1,"rtt_ms":45,"throughput_kbps":900},{"name":"resolver-b","reachable":true,"mtu":1000,"loss_pct":8,"rtt_ms":80,"throughput_kbps":650}]');
  const [dnsPlan, setDNSPlan] = useState<DNSTunnelPlanView | null>(null);
  const [dnsBusy, setDNSBusy] = useState(false);
  const [truthHandshake, setTruthHandshake] = useState(true);
  const [truthBurstSize, setTruthBurstSize] = useState(10);
  const [truthFirstBurst, setTruthFirstBurst] = useState(10);
  const [truthSecondBurst, setTruthSecondBurst] = useState(10);
  const [truthAdvertisedCountry, setTruthAdvertisedCountry] = useState('US');
  const [truthMeasuredCountry, setTruthMeasuredCountry] = useState('US');
  const [transportTruth, setTransportTruth] = useState<TransportTruthPlanView | null>(null);
  const [transportTruthBusy, setTransportTruthBusy] = useState(false);
  const [dnsIntegrityUDPReachable, setDNSIntegrityUDPReachable] = useState(true);
  const [dnsIntegrityUDPPoisoned, setDNSIntegrityUDPPoisoned] = useState(false);
  const [dnsIntegrityUDPInjected, setDNSIntegrityUDPInjected] = useState(false);
  const [dnsIntegrityUDPAnswers, setDNSIntegrityUDPAnswers] = useState('1.1.1.1');
  const [dnsIntegrityUDPLatency, setDNSIntegrityUDPLatency] = useState(20);
  const [dnsIntegrityTCPReachable, setDNSIntegrityTCPReachable] = useState(true);
  const [dnsIntegrityTCPPoisoned, setDNSIntegrityTCPPoisoned] = useState(false);
  const [dnsIntegrityTCPInjected, setDNSIntegrityTCPInjected] = useState(false);
  const [dnsIntegrityTCPAnswers, setDNSIntegrityTCPAnswers] = useState('1.1.1.1');
  const [dnsIntegrityTCPLatency, setDNSIntegrityTCPLatency] = useState(30);
  const [dnsIntegrityPlan, setDNSIntegrityPlan] = useState<DNSTransportIntegrityPlanView | null>(null);
  const [dnsIntegrityBusy, setDNSIntegrityBusy] = useState(false);

  const [updateManifestURL, setUpdateManifestURL] = useState('');
  const [updateKeyID, setUpdateKeyID] = useState('');
  const [updatePayload, setUpdatePayload] = useState('');
  const [updateSignature, setUpdateSignature] = useState('');
  const [updatePlan, setUpdatePlan] = useState<UpdatePlan | null>(null);
  const [updateStage, setUpdateStage] = useState<UpdateStageResult | null>(null);
  const [updateBusy, setUpdateBusy] = useState<'discover' | 'plan' | 'stage' | null>(null);
  const [updateError, setUpdateError] = useState<string | null>(null);

  const [trace, setTrace] = useState<TransportTraceSummary | null>(null);
  const [traceName, setTraceName] = useState('');
  const [traceError, setTraceError] = useState<string | null>(null);
  const [traceQuery, setTraceQuery] = useState('');
  const [traceCategory, setTraceCategory] = useState('all');

  const [interruptedJobs, setInterruptedJobs] = useState<InterruptedJobSummary[]>([]);
  const [recoveryJobID, setRecoveryJobID] = useState('');
  const [recoveryInfo, setRecoveryInfo] = useState<RecoveryInfo | null>(null);
  const [recoveryResult, setRecoveryResult] = useState<RecoveryRequeueResult | null>(null);
  const [recoveryBusy, setRecoveryBusy] = useState<'list' | 'inspect' | 'requeue' | null>(null);
  const [recoveryError, setRecoveryError] = useState<string | null>(null);

  const loadRecoveryCandidates = async () => {
    setRecoveryBusy('list');
    setRecoveryError(null);
    try {
      const jobs = await controlTransport.json('/api/history', parseInterruptedJobHistory);
      setInterruptedJobs(jobs);
      setRecoveryJobID((current) => current || jobs[0]?.id || '');
    } catch (caught) {
      setRecoveryError(errorMessage(caught, 'Interrupted job history is unavailable.'));
    } finally {
      setRecoveryBusy(null);
    }
  };

  const inspectRecovery = async (jobID = recoveryJobID) => {
    const id = jobID.trim();
    if (!id) return;
    setRecoveryBusy('inspect');
    setRecoveryError(null);
    setRecoveryResult(null);
    try {
      const info = await controlTransport.json(`/api/jobs/${encodeURIComponent(id)}/recovery`, parseRecoveryInfo);
      setRecoveryInfo(info);
      setRecoveryJobID(id);
    } catch (caught) {
      setRecoveryInfo(null);
      setRecoveryError(errorMessage(caught, 'Recovery inspection failed.'));
    } finally {
      setRecoveryBusy(null);
    }
  };

  const requeueRecovery = async () => {
    if (!recoveryInfo?.requeueAvailable || !recoveryInfo.requiresConfirmation) return;
    if (!window.confirm(`Create and start a NEW ${recoveryInfo.jobType} execution recovered from ${recoveryInfo.jobID}? The interrupted source record will remain unchanged.`)) return;
    setRecoveryBusy('requeue');
    setRecoveryError(null);
    try {
      const result = await controlTransport.json(`/api/jobs/${encodeURIComponent(recoveryInfo.jobID)}/requeue`, parseRecoveryRequeueResult, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ confirm: true }),
      });
      const refreshedInfo = await controlTransport.json(`/api/jobs/${encodeURIComponent(recoveryInfo.jobID)}/recovery`, parseRecoveryInfo);
      const jobs = await controlTransport.json('/api/history', parseInterruptedJobHistory);
      setRecoveryInfo(refreshedInfo);
      setInterruptedJobs(jobs);
      setRecoveryResult(result);
    } catch (caught) {
      setRecoveryError(errorMessage(caught, 'Recovery requeue failed.'));
    } finally {
      setRecoveryBusy(null);
    }
  };

  const loadOverview = async () => {
    setLoadingOverview(true);
    setOverviewError(null);

    const doctorTask = (async () => {
      const response = await controlTransport.request('/api/doctor');
      if (!response.ok) throw new Error(`doctor request failed (${response.status})`);
      const payload: unknown = await response.json();
      return parseDoctorReport(payload);
    })();
    const phasesTask = controlTransport.json('/api/diagnostics/phases', parseDiagnosticPhases);
    const enginesTask = controlTransport.json('/api/system/engines', parseRuntimeEngines);

    const [doctorResult, phasesResult, enginesResult] = await Promise.allSettled([doctorTask, phasesTask, enginesTask]);
    const unavailable: string[] = [];
    if (doctorResult.status === 'fulfilled') setDoctor(doctorResult.value);
    else unavailable.push(`doctor: ${errorMessage(doctorResult.reason, 'unavailable')}`);
    if (phasesResult.status === 'fulfilled') setPhases(phasesResult.value);
    else unavailable.push(`diagnostics: ${errorMessage(phasesResult.reason, 'unavailable')}`);
    if (enginesResult.status === 'fulfilled') setEngines(enginesResult.value);
    else unavailable.push(`engines: ${errorMessage(enginesResult.reason, 'unavailable')}`);

    if (unavailable.length > 0) {
      setOverviewError(`Some operations capabilities are unavailable. ${unavailable.join(' · ')}`);
    }
    setLoadingOverview(false);
  };

  useEffect(() => {
    void loadOverview();
    void loadRecoveryCandidates();
  }, []);

  useEffect(() => {
    if (!diagnosticID) return undefined;
    let cancelled = false;
    const poll = async () => {
      try {
        const status = await controlTransport.json(`/api/diagnostics/${encodeURIComponent(diagnosticID)}`, parseDiagnosticStatus);
        if (cancelled) return;
        setDiagnosticStatus(status);
        if (terminalDiagnosticStates.has(status.status.toLowerCase())) {
          setDiagnosticBusy(false);
          setDiagnosticID(null);
        }
      } catch (caught) {
        if (!cancelled) {
          setOverviewError(errorMessage(caught, 'Failed to poll diagnostic job.'));
          setDiagnosticBusy(false);
          setDiagnosticID(null);
        }
      }
    };
    void poll();
    const timer = window.setInterval(() => void poll(), 900);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [diagnosticID]);

  const runDiagnostic = async () => {
    setDiagnosticBusy(true);
    setDiagnosticStatus(null);
    setOverviewError(null);
    try {
      const id = await controlTransport.executeDiagnosticRun(diagnosticType, diagnosticTarget);
      setDiagnosticID(id);
      setLastDiagnosticID(id);
      setDiagnosticStatus({ status: 'running', progress: 0, results: null });
    } catch (caught) {
      setDiagnosticBusy(false);
      setOverviewError(errorMessage(caught, 'Failed to start diagnostic run.'));
    }
  };

  const exportDiagnostic = async () => {
    if (!lastDiagnosticID) return;
    setOverviewError(null);
    try {
      const response = await controlTransport.request(`/api/diagnostics/${encodeURIComponent(lastDiagnosticID)}/export`);
      if (!response.ok) throw new Error(`diagnostic export failed (${response.status})`);
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = `luminet-diagnostic-${lastDiagnosticID}.json`;
      anchor.click();
      URL.revokeObjectURL(url);
    } catch (caught) {
      setOverviewError(errorMessage(caught, 'Failed to export diagnostic report.'));
    }
  };

  const runPreflight = async () => {
    setPreflightBusy(true);
    setOverviewError(null);
    try {
      const result = await controlTransport.json('/api/system/port-preflight', parsePortPreflight, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ host: preflightHost, port: preflightPort }),
      });
      setPreflightResult(result);
    } catch (caught) {
      setOverviewError(errorMessage(caught, 'Port preflight failed.'));
    } finally {
      setPreflightBusy(false);
    }
  };

  const controlEngine = async (engine: string, action: 'start' | 'stop') => {
    setEngineBusy(engine);
    setOverviewError(null);
    try {
      const body: Record<string, unknown> = { engine, action };
      if (engine === 'sstp' && action === 'start') {
        Object.assign(body, {
          server: sstpServer,
          username: sstpUsername,
          password: sstpPassword,
          upstream_proxy: sstpProxy,
          ca_cert: sstpCACert,
          allow_cert_warning: sstpCertWarn,
          ppp_options: sstpPPPOptions.split(/\r?\n/).map((option) => option.trim()).filter(Boolean),
        });
      }
      if (engine === 'ikev2' && action === 'start') {
        Object.assign(body, {
          server: ikeServer,
          identity: ikeIdentity,
          remote_identity: ikeRemoteIdentity,
          certificate: ikeCertificate,
          private_key: ikePrivateKey,
          local_ts: ikeLocalTS,
          remote_ts: ikeRemoteTS,
          ike_proposals: ikeProposals.split(/\r?\n/).map((proposal) => proposal.trim()).filter(Boolean),
          esp_proposals: espProposals.split(/\r?\n/).map((proposal) => proposal.trim()).filter(Boolean),
        });
      }
      const response = await controlTransport.request('/api/system/engines', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!response.ok) {
        const payload: unknown = await response.json().catch(() => null);
        throw new Error(typeof payload === 'object' && payload !== null && 'error' in payload ? String(payload.error) : `engine request failed (${response.status})`);
      }
      await loadOverview();
    } catch (caught) {
      setOverviewError(errorMessage(caught, `Failed to ${action} ${engine}.`));
    } finally {
      setEngineBusy(null);
    }
  };

  const rotateTorIdentity = async () => {
    setTorBusy('rotate'); setOverviewError(null);
    try { const response = await controlTransport.request('/api/system/engines/tor/identity',{method:'POST'}); if(!response.ok) throw new Error(`Tor identity rotation failed (${response.status})`); }
    catch(caught){ setOverviewError(errorMessage(caught,'Tor identity rotation failed.')); } finally { setTorBusy(null); }
  };

  const probeOnion = async () => {
    setTorBusy('probe'); setOverviewError(null); setTorProbe(null);
    try { const proxies=torProxyPool.split(/\r?\n|,/).map((value)=>value.trim()).filter(Boolean); const result=await controlTransport.json('/api/system/tor/probe',parseOnionProbe,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:torOnionURL.trim(),socks_proxies:proxies})}); setTorProbe(result); }
    catch(caught){ setOverviewError(errorMessage(caught,'Onion probe failed.')); } finally { setTorBusy(null); }
  };

  const probeTorBridges = async () => {
    setTorBridgeBusy(true); setOverviewError(null); setTorBridgeResults([]);
    try {
      const bridges=torBridgeInput.split(/\r?\n/).map((value)=>value.trim()).filter(Boolean);
      const results=await controlTransport.json('/api/system/tor/bridges/probe',parseTorBridgeProbe,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({bridges,workers:torBridgeWorkers,timeout_ms:torBridgeTimeoutMs})});
      setTorBridgeResults(results);
    } catch(caught){ setOverviewError(errorMessage(caught,'Tor bridge reachability probe failed.')); } finally { setTorBridgeBusy(false); }
  };

  const runIperf = async () => {
    setIperfBusy(true); setOverviewError(null); setIperfResult(null);
    try {
      const result=await controlTransport.json('/api/system/iperf',parseIperfProbe,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({address:iperfAddress.trim(),protocol:iperfProtocol,duration_secs:iperfDurationSecs,parallel:iperfParallel,reverse:iperfReverse,udp_bitrate_mbps:iperfProtocol==='udp'?iperfUDPBitrateMbps:0,authorization_confirmed:iperfAuthorization})});
      setIperfResult(result);
    } catch(caught){ setOverviewError(errorMessage(caught,'iperf3 throughput probe failed.')); } finally { setIperfBusy(false); }
  };

  const runSTUNMapping = async () => {
    setSTUNBusy(true); setOverviewError(null); setSTUNResult(null);
    try {
      const result=await controlTransport.json('/api/system/stun-mapping',parseSTUNMappingProbe,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({primary:stunPrimary.trim(),secondary:stunSecondary.trim(),timeout_ms:2000,attempts:2})});
      setSTUNResult(result);
    } catch(caught){ setOverviewError(errorMessage(caught,'STUN mapping probe failed.')); } finally { setSTUNBusy(false); }
  };

  const loadVPNGate = async () => {
    setVPNGateBusy(true); setOverviewError(null);
    try { const params=new URLSearchParams({limit:'20'}); if(vpnGateCountry.trim()) params.set('country',vpnGateCountry.trim()); const rows=await controlTransport.json(`/api/providers/vpngate/servers?${params.toString()}`,parseVPNGate); setVPNGateServers(rows); }
    catch(caught){ setOverviewError(errorMessage(caught,'VPN Gate discovery failed.')); } finally { setVPNGateBusy(false); }
  };

  const selectVPNGateSSTP = (server: VPNGateServerView) => { setSSTPServer(server.sstp_server); setSSTPUsername(server.sstp_username); setSSTPPassword(server.sstp_password); };
  const useVPNGateSSTP = selectVPNGateSSTP;
  void useVPNGateSSTP;

  const loadSNICorpus = async () => {
    setSNIRankBusy(true); setOverviewError(null);
    try { const defaults=await controlTransport.json('/api/sni-scans/spoof/defaults',parseSNIDefaults); setSNIRankCandidates(defaults.candidates.join('\n')); setSNIRankTarget(defaults.target); }
    catch(caught){ setOverviewError(errorMessage(caught,'SNI corpus loading failed.')); } finally { setSNIRankBusy(false); }
  };

  const runSNIStability = async () => {
    setSNIRankBusy(true); setOverviewError(null);
    try { const snis=sniRankCandidates.split(/\r?\n|,/).map((value)=>value.trim()).filter(Boolean); const rows=await controlTransport.json('/api/sni-scans/spoof',parseSNIStability,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:sniRankTarget,snis,timeout_secs:6,concurrency:10,stability_runs:sniRankRuns})}); setSNIRankResults(rows); }
    catch(caught){ setOverviewError(errorMessage(caught,'SNI stability ranking failed.')); } finally { setSNIRankBusy(false); }
  };

  const generateDevcontainer = async () => {
    setDevBusy(true); setOverviewError(null); setDevBundle(null);
    try {
      const bundle=await controlTransport.json('/api/system/provision/templates/vless-devcontainer',parseDevcontainerBundle,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({uuid:devUUID.trim(),xray_version:devXrayVersion.trim(),port:devPort,path:devPath.trim(),mode:devMode})});
      setDevBundle(bundle);
    } catch(caught){ setOverviewError(errorMessage(caught,'Devcontainer generation failed.')); } finally { setDevBusy(false); }
  };

  const downloadDevcontainerBundle = () => {
    if(!devBundle) return;
    const blob=new Blob([JSON.stringify({schema:'luminet.vless-xhttp-devcontainer.v1',...devBundle},null,2)+'\n'],{type:'application/json'});
    const url=URL.createObjectURL(blob); const link=document.createElement('a'); link.href=url; link.download='luminet-vless-xhttp-devcontainer.json'; link.click(); URL.revokeObjectURL(url);
  };

  const loadCircumventionCatalog = async () => {
    setCircumventionBusy(true); setOverviewError(null);
    try { setCircumventionCatalog(await controlTransport.json('/api/circumvention/catalog',parseCircumventionCatalog)); }
    catch(caught){ setOverviewError(errorMessage(caught,'Circumvention catalog loading failed.')); } finally { setCircumventionBusy(false); }
  };

  const visibleCircumventionCatalog = useMemo(() => circumventionCatalog.filter((item)=>circumventionFilter==='all'||item.integration===circumventionFilter),[circumventionCatalog,circumventionFilter]);

  const updateEnvelope = useMemo(() => ({
    envelope: { key_id: updateKeyID.trim(), payload: updatePayload.trim(), signature: updateSignature.trim() },
  }), [updateKeyID, updatePayload, updateSignature]);

  const discoverUpdate = async () => {
    setUpdateBusy('discover');
    setUpdateError(null);
    try {
      if (!updateManifestURL.trim()) throw new Error('Signed manifest URL is required.');
      const discovered = await controlTransport.json('/api/system/update/discover', parseUpdateDiscovery, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ manifest_url: updateManifestURL.trim() }),
      });
      setUpdateKeyID(discovered.envelope.keyId);
      setUpdatePayload(discovered.envelope.payload);
      setUpdateSignature(discovered.envelope.signature);
      setUpdatePlan(discovered.plan);
      setUpdateStage(null);
    } catch (caught) {
      setUpdateError(errorMessage(caught, 'Update discovery failed.'));
    } finally {
      setUpdateBusy(null);
    }
  };

  const runUpdateAction = async (action: 'plan' | 'stage') => {
    setUpdateBusy(action);
    setUpdateError(null);
    try {
      if (!updateEnvelope.envelope.key_id || !updateEnvelope.envelope.payload || !updateEnvelope.envelope.signature) {
        throw new Error('Key ID, payload, and signature are required.');
      }
      if (action === 'plan') {
        const plan = await controlTransport.json('/api/system/update/plan', parseUpdatePlan, {
          method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(updateEnvelope),
        });
        setUpdatePlan(plan);
        setUpdateStage(null);
      } else {
        const staged = await controlTransport.json('/api/system/update/stage', parseUpdateStage, {
          method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(updateEnvelope),
        });
        setUpdatePlan(staged.plan);
        setUpdateStage(staged);
      }
    } catch (caught) {
      setUpdateError(errorMessage(caught, `Update ${action} failed.`));
    } finally {
      setUpdateBusy(null);
    }
  };

  const runMeshRoutePlan = async () => {
    setMeshBusy(true); setOverviewError(null); setMeshPlan(null);
    try {
      const nodes: unknown = JSON.parse(meshNodes);
      const edges: unknown = JSON.parse(meshEdges);
      const plan = await controlTransport.json('/api/system/mesh-route-plan', parseMeshRoutePlan, {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({source:meshSource,policy:meshPolicy,nodes,edges})});
      setMeshPlan(plan);
    } catch (caught) { setOverviewError(errorMessage(caught,'Mesh route planning failed.')); } finally { setMeshBusy(false); }
  };

  const runEndpointPoolPlan = async () => {
    setEndpointBusy(true); setOverviewError(null); setEndpointPlan(null);
    try {
      const endpoints: unknown = JSON.parse(endpointPoolInput);
      const plan = await controlTransport.json('/api/system/endpoint-pool-plan', parseEndpointPoolPlan, {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({endpoints,scope:endpointPoolScope,previous_successful:endpointPreviousSuccessful,strategy:endpointStrategy})});
      setEndpointPlan(plan);
    } catch (caught) { setOverviewError(errorMessage(caught,'Endpoint pool planning failed.')); } finally { setEndpointBusy(false); }
  };

  const runConvergencePlanner = async () => {
    setConvergencePlannerBusy(true); setOverviewError(null); setConvergencePlannerResult(null);
    try {
      const endpoint: Record<ConvergencePlannerKind, string> = { presets:'/api/system/convergence-presets', kcp:'/api/system/kcp-policy-plan', doh:'/api/system/doh-resolver-pool-plan', l7:'/api/system/l7-signature-plan', traffic:'/api/system/traffic-profile-plan', routing:'/api/system/routing-corpus-plan', sniPath:'/api/system/sni-path-plan', sniGateway:'/api/system/sni-gateway-plan', relay:'/api/system/relay-inspection-plan', artifact:'/api/system/artifact-admission-plan', dnsPolicy:'/api/system/dns-resolution-policy-plan', muxPolicy:'/api/system/multiplex-policy-plan', routingArtifact:'/api/system/routing-artifact-plan', tlsFingerprint:'/api/system/tls-fingerprint-policy-plan', incident:'/api/system/service-incident-policy-plan', queue:'/api/system/queue-backpressure-plan', workflow:'/api/system/network-workflow-plan', wireguard:'/api/system/wireguard-device-policy-plan', torBridgeSelect:'/api/system/tor-bridge-selection-plan', torBootstrap:'/api/system/tor-bootstrap-evidence-plan', censorshipEvidence:'/api/system/censorship-measurement-plan', dtlsPolicy:'/api/system/dtls-session-policy-plan', phantomPool:'/api/system/phantom-pool-plan', flowFilter:'/api/system/flow-filter-plan', ptLifecycle:'/api/system/pluggable-transport-plan', circumventionFallback:'/api/system/circumvention-fallback-plan', naivePolicy:'/api/system/naive-proxy-policy-plan', stegoScheme:'/api/system/stego-scheme-plan', multipathTransport:'/api/system/multipath-transport-plan', dnsResolverCampaign:'/api/system/dns-resolver-campaign-plan', outlineAccess:'/api/system/outline-access-plan', dnsTunnelDeployment:'/api/system/dns-tunnel-deployment-plan', dnsRefiner:'/api/system/dns-refiner-plan', httpsUpgradeAudit:'/api/system/https-upgrade-ruleset-plan', torExitScan:'/api/system/tor-exit-scan-plan', mobileTorLifecycle:'/api/system/mobile-tor-lifecycle-plan', securityPosture:'/api/system/security-posture-plan', trafficShaper:'/api/system/traffic-shaper-plan', endpointLocation:'/api/system/endpoint-location-evidence-plan', dnsBlocklistAudit:'/api/system/dns-blocklist-corpus-plan', apiTraceSchema:'/api/system/api-trace-schema-plan', torDescriptorEvidence:'/api/system/tor-descriptor-evidence-plan', processProxyRules:'/api/system/process-proxy-rule-plan', evidenceChain:'/api/system/evidence-chain-plan', dnscryptResolver:'/api/system/dnscrypt-resolver-policy-plan', scanLoadPolicy:'/api/system/scan-load-policy-plan', mobileConnectionReadiness:'/api/system/mobile-connection-readiness-plan', configFallback:'/api/system/config-fallback-plan', dnsInterceptSafety:'/api/system/dns-intercept-safety-plan', torConsensusEvidence:'/api/system/tor-consensus-evidence-plan', dnscryptTopology:'/api/system/dnscrypt-topology-plan', evidenceReceiptTopology:'/api/system/evidence-receipt-topology-plan', dnsFilterPreset:'/api/system/dns-filter-preset-plan', networkEvidenceBundle:'/api/system/network-evidence-bundle-plan', clientHelloEvidence:'/api/system/clienthello-evidence-plan', encryptedDNSPolicy:'/api/system/encrypted-dns-policy-plan', torLabRelay:'/api/system/tor-lab-relay-plan', proxyChainSafety:'/api/system/proxy-chain-safety-plan', transportReplay:'/api/system/transport-replay-plan', secretRefreshPolicy:'/api/system/secret-refresh-policy-plan', realityAdmission:'/api/system/reality-admission-plan', serviceRecoveryPolicy:'/api/system/service-recovery-policy-plan', networkTrustBundle:'/api/system/network-trust-bundle-plan' };
      const options = convergencePlanner === 'presets' ? undefined : { method:'POST', headers:{'Content-Type':'application/json'}, body:convergencePlannerInput.trim() || '{}' };
      const result = await controlTransport.json(endpoint[convergencePlanner], parseConvergencePlannerResult, options);
      setConvergencePlannerResult(result);
    } catch (caught) { setOverviewError(errorMessage(caught,'Convergence planning failed.')); } finally { setConvergencePlannerBusy(false); }
  };

  const runPeerDiscoveryPlan = async () => {
    setPeerBusy(true); setOverviewError(null); setPeerPlan(null);
    try {
      const candidates: unknown = JSON.parse(peerCandidatesInput);
      const blocked_cidrs = peerBlockedCIDRs.split(/\r?\n|,/).map((item)=>item.trim()).filter(Boolean);
      const plan = await controlTransport.json('/api/system/peer-discovery-plan', parsePeerDiscoveryPlan, {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({local_node_id:peerLocalNodeID,candidates,blocked_cidrs,max_results:peerMaxResults})});
      setPeerPlan(plan);
    } catch (caught) { setOverviewError(errorMessage(caught,'Peer discovery planning failed.')); } finally { setPeerBusy(false); }
  };

  const runDNSTunnelPlan = async () => {
    setDNSBusy(true); setOverviewError(null); setDNSPlan(null);
    try {
      const resolvers: unknown = JSON.parse(dnsResolvers);
      const plan = await controlTransport.json('/api/system/dns-tunnel-plan', parseDNSTunnelPlan, {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({suffix:dnsSuffix,payload_bytes:dnsPayloadBytes,udp_budget:dnsBudget,encoding:dnsEncoding,preset:dnsPreset,observed_loss_pct:dnsObservedLossPct,resolvers:dnsResolvers && resolvers})});
      setDNSPlan(plan);
    } catch (caught) { setOverviewError(errorMessage(caught,'DNS tunnel planning failed.')); } finally { setDNSBusy(false); }
  };

  const runTransportTruthPlan = async () => {
    setTransportTruthBusy(true); setOverviewError(null); setTransportTruth(null);
    try {
      const plan = await controlTransport.json('/api/system/transport-truth-plan', parseTransportTruthPlan, {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({handshake_ok:truthHandshake,burst_size:truthBurstSize,first_burst_successes:truthFirstBurst,second_burst_successes:truthSecondBurst,advertised_country:truthAdvertisedCountry,measured_egress_country:truthMeasuredCountry})});
      setTransportTruth(plan);
    } catch (caught) { setOverviewError(errorMessage(caught,'Transport truth planning failed.')); } finally { setTransportTruthBusy(false); }
  };

  const runDNSTransportIntegrityPlan = async () => {
    setDNSIntegrityBusy(true); setOverviewError(null); setDNSIntegrityPlan(null);
    try {
      const answers = (raw: string) => raw.split(/\r?\n|,/).map((item)=>item.trim()).filter(Boolean);
      const plan = await controlTransport.json('/api/system/dns-transport-integrity-plan', parseDNSTransportIntegrityPlan, {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({udp:{reachable:dnsIntegrityUDPReachable,poisoned:dnsIntegrityUDPPoisoned,injection_observed:dnsIntegrityUDPInjected,answers:answers(dnsIntegrityUDPAnswers),latency_ms:dnsIntegrityUDPLatency},tcp:{reachable:dnsIntegrityTCPReachable,poisoned:dnsIntegrityTCPPoisoned,injection_observed:dnsIntegrityTCPInjected,answers:answers(dnsIntegrityTCPAnswers),latency_ms:dnsIntegrityTCPLatency}})});
      setDNSIntegrityPlan(plan);
    } catch (caught) { setOverviewError(errorMessage(caught,'DNS transport integrity planning failed.')); } finally { setDNSIntegrityBusy(false); }
  };

  const loadTrace = async (file: File | undefined) => {
    if (!file) return;
    setTraceName(file.name);
    setTraceError(null);
    try {
      const text = await file.text();
      setTrace(parseTransportTrace(text));
    } catch (caught) {
      setTrace(null);
      setTraceError(errorMessage(caught, 'Unable to parse transport trace.'));
    }
  };

  const filteredTraceEvents = useMemo(() => {
    if (!trace) return [];
    const query = traceQuery.trim().toLowerCase();
    return trace.retainedEvents.filter((event) => {
      if (traceCategory !== 'all' && event.category !== traceCategory) return false;
      if (!query) return true;
      return `${event.category} ${event.name} ${event.detail}`.toLowerCase().includes(query);
    });
  }, [trace, traceCategory, traceQuery]);

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <header className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
        <div>
          <p className="mono mb-2 text-xs uppercase tracking-[0.2em] text-accent">Operator workspace</p>
          <h2 className="mb-2 text-3xl text-text-primary">Operations & transport lab</h2>
          <p className="m-0 max-w-3xl text-sm text-text-secondary">Diagnostics, runtime engines, signed updates, local bind preflight, and offline QUIC/QLOG inspection in one control surface.</p>
        </div>
        <button type="button" onClick={() => void loadOverview()} disabled={loadingOverview} className="btn btn-secondary">
          <RefreshCw size={16} className={loadingOverview ? 'animate-spin' : ''} aria-hidden="true" /> Refresh
        </button>
      </header>

      {overviewError && <div role="alert" className="rounded-md border border-error/30 bg-error/15 p-3 text-sm text-error">{overviewError}</div>}

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <section className="card space-y-4" aria-labelledby="doctor-title">
          <h3 id="doctor-title" className="m-0 flex items-center gap-2 border-b border-border-color pb-3 text-lg"><Stethoscope size={18} className="text-cyan" /> Readiness doctor</h3>
          {doctor ? (
            <>
              <div className={`rounded-md border p-3 text-sm font-semibold ${doctor.healthy ? 'border-success/30 bg-success/10 text-success' : 'border-warning/30 bg-warning/10 text-warning'}`}>
                {doctor.healthy ? 'All readiness checks passed.' : 'One or more readiness checks are degraded.'}
                <span className="mono ml-2 text-xs text-text-muted">{doctor.goVersion} · {doctor.goos}/{doctor.goarch}</span>
              </div>
              <div className="space-y-2">
                {doctor.checks.map((check) => (
                  <div key={check.name} className="flex items-start gap-3 rounded-md border border-border-color bg-bg-secondary/50 p-3">
                    {check.ok ? <CircleCheck size={18} className="mt-0.5 shrink-0 text-success" /> : <CircleX size={18} className="mt-0.5 shrink-0 text-error" />}
                    <div className="min-w-0 flex-1">
                      <div className="text-sm font-semibold text-text-primary">{check.name}</div>
                      <div className="text-xs text-text-secondary">{check.message || 'No detail reported.'}</div>
                    </div>
                    <span className="mono text-[10px] text-text-muted">{(check.latencyNs / 1_000_000).toFixed(2)} ms</span>
                  </div>
                ))}
              </div>
            </>
          ) : <p className="m-0 text-sm text-text-muted">No readiness report loaded.</p>}
        </section>

        <section className="card space-y-4" aria-labelledby="preflight-title">
          <h3 id="preflight-title" className="m-0 flex items-center gap-2 border-b border-border-color pb-3 text-lg"><Cable size={18} className="text-purple" /> Local port preflight</h3>
          <p className="m-0 text-sm text-text-secondary">Check whether a local listener port is already occupied before starting a sidecar or proxy.</p>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-[1fr_140px_auto]">
            <input value={preflightHost} onChange={(e) => setPreflightHost(e.target.value)} placeholder="127.0.0.1" className="min-h-11 rounded-md border border-border-color bg-bg-primary px-3" />
            <input type="number" min={1} max={65535} value={preflightPort} onChange={(e) => setPreflightPort(Number(e.target.value))} className="min-h-11 rounded-md border border-border-color bg-bg-primary px-3" />
            <button type="button" onClick={() => void runPreflight()} disabled={preflightBusy} className="btn btn-primary"><Gauge size={16} /> Check</button>
          </div>
          {preflightResult && (
            <div className={`rounded-md border p-3 text-sm ${preflightResult.available ? 'border-success/30 bg-success/10 text-success' : 'border-warning/30 bg-warning/10 text-warning'}`}>
              <span className="mono font-semibold">{preflightResult.address}</span> · {preflightResult.message}
            </div>
          )}
        </section>
      </div>

      <section className="card space-y-5" aria-labelledby="engines-title">
        <h3 id="engines-title" className="m-0 flex items-center gap-2 border-b border-border-color pb-3 text-lg"><ServerCog size={18} className="text-accent" /> Runtime engines</h3>
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
          {engines.map((engine) => (
            <article key={engine.id} className="rounded-lg border border-border-color bg-bg-secondary/45 p-4">
              <div className="mb-3 flex items-start justify-between gap-3">
                <div><h4 className="m-0 text-base text-text-primary">{engine.name}</h4><p className="mt-1 text-xs text-text-muted">{engine.description}</p></div>
                <div className="flex flex-col items-end gap-1"><span className={`rounded-full border px-2 py-1 text-[10px] font-semibold uppercase ${engine.running ? 'border-success/30 bg-success/10 text-success' : 'border-border-color text-text-muted'}`}>{engine.running ? 'running' : 'stopped'}</span><span className={`text-[10px] uppercase ${engine.available ? 'text-success' : 'text-warning'}`}>{engine.available ? 'available' : 'missing binary'}</span></div>
              </div>
              <p className="mono text-xs text-text-secondary">{engine.mode}{engine.socksPort ? ` · 127.0.0.1:${engine.socksPort}` : ''}</p>
              {engine.binaryPath && <p className="mono truncate text-[10px] text-text-muted" title={engine.binaryPath}>{engine.binaryPath}</p>}
              {!engine.available && engine.availabilityReason && <p className="text-xs text-warning">{engine.availabilityReason}</p>}
              <button type="button" onClick={() => void controlEngine(engine.id, engine.running ? 'stop' : 'start')} disabled={engineBusy !== null || (!engine.running && !engine.available) || ((engine.id === 'sstp' || engine.id === 'ikev2') && !engine.running)} className="btn btn-secondary w-full">
                {engineBusy === engine.id ? <RefreshCw size={16} className="animate-spin" /> : <Play size={16} />}{engine.running ? 'Stop engine' : engine.id === 'sstp' ? 'Use SSTP form below' : engine.id === 'ikev2' ? 'Use IKEv2 form below' : 'Start engine'}
              </button>
            </article>
          ))}
        </div>
        <div className="rounded-lg border border-border-color bg-bg-primary/60 p-4">
          <div className="mb-3 flex items-center gap-2"><Wifi size={17} className="text-cyan" /><h4 className="m-0 text-sm">SSTP profile</h4></div>
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
            <Field label="Server"><input value={sstpServer} onChange={(e) => setSSTPServer(e.target.value)} placeholder="vpn.example.com:443" className="field-input" /></Field>
            <Field label="Username"><input value={sstpUsername} onChange={(e) => setSSTPUsername(e.target.value)} className="field-input" /></Field>
            <Field label="Password"><input type="password" value={sstpPassword} onChange={(e) => setSSTPPassword(e.target.value)} className="field-input" /></Field>
            <Field label="HTTP proxy (optional)"><input value={sstpProxy} onChange={(e) => setSSTPProxy(e.target.value)} placeholder="http://127.0.0.1:8080" className="field-input" /></Field>
            <Field label="CA certificate path (optional)"><input value={sstpCACert} onChange={(e) => setSSTPCACert(e.target.value)} className="field-input" /></Field>
            <label className="flex min-h-11 items-center gap-2 rounded-md border border-border-color px-3 text-sm text-text-secondary"><input type="checkbox" checked={sstpCertWarn} onChange={(e) => setSSTPCertWarn(e.target.checked)} /> Accept certificate warnings</label>
            <Field label="Advanced PPP options (one per line; blank uses LumiNet defaults)"><textarea value={sstpPPPOptions} onChange={(e) => setSSTPPPPOptions(e.target.value)} rows={4} className="field-input mono resize-y" placeholder={'usepeerdns\ndefaultroute'} /></Field>
          </div>
          <div className="mt-3 flex flex-wrap gap-2">
            <button type="button" onClick={() => void controlEngine('sstp', 'start')} disabled={engineBusy !== null || engines.find((engine) => engine.id === 'sstp')?.available === false || !sstpServer || !sstpUsername || !sstpPassword} className="btn btn-primary"><Play size={16} /> Start SSTP</button>
            <button type="button" onClick={() => void controlEngine('sstp', 'stop')} disabled={engineBusy !== null} className="btn btn-secondary">Stop SSTP</button>
          </div>
        </div>
        <div className="rounded-lg border border-border-color bg-bg-primary/60 p-4">
          <div className="mb-3 flex items-center gap-2"><ShieldCheck size={17} className="text-purple" /><h4 className="m-0 text-sm">IKEv2 / strongSwan public-key profile</h4></div>
          <p className="mb-3 mt-0 text-xs text-text-muted">Non-interactive <span className="mono">charon-cmd --profile ikev2-pub</span>. Certificate and private-key paths are read by the external strongSwan engine.</p>
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
            <Field label="Gateway host or IP"><input value={ikeServer} onChange={(e)=>setIKEServer(e.target.value)} placeholder="vpn.example.com" className="field-input mono" /></Field>
            <Field label="Local identity"><input value={ikeIdentity} onChange={(e)=>setIKEIdentity(e.target.value)} placeholder="client@example.com" className="field-input mono" /></Field>
            <Field label="Remote identity (optional)"><input value={ikeRemoteIdentity} onChange={(e)=>setIKERemoteIdentity(e.target.value)} placeholder="vpn.example.com" className="field-input mono" /></Field>
            <Field label="Certificate path"><input value={ikeCertificate} onChange={(e)=>setIKECertificate(e.target.value)} placeholder="/etc/luminet/client-cert.pem" className="field-input mono" /></Field>
            <Field label="Private-key path"><input value={ikePrivateKey} onChange={(e)=>setIKEPrivateKey(e.target.value)} placeholder="/etc/luminet/client-key.pem" className="field-input mono" /></Field>
            <Field label="Local traffic selector (optional)"><input value={ikeLocalTS} onChange={(e)=>setIKELocalTS(e.target.value)} placeholder="0.0.0.0/0" className="field-input mono" /></Field>
            <Field label="Remote traffic selector (optional)"><input value={ikeRemoteTS} onChange={(e)=>setIKERemoteTS(e.target.value)} placeholder="0.0.0.0/0" className="field-input mono" /></Field>
            <Field label="IKE proposals (one per line)"><textarea value={ikeProposals} onChange={(e)=>setIKEProposals(e.target.value)} rows={3} placeholder="aes256-sha256-modp2048" className="field-input mono resize-y" /></Field>
            <Field label="ESP proposals (one per line)"><textarea value={espProposals} onChange={(e)=>setESPProposals(e.target.value)} rows={3} placeholder="aes256-sha256" className="field-input mono resize-y" /></Field>
          </div>
          <div className="mt-3 flex flex-wrap gap-2">
            <button type="button" onClick={()=>void controlEngine('ikev2','start')} disabled={engineBusy !== null || engines.find((engine)=>engine.id==='ikev2')?.available === false || !ikeServer.trim() || !ikeIdentity.trim() || !ikeCertificate.trim() || !ikePrivateKey.trim()} className="btn btn-primary"><Play size={16}/> Start IKEv2</button>
            <button type="button" onClick={()=>void controlEngine('ikev2','stop')} disabled={engineBusy !== null} className="btn btn-secondary">Stop IKEv2</button>
          </div>
        </div>
      </section>

      <section className="card space-y-4" aria-labelledby="network-planners-title">
        <h3 id="network-planners-title" className="m-0 flex items-center gap-2 border-b border-border-color pb-3 text-lg"><Activity size={18} className="text-cyan" /> Network planning lab</h3>
        <p className="m-0 text-sm text-text-secondary">Compare mesh routes, evidence-ranked endpoint pools, BEP42 peer admission, and DNS framing capacity without changing routes or opening tunnel sockets.</p>
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-2 2xl:grid-cols-4">
          <div className="space-y-3 rounded-lg border border-border-color bg-bg-primary/60 p-4">
            <h4 className="m-0 text-sm">Mesh route planner</h4>
            <div className="grid grid-cols-2 gap-2"><input value={meshSource} onChange={(e)=>setMeshSource(e.target.value)} className="field-input mono" placeholder="source node" /><select value={meshPolicy} onChange={(e)=>setMeshPolicy(e.target.value)} className="field-input"><option value="latency-first">latency-first</option><option value="least-hop">least-hop</option></select></div>
            <Field label="Nodes JSON"><textarea value={meshNodes} onChange={(e)=>setMeshNodes(e.target.value)} rows={2} className="field-input mono resize-y" /></Field>
            <Field label="Edges JSON"><textarea value={meshEdges} onChange={(e)=>setMeshEdges(e.target.value)} rows={5} className="field-input mono resize-y" /></Field>
            <button type="button" onClick={()=>void runMeshRoutePlan()} disabled={meshBusy} className="btn btn-secondary">{meshBusy?<RefreshCw size={16} className="animate-spin"/>:<Gauge size={16}/>} Plan routes</button>
            {meshPlan && <div className="max-h-52 overflow-auto rounded border border-border-color">{meshPlan.routes.map((route)=><div key={route.destination} className="border-b border-border-color/50 p-2 text-xs last:border-0"><div className="flex justify-between gap-2"><span className="mono text-accent">{route.destination}</span><span>{route.total_latency_ms} ms · {route.reliability_pct}%</span></div><div className="mono mt-1 text-[10px] text-text-muted">{route.path.join(' → ')} · cost {route.cost}</div></div>)}</div>}
          </div>
          <div className="space-y-3 rounded-lg border border-border-color bg-bg-primary/60 p-4">
            <h4 className="m-0 text-sm">Endpoint pool planner</h4>
            <p className="m-0 text-xs text-text-muted">Rank observed endpoints by success, latency, usable quota headroom, recent failure, jitter and loss. A quota safety buffer reserves capacity before exhaustion; diversity only rotates near-equal candidates.</p>
            <Field label="Endpoint observations JSON"><textarea value={endpointPoolInput} onChange={(e)=>setEndpointPoolInput(e.target.value)} rows={8} className="field-input mono resize-y" /></Field>
            <div className="grid grid-cols-2 gap-2"><Field label="Diversity scope"><input value={endpointPoolScope} onChange={(e)=>setEndpointPoolScope(e.target.value)} maxLength={256} className="field-input mono" /></Field><Field label="Last-known-good hint"><input value={endpointPreviousSuccessful} onChange={(e)=>setEndpointPreviousSuccessful(e.target.value)} maxLength={512} placeholder="optional endpoint" className="field-input mono" /></Field></div>
            <Field label="Dispatch strategy"><select value={endpointStrategy} onChange={(e)=>setEndpointStrategy(e.target.value)} className="field-input"><option value="quality-first">quality-first</option><option value="least-loaded">least-loaded</option><option value="weighted-quality">weighted-quality</option><option value="sticky">sticky</option></select></Field>
            <button type="button" onClick={()=>void runEndpointPoolPlan()} disabled={endpointBusy} className="btn btn-secondary">{endpointBusy?<RefreshCw size={16} className="animate-spin"/>:<Activity size={16}/>} Rank pool</button>
            {endpointPlan && <><div className="text-xs text-text-muted">Preferred <span className="mono text-text-primary">{endpointPlan.preferred_endpoint || 'none'}</span> · warm {endpointPlan.warm_pool} · diversity {endpointPlan.diversity_applied?'applied':'not needed'} · prior success {endpointPlan.reused_previous_success?'reused':'not reused'}</div><div className="flex flex-wrap gap-1">{endpointPlan.selection_basis.map((basis)=><span key={basis} className="rounded bg-bg-secondary px-1.5 py-0.5 text-[10px] text-text-muted">{basis}</span>)}</div><div className="max-h-52 overflow-auto rounded border border-border-color">{endpointPlan.ranked.map((row)=><div key={row.endpoint} className="border-b border-border-color/50 p-2 text-xs last:border-0"><div className="flex items-center justify-between gap-2"><span className="mono truncate">{row.endpoint}</span><span className={row.eligible?'text-success':'text-text-muted'}>{row.quality} · {row.score}</span></div><div className="mt-1 text-[10px] text-text-muted">success {row.success_rate_pct}% · latency {row.latency_ms ?? 0} ms · quota headroom {row.quota_headroom ?? 0} ({row.quota_headroom_pct ?? 0}%) / reserve {row.quota_safety_buffer ?? 0}{row.quota_guarded?' · quota guarded':''} · jitter {row.jitter_ms ?? 0} ms · loss {row.packet_loss_pct ?? 0}% · health {row.health_state} · load {row.load_pct ?? 0}% · weight {row.weight}{row.circuit_open?' · circuit open':''}</div></div>)}</div></>}
          </div>
          <div className="space-y-3 rounded-lg border border-border-color bg-bg-primary/60 p-4">
            <h4 className="m-0 text-sm">Convergence policy lab</h4>
            <p className="m-0 text-xs text-text-muted">Every surface is planning-only; none installs policy or opens sockets. This convergence laboratory also never sends notifications or mutates queues while reviewing transport, SNI, TLS fingerprint, DNS, multiplex, routing-artifact, incident, backpressure, workflow, WireGuard, Tor bridge/bootstrap, censorship evidence, DTLS, phantom selection, flow-filter, multipath, DNS campaign, Outline access-key, DNSTT deployment, DNS refinement, HTTPS upgrade audit, Tor exit scheduling, mobile Tor lifecycle, security posture, traffic shaping and endpoint-location evidence, adaptive scan load, mobile readiness, first-supported config fallback, DNS intercept safety, Tor consensus evidence, DNSCrypt topology, evidence-receipt topology and DNS-filter preset composition.</p>
            <Field label="Planner"><select value={convergencePlanner} onChange={(e)=>{const next=e.target.value as ConvergencePlannerKind;setConvergencePlanner(next);setConvergencePlannerInput(convergencePlannerExamples[next]);setConvergencePlannerResult(null);}} className="field-input"><option value="presets">presets</option><option value="kcp">KCP policy</option><option value="doh">DoH resolver pool</option><option value="l7">L7 signature admission</option><option value="traffic">traffic profile</option><option value="routing">routing corpus</option><option value="sniPath">SNI path lifecycle</option><option value="sniGateway">SNI gateway preflight</option><option value="relay">relay design inspection</option><option value="artifact">artifact admission</option><option value="dnsPolicy">DNS resolution policy</option><option value="muxPolicy">multiplex policy</option><option value="routingArtifact">routing artifact provenance</option><option value="tlsFingerprint">TLS fingerprint policy</option><option value="incident">service incident policy</option><option value="queue">queue backpressure</option><option value="workflow">network workflow composition</option><option value="wireguard">WireGuard device policy</option><option value="torBridgeSelect">Tor bridge selection</option><option value="torBootstrap">Tor bootstrap evidence</option><option value="censorshipEvidence">censorship control evidence</option><option value="dtlsPolicy">DTLS session policy</option><option value="phantomPool">phantom endpoint pool</option><option value="flowFilter">flow metadata filter</option><option value="ptLifecycle">pluggable transport lifecycle</option><option value="circumventionFallback">bounded circumvention fallback</option><option value="naivePolicy">NaiveProxy compatibility policy</option><option value="stegoScheme">stego cover-scheme selection</option><option value="multipathTransport">multipath transport scheduling</option><option value="dnsResolverCampaign">DNS resolver campaign</option><option value="outlineAccess">Outline access-key admission</option><option value="dnsTunnelDeployment">DNSTT deployment preflight</option><option value="dnsRefiner">DNS subscription refinement</option><option value="httpsUpgradeAudit">HTTPS upgrade corpus audit</option><option value="torExitScan">Tor exit scan scheduling</option><option value="mobileTorLifecycle">mobile Tor lifecycle</option><option value="securityPosture">security posture evidence</option><option value="trafficShaper">traffic shaper policy</option><option value="endpointLocation">endpoint location evidence</option><option value="dnsBlocklistAudit">DNS blocklist corpus audit</option><option value="apiTraceSchema">API trace schema inference</option><option value="torDescriptorEvidence">Tor descriptor evidence</option><option value="processProxyRules">process proxy rule compilation</option><option value="evidenceChain">cryptographic evidence chain</option><option value="dnscryptResolver">DNSCrypt resolver policy</option><option value="scanLoadPolicy">adaptive scan-load policy</option><option value="mobileConnectionReadiness">mobile connection readiness</option><option value="configFallback">first-supported config fallback</option><option value="dnsInterceptSafety">DNS intercept safety</option><option value="torConsensusEvidence">Tor consensus evidence</option><option value="dnscryptTopology">DNSCrypt resolver/relay topology</option><option value="evidenceReceiptTopology">evidence receipt topology</option><option value="dnsFilterPreset">DNS filter preset composition</option><option value="networkEvidenceBundle">network evidence readiness bundle</option><option value="clientHelloEvidence">ClientHello / QUIC evidence</option><option value="encryptedDNSPolicy">encrypted DNS cache / ECS policy</option><option value="torLabRelay">Tor lab / relay topology</option><option value="proxyChainSafety">proxy chain safety</option><option value="transportReplay">transport replay / salt admission</option><option value="secretRefreshPolicy">secret refresh / watch policy</option><option value="realityAdmission">REALITY admission</option><option value="serviceRecoveryPolicy">service recovery ordering</option><option value="networkTrustBundle">network trust readiness bundle</option></select></Field>
            {convergencePlanner!=='presets' && <Field label="Request JSON"><textarea value={convergencePlannerInput} onChange={(e)=>setConvergencePlannerInput(e.target.value)} rows={8} className="field-input mono resize-y" /></Field>}
            <button type="button" onClick={()=>void runConvergencePlanner()} disabled={convergencePlannerBusy} className="btn btn-secondary">{convergencePlannerBusy?<RefreshCw size={16} className="animate-spin"/>:<ShieldCheck size={16}/>} {convergencePlanner==='presets'?'Load presets':'Analyze'}</button>
            {convergencePlannerResult && <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-words rounded border border-border-color bg-bg-secondary p-2 text-[10px] text-text-muted">{JSON.stringify(convergencePlannerResult,null,2)}</pre>}
          </div>
          <GatewayCompositionPlanner />
          <WireGuardIndexTranslationPlanner />
          <SNIDecoyHandshakePlanner />
          <div className="space-y-3 rounded-lg border border-border-color bg-bg-primary/60 p-4">
            <h4 className="m-0 text-sm">Peer discovery admission</h4>
            <p className="m-0 text-xs text-text-muted">Read-only BEP42 IPv4 admission and exact 160-bit XOR ordering. It never dials, persists, or routes through candidates.</p>
            <Field label="Local node ID"><input value={peerLocalNodeID} onChange={(e)=>setPeerLocalNodeID(e.target.value)} maxLength={40} className="field-input mono" /></Field>
            <Field label="Candidate peers JSON"><textarea value={peerCandidatesInput} onChange={(e)=>setPeerCandidatesInput(e.target.value)} rows={7} className="field-input mono resize-y" /></Field>
            <Field label="Local blocked IPv4 CIDRs (optional, one per line)"><textarea value={peerBlockedCIDRs} onChange={(e)=>setPeerBlockedCIDRs(e.target.value)} rows={3} maxLength={8192} className="field-input mono resize-y" placeholder={'203.0.113.0/24\n198.51.100.5/32'} /></Field>
            <Field label="Maximum results"><input type="number" min={1} max={64} value={peerMaxResults} onChange={(e)=>setPeerMaxResults(Math.max(1,Math.min(64,Number(e.target.value)||20)))} className="field-input" /></Field>
            <button type="button" onClick={()=>void runPeerDiscoveryPlan()} disabled={peerBusy} className="btn btn-secondary">{peerBusy?<RefreshCw size={16} className="animate-spin"/>:<ShieldCheck size={16}/>} Validate peers</button>
            {peerPlan && <div className="space-y-2"><div className="text-xs text-text-muted">{peerPlan.returned_count}/{peerPlan.eligible_count} admitted · {peerPlan.rejected_count} rejected · {peerPlan.blocked_prefix_count} local deny prefixes</div><div className="max-h-40 overflow-auto rounded border border-border-color">{peerPlan.accepted.map((peer)=><div key={`${peer.node_id}-${peer.address}-${peer.port}`} className="border-b border-border-color/50 p-2 text-xs last:border-0"><div className="flex justify-between gap-2"><span className="mono truncate">{peer.address}:{peer.port}</span><span className="text-success">admitted</span></div><div className="mono mt-1 truncate text-[10px] text-text-muted">{peer.node_id} · distance {peer.distance.slice(0,16)}…{peer.trust_observed?` · trust ${peer.trust_score?.toFixed(2)}`:''}{peer.shared_address_observed?` · shared address ×${peer.shared_address_count}`:''}</div></div>)}{peerPlan.rejected.map((peer,index)=><div key={`${peer.node_id || peer.address || 'peer'}-${index}`} className="border-b border-border-color/50 p-2 text-xs last:border-0"><div className="flex justify-between gap-2"><span className="mono truncate">{peer.address || peer.node_id || 'candidate'}</span><span className="text-warning">{peer.reason}</span></div><div className="mt-1 text-[10px] text-text-muted">{peer.detail}</div></div>)}</div><p className="m-0 text-[10px] text-text-muted">{peerPlan.identity_model} · {peerPlan.safety_boundary}</p></div>}
          </div>
          <div className="space-y-3 rounded-lg border border-border-color bg-bg-primary/60 p-4">
            <h4 className="m-0 text-sm">DNS tunnel capacity</h4>
            <p className="m-0 text-xs text-text-muted">Capacity plus read-only reliability advice. Reliability mode can move through raw / fec / super-fec / arq-primary; this planner never opens a DNS tunnel.</p>
            <Field label="DNS suffix"><input value={dnsSuffix} onChange={(e)=>setDNSSuffix(e.target.value)} className="field-input mono" /></Field>
            <div className="grid grid-cols-2 gap-2"><Field label="Payload bytes"><input type="number" min={0} value={dnsPayloadBytes} onChange={(e)=>setDNSPayloadBytes(Math.max(0,Number(e.target.value)||0))} className="field-input" /></Field><Field label="UDP budget"><input type="number" min={512} max={4096} value={dnsBudget} onChange={(e)=>setDNSBudget(Number(e.target.value)||1232)} className="field-input" /></Field></div>
            <Field label="Encoding"><select value={dnsEncoding} onChange={(e)=>setDNSEncoding(e.target.value)} className="field-input"><option value="base32">base32</option><option value="base64url">base64url</option></select></Field>
            <div className="grid grid-cols-2 gap-2"><Field label="Reliability preset"><select value={dnsPreset} onChange={(e)=>setDNSPreset(e.target.value)} className="field-input"><option value="balanced">balanced</option><option value="speed">speed</option><option value="survival">survival</option><option value="tcp-survival">tcp-survival</option><option value="high-latency">high-latency</option></select></Field><Field label="Observed loss %"><input type="number" min={0} max={100} step={0.1} value={dnsObservedLossPct} onChange={(e)=>setDNSObservedLossPct(Math.max(0,Math.min(100,Number(e.target.value)||0)))} className="field-input" /></Field></div>
            <Field label="Resolver observations JSON"><textarea value={dnsResolvers} onChange={(e)=>setDNSResolvers(e.target.value)} rows={5} className="field-input mono resize-y" /></Field>
            <button type="button" onClick={()=>void runDNSTunnelPlan()} disabled={dnsBusy} className="btn btn-secondary">{dnsBusy?<RefreshCw size={16} className="animate-spin"/>:<Cable size={16}/>} Estimate</button>
            {dnsPlan && <div className="space-y-2"><dl className="grid grid-cols-2 gap-2 rounded border border-border-color p-2 text-xs"><DataPoint label="Frame payload" value={`${dnsPlan.frame_payload_bytes} B`} /><DataPoint label="Fragments" value={String(dnsPlan.fragments)} /><DataPoint label="Query bytes" value={String(dnsPlan.query_payload_bytes)} /><DataPoint label="Response bytes" value={String(dnsPlan.response_payload_bytes)} /><DataPoint label="Reliability mode" value={dnsPlan.reliability.mode} /><DataPoint label="Preferred transport" value={dnsPlan.reliability.preferred_transport.toUpperCase()} /><DataPoint label="FEC shards" value={`${dnsPlan.reliability.data_shards}+${dnsPlan.reliability.parity_shards}`} /><DataPoint label="Recovery probability" value={`${dnsPlan.reliability.recovery_probability_pct}%`} /></dl>{dnsPlan.reliability.resolvers.length>0 && <div><div className="mb-1 text-[10px] uppercase tracking-wide text-text-muted">Resolver tiers · operating MTU {dnsPlan.reliability.operating_mtu || 'n/a'}</div><div className="max-h-40 overflow-auto rounded border border-border-color">{dnsPlan.reliability.resolvers.map((row)=><div key={row.name} className="flex items-center justify-between gap-2 border-b border-border-color/50 p-2 text-xs last:border-0"><span className="mono truncate">{row.name}</span><span className={row.tier==='active'?'text-success':row.tier==='reserve'?'text-warning':'text-text-muted'}>{row.tier} · {row.mtu} B · {row.effective_goodput_kbps.toFixed(1)} effective</span></div>)}</div></div>}</div>}
          </div>
          <div className="space-y-3 rounded-lg border border-border-color bg-bg-primary/60 p-4">
            <h4 className="m-0 text-sm">Transport truth</h4>
            <p className="m-0 text-xs text-text-muted">Handshake alone is not connected. This read-only planner requires sustained in-tunnel payload evidence and keeps advertised location separate from measured egress.</p>
            <label className="flex items-center gap-2 text-xs"><input type="checkbox" checked={truthHandshake} onChange={(e)=>setTruthHandshake(e.target.checked)} /> Handshake observed</label>
            <div className="grid grid-cols-3 gap-2"><Field label="Burst size"><input type="number" min={1} max={10000} value={truthBurstSize} onChange={(e)=>setTruthBurstSize(Math.max(1,Math.min(10000,Number(e.target.value)||1)))} className="field-input" /></Field><Field label="First burst successes"><input type="number" min={0} max={truthBurstSize} value={truthFirstBurst} onChange={(e)=>setTruthFirstBurst(Math.max(0,Math.min(truthBurstSize,Number(e.target.value)||0)))} className="field-input" /></Field><Field label="Second burst successes"><input type="number" min={0} max={truthBurstSize} value={truthSecondBurst} onChange={(e)=>setTruthSecondBurst(Math.max(0,Math.min(truthBurstSize,Number(e.target.value)||0)))} className="field-input" /></Field></div>
            <div className="grid grid-cols-2 gap-2"><Field label="Advertised country"><input value={truthAdvertisedCountry} onChange={(e)=>setTruthAdvertisedCountry(e.target.value.toUpperCase().slice(0,2))} maxLength={2} className="field-input mono" /></Field><Field label="Measured egress"><input value={truthMeasuredCountry} onChange={(e)=>setTruthMeasuredCountry(e.target.value.toUpperCase().slice(0,2))} maxLength={2} className="field-input mono" /></Field></div>
            <button type="button" onClick={()=>void runTransportTruthPlan()} disabled={transportTruthBusy} className="btn btn-secondary">{transportTruthBusy?<RefreshCw size={16} className="animate-spin"/>:<ShieldCheck size={16}/>} Classify evidence</button>
            {transportTruth && <div className="space-y-2 rounded border border-border-color p-2 text-xs"><div className="flex items-center justify-between"><span className="font-medium">{transportTruth.verdict}</span><span className={transportTruth.connected?'text-success':'text-warning'}>{transportTruth.connected?'durably connected':'not proven connected'}</span></div><div className="grid grid-cols-2 gap-2"><DataPoint label="First payload" value={`${transportTruth.first_burst_delivery_pct}%`} /><DataPoint label="Second payload" value={`${transportTruth.second_burst_delivery_pct}%`} /><DataPoint label="Advertised country" value={transportTruth.advertised_country || 'unknown'} /><DataPoint label="Measured egress" value={transportTruth.measured_egress_country || 'unmeasured'} /></div>{transportTruth.location_verdict==='mismatch' && <p className="m-0 text-warning">Measured egress disagrees with advertised metadata.</p>}<div className="space-y-1 text-[10px] text-text-muted">{transportTruth.evidence.map((line)=><div key={line}>{line}</div>)}<div>{transportTruth.safety_boundary}</div></div></div>}
          </div>
          <div className="rounded border border-border-color bg-bg-primary/50 p-3 space-y-3">
            <h4 className="m-0 text-sm">UDP/TCP DNS integrity</h4>
            <p className="m-0 text-xs text-text-muted">Compare transport-specific DNS evidence without performing DNS I/O. Answer disagreement is not poisoning unless trusted poisoning or injection evidence is supplied.</p>
            <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
              <div className="space-y-2 rounded border border-border-color p-2">
                <div className="text-xs font-semibold">UDP evidence</div>
                <div className="flex flex-wrap gap-3 text-xs"><label className="flex items-center gap-2"><input type="checkbox" checked={dnsIntegrityUDPReachable} onChange={(e)=>setDNSIntegrityUDPReachable(e.target.checked)} /> Reachable</label><label className="flex items-center gap-2"><input type="checkbox" checked={dnsIntegrityUDPPoisoned} onChange={(e)=>setDNSIntegrityUDPPoisoned(e.target.checked)} /> Trusted poisoning</label><label className="flex items-center gap-2"><input type="checkbox" checked={dnsIntegrityUDPInjected} onChange={(e)=>setDNSIntegrityUDPInjected(e.target.checked)} /> Injection observed</label></div>
                <Field label="UDP answers (IP per line or comma-separated)"><textarea rows={3} value={dnsIntegrityUDPAnswers} onChange={(e)=>setDNSIntegrityUDPAnswers(e.target.value)} className="field-input mono resize-y" /></Field>
                <Field label="UDP latency ms"><input type="number" min={0} max={600000} value={dnsIntegrityUDPLatency} onChange={(e)=>setDNSIntegrityUDPLatency(Math.max(0,Math.min(600000,Number(e.target.value)||0)))} className="field-input" /></Field>
              </div>
              <div className="space-y-2 rounded border border-border-color p-2">
                <div className="text-xs font-semibold">TCP evidence</div>
                <div className="flex flex-wrap gap-3 text-xs"><label className="flex items-center gap-2"><input type="checkbox" checked={dnsIntegrityTCPReachable} onChange={(e)=>setDNSIntegrityTCPReachable(e.target.checked)} /> Reachable</label><label className="flex items-center gap-2"><input type="checkbox" checked={dnsIntegrityTCPPoisoned} onChange={(e)=>setDNSIntegrityTCPPoisoned(e.target.checked)} /> Trusted poisoning</label><label className="flex items-center gap-2"><input type="checkbox" checked={dnsIntegrityTCPInjected} onChange={(e)=>setDNSIntegrityTCPInjected(e.target.checked)} /> Injection observed</label></div>
                <Field label="TCP answers (IP per line or comma-separated)"><textarea rows={3} value={dnsIntegrityTCPAnswers} onChange={(e)=>setDNSIntegrityTCPAnswers(e.target.value)} className="field-input mono resize-y" /></Field>
                <Field label="TCP latency ms"><input type="number" min={0} max={600000} value={dnsIntegrityTCPLatency} onChange={(e)=>setDNSIntegrityTCPLatency(Math.max(0,Math.min(600000,Number(e.target.value)||0)))} className="field-input" /></Field>
              </div>
            </div>
            <button type="button" onClick={()=>void runDNSTransportIntegrityPlan()} disabled={dnsIntegrityBusy} className="btn btn-secondary">{dnsIntegrityBusy?<RefreshCw size={16} className="animate-spin"/>:<ShieldCheck size={16}/>} Compare DNS paths</button>
            {dnsIntegrityPlan && <div className="space-y-2 rounded border border-border-color p-2 text-xs"><div className="flex items-center justify-between gap-2"><span className="font-medium">{dnsIntegrityPlan.verdict}</span><span className={dnsIntegrityPlan.poisoning_observed?'text-error':'text-text-secondary'}>{dnsIntegrityPlan.poisoning_observed?'trusted poisoning evidence':'no trusted poisoning evidence'}</span></div><div className="grid grid-cols-2 gap-2"><DataPoint label="Preferred transport" value={dnsIntegrityPlan.preferred_transport.toUpperCase()} /><DataPoint label="Answer sets" value={dnsIntegrityPlan.answer_sets_equal?'equal':'different'} /><DataPoint label="UDP normalized" value={dnsIntegrityPlan.udp_answers.join(', ') || 'none'} /><DataPoint label="TCP normalized" value={dnsIntegrityPlan.tcp_answers.join(', ') || 'none'} /></div><div className="space-y-1 text-[10px] text-text-muted">{dnsIntegrityPlan.evidence.map((line)=><div key={line}>{line}</div>)}<div>{dnsIntegrityPlan.safety_boundary}</div></div></div>}
          </div>
        </div>
      </section>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <section className="card space-y-4" aria-labelledby="tor-tools-title">
          <h3 id="tor-tools-title" className="m-0 flex items-center gap-2 border-b border-border-color pb-3 text-lg"><RefreshCw size={18} className="text-purple" /> Tor identity & onion tools</h3>
          <p className="m-0 text-sm text-text-secondary">Request a fresh Tor circuit identity or probe a v3 onion service through the active Tor engine. Optional proxy pools use deterministic same-onion affinity.</p>
          <div className="flex flex-wrap gap-2"><button type="button" onClick={() => void rotateTorIdentity()} disabled={torBusy !== null || !engines.find((engine)=>engine.id==='tor')?.running} className="btn btn-secondary">{torBusy==='rotate'?<RefreshCw size={16} className="animate-spin"/>:<RefreshCw size={16}/>} Rotate Tor identity</button></div>
          <Field label="v3 onion URL"><input value={torOnionURL} onChange={(e)=>setTorOnionURL(e.target.value)} placeholder="http://<56-char-v3-address>.onion/" className="field-input mono" /></Field>
          <Field label="SOCKS5 proxy pool (optional; one per line)"><textarea value={torProxyPool} onChange={(e)=>setTorProxyPool(e.target.value)} rows={2} placeholder="127.0.0.1:9050" className="field-input mono resize-y" /></Field>
          <button type="button" onClick={() => void probeOnion()} disabled={torBusy !== null || !torOnionURL.trim()} className="btn btn-primary">{torBusy==='probe'?<RefreshCw size={16} className="animate-spin"/>:<Activity size={16}/>} Probe onion</button>
          {torProbe && <div className="rounded-md border border-border-color bg-bg-secondary/40 p-3 text-xs"><div className="grid grid-cols-2 gap-2 md:grid-cols-3"><DataPoint label="HTTP" value={String(torProbe.status_code)} /><DataPoint label="Latency" value={`${torProbe.latency_ms.toFixed(0)} ms`} /><DataPoint label="Proxy" value={torProbe.proxy} /><DataPoint label="Sample" value={`${torProbe.sample_bytes} bytes`} /><DataPoint label="Onion links" value={String(torProbe.onion_links)} /><DataPoint label="Same service" value={String(torProbe.same_service_links)} /></div>{torProbe.title && <div className="mt-3 font-semibold text-text-primary">{torProbe.title}</div>}{torProbe.description && <div className="mt-1 text-text-secondary">{torProbe.description}</div>}{torProbe.text_sample && <pre className="mono mt-3 max-h-40 overflow-auto whitespace-pre-wrap rounded bg-bg-primary p-2 text-[10px] text-text-muted">{torProbe.text_sample.slice(0,4096)}</pre>}</div>}
        </section>

        <section className="card space-y-4" aria-labelledby="vpngate-title">
          <h3 id="vpngate-title" className="m-0 flex items-center gap-2 border-b border-border-color pb-3 text-lg"><Wifi size={18} className="text-cyan" /> VPN Gate discovery</h3>
          <p className="m-0 text-sm text-text-secondary">Browse and rank public VPN Gate servers, then hand a selected endpoint directly to LumiNet's SSTP form.</p>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-[1fr_auto]"><input value={vpnGateCountry} onChange={(e)=>setVPNGateCountry(e.target.value)} placeholder="Country name or code, e.g. JP" className="field-input" /><button type="button" onClick={() => void loadVPNGate()} disabled={vpnGateBusy} className="btn btn-secondary">{vpnGateBusy?<RefreshCw size={16} className="animate-spin"/>:<Download size={16}/>} Discover</button></div>
          {vpnGateServers.length>0 && <div className="max-h-72 overflow-auto rounded-md border border-border-color"><table className="w-full border-collapse text-left text-xs"><thead className="sticky top-0 bg-bg-secondary text-text-muted"><tr><th className="p-2">Server</th><th className="p-2">Country</th><th className="p-2">Ping</th><th className="p-2">Speed</th><th className="p-2"></th></tr></thead><tbody>{vpnGateServers.map((server)=><tr key={`${server.hostname}-${server.ip}`} className="border-t border-border-color/50"><td className="mono p-2">{server.hostname}<div className="text-[10px] text-text-muted">{server.ip}</div></td><td className="p-2">{server.country_code || server.country}</td><td className="mono p-2">{server.ping_ms>0?`${server.ping_ms} ms`:'—'}</td><td className="mono p-2">{(server.speed_bps/1_000_000).toFixed(1)} Mb/s</td><td className="p-2"><button type="button" onClick={()=>selectVPNGateSSTP(server)} className="btn btn-secondary">Use SSTP</button></td></tr>)}</tbody></table></div>}
        </section>
      </div>

      <section className="card space-y-4" aria-labelledby="sni-rank-title">
        <h3 id="sni-rank-title" className="m-0 flex items-center gap-2 border-b border-border-color pb-3 text-lg"><Gauge size={18} className="text-success" /> SNI stability ranking</h3>
        <p className="m-0 text-sm text-text-secondary">Repeat bounded SNI probes and rank candidates by stability first, then latency.</p>
        <div className="flex flex-wrap gap-2"><button type="button" onClick={()=>void loadSNICorpus()} disabled={sniRankBusy} className="btn btn-secondary"><Download size={16}/> Load 285-candidate corpus</button></div>
        <div className="grid grid-cols-1 gap-3 md:grid-cols-[1fr_120px_auto]"><input value={sniRankTarget} onChange={(e)=>setSNIRankTarget(e.target.value)} className="field-input mono" placeholder="target:443" /><input type="number" min={2} max={5} value={sniRankRuns} onChange={(e)=>setSNIRankRuns(Math.max(2,Math.min(5,Number(e.target.value)||3)))} className="field-input" /><button type="button" onClick={()=>void runSNIStability()} disabled={sniRankBusy} className="btn btn-primary">{sniRankBusy?<RefreshCw size={16} className="animate-spin"/>:<Gauge size={16}/>} Rank</button></div>
        <textarea value={sniRankCandidates} onChange={(e)=>setSNIRankCandidates(e.target.value)} rows={4} className="field-input mono resize-y" />
        {sniRankResults.length>0 && <div className="max-h-72 overflow-auto rounded-md border border-border-color"><table className="w-full border-collapse text-left text-xs"><thead className="sticky top-0 bg-bg-secondary text-text-muted"><tr><th className="p-2">SNI</th><th className="p-2">Stable</th><th className="p-2">Latency</th><th className="p-2">Score</th></tr></thead><tbody>{sniRankResults.map((row)=><tr key={row.sni} className="border-t border-border-color/50"><td className="mono p-2">{row.sni}</td><td className="p-2">{row.stability_pct}% ({row.successes}/{row.attempts})</td><td className="mono p-2">{row.avg_latency_ms} ms</td><td className="mono p-2">{row.score}</td></tr>)}</tbody></table></div>}
      </section>

      <section className="card space-y-4" aria-labelledby="devcontainer-title">
        <h3 id="devcontainer-title" className="m-0 flex items-center gap-2 border-b border-border-color pb-3 text-lg"><ServerCog size={18} className="text-purple" /> VLESS + XHTTP devcontainer</h3>
        <p className="m-0 text-sm text-text-secondary">Generate a reviewable Codespaces/devcontainer bundle with a pinned Xray release and first-class XHTTP settings. Generation is read-only; nothing is deployed automatically.</p>
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-5">
          <Field label="Client UUID"><input value={devUUID} onChange={(e)=>setDevUUID(e.target.value)} className="field-input mono" /></Field>
          <Field label="Xray version"><input value={devXrayVersion} onChange={(e)=>setDevXrayVersion(e.target.value)} className="field-input mono" /></Field>
          <Field label="Port"><input type="number" min={1} max={65535} value={devPort} onChange={(e)=>setDevPort(Number(e.target.value)||443)} className="field-input" /></Field>
          <Field label="XHTTP path"><input value={devPath} onChange={(e)=>setDevPath(e.target.value)} className="field-input mono" /></Field>
          <Field label="XHTTP mode"><select value={devMode} onChange={(e)=>setDevMode(e.target.value)} className="field-input"><option value="auto">auto</option><option value="packet-up">packet-up</option><option value="stream-up">stream-up</option><option value="stream-one">stream-one</option></select></Field>
        </div>
        <div className="flex flex-wrap gap-2"><button type="button" onClick={()=>void generateDevcontainer()} disabled={devBusy} className="btn btn-primary">{devBusy?<RefreshCw size={16} className="animate-spin"/>:<ServerCog size={16}/>} Generate bundle</button>{devBundle && <button type="button" onClick={downloadDevcontainerBundle} className="btn btn-secondary"><Download size={16}/> Download bundle JSON</button>}</div>
        {devBundle && <div className="space-y-3">{devBundle.notes.map((note)=><p key={note} className="m-0 text-xs text-text-muted">{note}</p>)}<div className="grid grid-cols-1 gap-3 xl:grid-cols-3">{devBundle.files.map((file)=><div key={file.path} className="overflow-hidden rounded-md border border-border-color bg-bg-secondary/40"><div className="mono border-b border-border-color px-3 py-2 text-xs text-accent">{file.path}</div><pre className="mono max-h-64 overflow-auto whitespace-pre-wrap p-3 text-[10px] text-text-secondary">{file.content}</pre></div>)}</div></div>}
      </section>

      <section className="card space-y-4" aria-labelledby="circumvention-catalog-title">
        <h3 id="circumvention-catalog-title" className="m-0 flex items-center gap-2 border-b border-border-color pb-3 text-lg"><ShieldCheck size={18} className="text-cyan" /> Circumvention capability catalog</h3>
        <p className="m-0 text-sm text-text-secondary">A target-native map of techniques mined from the uploaded privacy, anti-censorship and Tor catalogs. It distinguishes working LumiNet integrations from reference-only techniques.</p>
        <div className="flex flex-wrap gap-2"><button type="button" onClick={()=>void loadCircumventionCatalog()} disabled={circumventionBusy} className="btn btn-secondary">{circumventionBusy?<RefreshCw size={16} className="animate-spin"/>:<Download size={16}/>} Load catalog</button><select value={circumventionFilter} onChange={(e)=>setCircumventionFilter(e.target.value)} className="field-input w-auto"><option value="all">all</option><option value="native">native</option><option value="external-engine">external engines</option><option value="reference">reference</option></select></div>
        {visibleCircumventionCatalog.length>0 && <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">{visibleCircumventionCatalog.map((item)=><article key={item.id} className="rounded-md border border-border-color bg-bg-secondary/40 p-3"><div className="flex items-start justify-between gap-2"><div><div className="text-sm font-semibold">{item.name}</div><div className="mono text-[10px] text-text-muted">{item.category}</div></div><span className="mono rounded bg-bg-primary px-2 py-1 text-[10px] text-accent">{item.integration}</span></div><p className="mt-2 text-xs text-text-secondary">{item.description}</p>{item.operator_surface && <div className="text-[10px] text-text-muted">{item.operator_surface}</div>}{item.tags.length>0 && <div className="mt-2 flex flex-wrap gap-1">{item.tags.map((tag)=><span key={tag} className="rounded bg-bg-primary px-1.5 py-0.5 text-[9px] text-text-muted">{tag}</span>)}</div>}</article>)}</div>}
      </section>

      <section className="card space-y-5" aria-labelledby="network-characterization-title">
        <h3 id="network-characterization-title" className="m-0 flex items-center gap-2 border-b border-border-color pb-3 text-lg"><Gauge size={18} className="text-cyan" /> Network characterization</h3>
        <p className="m-0 text-sm text-text-secondary">Target-native diagnostics converged from peer mechanisms: front-aware Tor bridge reachability, real iperf3 protocol measurement, and evidence-bounded RFC5389 NAT mapping. Remote targets must resolve only to public addresses.</p>
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
          <div className="space-y-3 rounded-lg border border-border-color bg-bg-secondary/35 p-4">
            <div><div className="text-sm font-semibold text-text-primary">Tor bridge reachability</div><div className="mt-1 text-xs text-text-muted">Fronted transports probe their declared broker/front instead of placeholder bridge IPs.</div></div>
            <Field label="Bridge lines (1-64)"><textarea value={torBridgeInput} onChange={(e)=>setTorBridgeInput(e.target.value)} rows={5} placeholder="obfs4 host:port fingerprint cert=... iat-mode=0" className="field-input mono resize-y" /></Field>
            <div className="grid grid-cols-2 gap-2"><Field label="Workers"><input type="number" min={1} max={32} value={torBridgeWorkers} onChange={(e)=>setTorBridgeWorkers(Number(e.target.value))} className="field-input" /></Field><Field label="Timeout (ms)"><input type="number" min={500} max={10000} step={500} value={torBridgeTimeoutMs} onChange={(e)=>setTorBridgeTimeoutMs(Number(e.target.value))} className="field-input" /></Field></div>
            <button type="button" onClick={() => void probeTorBridges()} disabled={torBridgeBusy || !torBridgeInput.trim()} className="btn btn-secondary">{torBridgeBusy?<RefreshCw size={16} className="animate-spin"/>:<Wifi size={16}/>} Probe bridges</button>
            {torBridgeResults.length>0 && <div className="max-h-64 space-y-2 overflow-auto">{torBridgeResults.map((result,index)=><div key={`${result.raw_line}-${index}`} className="rounded border border-border-color bg-bg-primary/60 p-2 text-xs"><div className="flex items-center justify-between gap-2"><span className="font-semibold text-text-primary">{result.transport}</span><span className="mono text-accent">{result.reachability}</span></div><div className="mono mt-1 break-all text-text-muted">{result.target_host?`${result.target_host}:${result.target_port??''}`:'no direct target'}{result.latency_ms!==undefined?` · ${result.latency_ms} ms`:''}{result.fronted?' · fronted':''}</div>{result.detail&&<div className="mt-1 text-text-secondary">{result.detail}</div>}</div>)}</div>}
          </div>
          <div className="space-y-3 rounded-lg border border-border-color bg-bg-secondary/35 p-4">
            <div><div className="text-sm font-semibold text-text-primary">iperf3 throughput</div><div className="mt-1 text-xs text-text-muted">Runs the actual iperf3 client protocol. This is sustained traffic, so every run requires an explicit authorization attestation.</div></div>
            <Field label="Authorized iperf3 server"><input value={iperfAddress} onChange={(e)=>{setIperfAddress(e.target.value);setIperfAuthorization(false);}} placeholder="host.example:5201" className="field-input mono" /></Field>
            <div className="grid grid-cols-2 gap-2"><Field label="Protocol"><select value={iperfProtocol} onChange={(e)=>setIperfProtocol(e.target.value as 'tcp'|'udp')} className="field-input"><option value="tcp">TCP</option><option value="udp">UDP</option></select></Field><Field label="Duration (s)"><input type="number" min={1} max={60} value={iperfDurationSecs} onChange={(e)=>setIperfDurationSecs(Number(e.target.value))} className="field-input" /></Field><Field label="Parallel streams"><input type="number" min={1} max={16} value={iperfParallel} onChange={(e)=>setIperfParallel(Number(e.target.value))} className="field-input" /></Field>{iperfProtocol==='udp'&&<Field label="UDP bitrate (Mbps)"><input type="number" min={1} max={1000} value={iperfUDPBitrateMbps} onChange={(e)=>setIperfUDPBitrateMbps(Number(e.target.value))} className="field-input" /></Field>}</div>
            <label className="flex items-start gap-2 text-xs text-text-secondary"><input type="checkbox" checked={iperfReverse} onChange={(e)=>setIperfReverse(e.target.checked)} className="mt-0.5" /><span>Reverse direction (server sends to this host)</span></label>
            <label className="flex items-start gap-2 rounded border border-warning/30 bg-warning/10 p-2 text-xs text-text-secondary"><input type="checkbox" checked={iperfAuthorization} onChange={(e)=>setIperfAuthorization(e.target.checked)} className="mt-0.5" /><span>I confirm I control this server or have explicit permission to generate throughput-test traffic to it.</span></label>
            <button type="button" onClick={() => void runIperf()} disabled={iperfBusy || !iperfAddress.trim() || !iperfAuthorization} className="btn btn-primary">{iperfBusy?<RefreshCw size={16} className="animate-spin"/>:<Gauge size={16}/>} Run iperf3</button>
            {iperfResult&&<div className="rounded border border-border-color bg-bg-primary/60 p-3 text-xs"><div className="grid grid-cols-2 gap-2"><DataPoint label="Protocol" value={iperfResult.protocol.toUpperCase()} /><DataPoint label="Aggregate" value={`${iperfResult.bandwidth_mbps.toFixed(2)} Mbps`} /><DataPoint label="Transferred" value={`${(iperfResult.bytes_transferred/1024/1024).toFixed(2)} MiB`} /><DataPoint label="iperf" value={iperfResult.iperf_version??'unknown'} /></div><div className="mt-3 space-y-2">{iperfResult.directions.map((direction)=><div key={direction.direction} className="rounded bg-bg-secondary/55 p-2"><div className="font-semibold text-text-primary">{direction.direction}: {direction.bandwidth_mbps.toFixed(2)} Mbps</div><div className="mono mt-1 text-text-muted">{direction.retransmits!==undefined?`retransmits ${direction.retransmits}`:''}{direction.jitter_ms!==undefined?` jitter ${direction.jitter_ms.toFixed(2)} ms`:''}{direction.lost_percent!==undefined?` loss ${direction.lost_percent.toFixed(2)}%`:''}</div></div>)}</div></div>}
          </div>
          <div className="space-y-3 rounded-lg border border-border-color bg-bg-secondary/35 p-4">
            <div><div className="text-sm font-semibold text-text-primary">STUN mapping behavior</div><div className="mt-1 text-xs text-text-muted">Compares one local UDP socket across distinct RFC5389 destinations. It does not claim cone/filtering type without evidence.</div></div>
            <Field label="Primary STUN server"><input value={stunPrimary} onChange={(e)=>setSTUNPrimary(e.target.value)} placeholder="stun.example:3478" className="field-input mono" /></Field>
            <Field label="Secondary STUN server (optional)"><input value={stunSecondary} onChange={(e)=>setSTUNSecondary(e.target.value)} placeholder="optional; OTHER-ADDRESS is used when supplied" className="field-input mono" /></Field>
            <button type="button" onClick={() => void runSTUNMapping()} disabled={stunBusy || !stunPrimary.trim()} className="btn btn-secondary">{stunBusy?<RefreshCw size={16} className="animate-spin"/>:<Activity size={16}/>} Probe mapping</button>
            {stunResult&&<div className="rounded border border-border-color bg-bg-primary/60 p-3 text-xs"><div className="grid grid-cols-1 gap-2"><DataPoint label="Mapping behavior" value={stunResult.mapping_behavior} /><DataPoint label="Primary mapped" value={stunResult.primary_mapped_address} />{stunResult.secondary_mapped_address&&<DataPoint label="Secondary mapped" value={stunResult.secondary_mapped_address} />}{stunResult.other_address&&<DataPoint label="Server OTHER-ADDRESS" value={stunResult.other_address} />}</div><ul className="mb-0 mt-3 space-y-1 pl-4 text-text-secondary">{stunResult.evidence.map((line,index)=><li key={`${line}-${index}`}>{line}</li>)}</ul></div>}
          </div>
        </div>
      </section>

      <section className="card space-y-4" aria-labelledby="diag-title">
        <h3 id="diag-title" className="m-0 flex items-center gap-2 border-b border-border-color pb-3 text-lg"><Activity size={18} className="text-success" /> Diagnostic runbook</h3>
        <div className="grid grid-cols-1 gap-3 md:grid-cols-[240px_1fr_auto]">
          <select value={diagnosticType} onChange={(e) => setDiagnosticType(e.target.value)} className="field-input">
            <option value="connectivity">Connectivity</option><option value="dns">DNS</option><option value="tls">TLS</option><option value="http">HTTP</option><option value="sni">SNI</option><option value="speed">Speed</option>
          </select>
          <input value={diagnosticTarget} onChange={(e) => setDiagnosticTarget(e.target.value)} placeholder="Target host or IP" className="field-input" />
          <button type="button" onClick={() => void runDiagnostic()} disabled={diagnosticBusy} className="btn btn-primary">{diagnosticBusy ? <RefreshCw size={16} className="animate-spin" /> : <Play size={16} />} Run</button>
        </div>
        {phases.length > 0 && <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-3">{phases.map((phase) => <div key={phase.number} className="rounded-md border border-border-color bg-bg-secondary/40 p-3"><div className="mono text-[10px] text-accent">PHASE {phase.number}</div><div className="text-sm font-semibold">{phase.name}</div><div className="text-xs text-text-muted">{phase.description}</div></div>)}</div>}
        {diagnosticStatus && (
          <div className="space-y-2 rounded-md border border-border-color bg-bg-secondary/50 p-4">
            <div className="flex items-center justify-between text-sm"><span className="font-semibold uppercase text-text-primary">{diagnosticStatus.status}</span><span className="mono text-text-muted">{diagnosticStatus.progress.toFixed(0)}%</span></div>
            <div className="h-2 overflow-hidden rounded-full bg-bg-primary"><div className="h-full bg-accent transition-all" style={{ width: `${diagnosticStatus.progress}%` }} /></div>
            {diagnosticStatus.error && <p className="m-0 text-xs text-error">{diagnosticStatus.error}</p>}
            {diagnosticStatus.results !== null && diagnosticStatus.results !== undefined && <pre className="mono max-h-64 overflow-auto rounded-md bg-bg-primary p-3 text-xs text-text-secondary">{JSON.stringify(diagnosticStatus.results, null, 2)}</pre>}
          </div>
        )}
        {lastDiagnosticID && diagnosticStatus && terminalDiagnosticStates.has(diagnosticStatus.status.toLowerCase()) && <button type="button" onClick={() => void exportDiagnostic()} className="btn btn-secondary"><Download size={16} /> Export diagnostic JSON</button>}
      </section>

      <section className="card space-y-4" aria-labelledby="recovery-title">
        <div className="flex flex-col justify-between gap-3 lg:flex-row lg:items-start">
          <div>
            <p className="mono m-0 text-[10px] uppercase tracking-[0.14em] text-accent">Audited restart recovery</p>
            <h3 id="recovery-title" className="m-0 mt-1 text-lg text-text-primary">Interrupted job recovery</h3>
            <p className="m-0 mt-1 max-w-4xl text-xs text-text-muted">Nothing auto-replays on daemon boot. Only credential-free observational intents with an audited reconstruction contract can create a new descendant job, and every execution requires explicit operator confirmation. The interrupted source remains immutable.</p>
          </div>
          <button type="button" className="btn btn-secondary" disabled={recoveryBusy !== null} onClick={() => void loadRecoveryCandidates()}><RefreshCw size={15} className={recoveryBusy === 'list' ? 'animate-spin' : ''} /> Refresh interrupted</button>
        </div>
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-[minmax(0,1fr)_minmax(0,2fr)_auto] lg:items-end">
          <Field label="Recent interrupted job">
            <select className="field-input mono" value={interruptedJobs.some((job) => job.id === recoveryJobID) ? recoveryJobID : ''} onChange={(event) => { setRecoveryJobID(event.target.value); setRecoveryInfo(null); setRecoveryResult(null); }}>
              <option value="">Choose from restart-interrupted history</option>
              {interruptedJobs.map((job) => <option key={job.id} value={job.id}>{job.type} · {job.id}</option>)}
            </select>
          </Field>
          <Field label="Job ID (paste a historical ID to inspect)"><input className="field-input mono" value={recoveryJobID} onChange={(event) => { setRecoveryJobID(event.target.value); setRecoveryInfo(null); setRecoveryResult(null); }} placeholder="job id" /></Field>
          <button type="button" className="btn btn-secondary" disabled={recoveryBusy !== null || !recoveryJobID.trim()} onClick={() => void inspectRecovery()}>{recoveryBusy === 'inspect' ? <RefreshCw size={15} className="animate-spin" /> : <ShieldCheck size={15} />} Inspect recovery</button>
        </div>
        {recoveryError && <div role="alert" className="rounded-md border border-error/30 bg-error/10 p-3 text-xs text-error">{recoveryError}</div>}
        {recoveryInfo && (
          <div className="grid grid-cols-1 gap-4 rounded-md border border-border-color bg-bg-secondary/45 p-4 lg:grid-cols-[minmax(0,2fr)_minmax(240px,1fr)]">
            <div>
              <div className="flex flex-wrap gap-2">
                <span className="rounded border border-border-color bg-bg-primary px-2 py-1 text-[10px] uppercase text-text-secondary">{recoveryInfo.jobType}</span>
                <span className={`rounded border px-2 py-1 text-[10px] uppercase ${recoveryInfo.reconstructible ? 'border-success/30 bg-success/10 text-success' : 'border-warning/30 bg-warning/10 text-warning'}`}>{recoveryInfo.reconstructible ? 'reconstructible' : 'not reconstructible'}</span>
                <span className={`rounded border px-2 py-1 text-[10px] uppercase ${recoveryInfo.requeueAvailable ? 'border-accent/30 bg-accent/10 text-accent' : 'border-border-color bg-bg-primary text-text-muted'}`}>{recoveryInfo.requeueAvailable ? 'new execution available' : 'requeue blocked'}</span>
              </div>
              <p className="m-0 mt-3 text-sm text-text-primary">{recoveryInfo.reason || 'No recovery rationale returned.'}</p>
              <p className="mono m-0 mt-2 break-all text-[10px] text-text-muted">source {recoveryInfo.jobID} · policy {recoveryInfo.policy}</p>
              {recoveryInfo.activeDescendant && <p className="mono m-0 mt-1 break-all text-[10px] text-warning">active descendant {recoveryInfo.activeDescendant}</p>}
              {recoveryResult && <p className="mono m-0 mt-2 break-all rounded border border-success/30 bg-success/10 p-2 text-[10px] text-success">created {recoveryResult.jobID} from {recoveryResult.recoveredFrom} · {recoveryResult.status}</p>}
            </div>
            <div className="flex items-end">
              <button type="button" className="btn btn-primary w-full" disabled={recoveryBusy !== null || !recoveryInfo.requeueAvailable || !recoveryInfo.requiresConfirmation} onClick={() => void requeueRecovery()}>{recoveryBusy === 'requeue' ? <RefreshCw size={15} className="animate-spin" /> : <Play size={15} />} Confirm & create new execution</button>
            </div>
          </div>
        )}
        {interruptedJobs.length === 0 && recoveryBusy !== 'list' && <p className="m-0 text-xs text-text-muted">No restart-interrupted jobs are present in the retained 100-job history window. You can still paste an older job ID for read-only inspection.</p>}
      </section>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <section className="card space-y-4" aria-labelledby="update-title">
          <h3 id="update-title" className="m-0 flex items-center gap-2 border-b border-border-color pb-3 text-lg"><Download size={18} className="text-cyan" /> Signed update center</h3>
          <p className="m-0 text-sm text-text-secondary">Discover or paste a signed release envelope, inspect the transition, then download and hash-verify the exact artifact into LumiNet's staging cache.</p>
          <div className="grid grid-cols-1 gap-2 md:grid-cols-[1fr_auto]"><Field label="Signed manifest URL"><input value={updateManifestURL} onChange={(e) => setUpdateManifestURL(e.target.value)} placeholder="https://releases.example/luminet/latest.json" className="field-input mono" /></Field><button type="button" onClick={() => void discoverUpdate()} disabled={updateBusy !== null || !updateManifestURL.trim()} className="btn btn-secondary self-end">{updateBusy === 'discover' ? <RefreshCw size={16} className="animate-spin" /> : <Download size={16} />} Discover</button></div>
          <Field label="Signing key ID"><input value={updateKeyID} onChange={(e) => setUpdateKeyID(e.target.value)} className="field-input" /></Field>
          <Field label="Base64 manifest payload"><textarea value={updatePayload} onChange={(e) => setUpdatePayload(e.target.value)} rows={3} className="field-input mono resize-y" /></Field>
          <Field label="Base64 Ed25519 signature"><textarea value={updateSignature} onChange={(e) => setUpdateSignature(e.target.value)} rows={2} className="field-input mono resize-y" /></Field>
          <div className="flex flex-wrap gap-2"><button type="button" onClick={() => void runUpdateAction('plan')} disabled={updateBusy !== null} className="btn btn-secondary"><ShieldCheck size={16} /> Verify plan</button><button type="button" onClick={() => void runUpdateAction('stage')} disabled={updateBusy !== null} className="btn btn-primary">{updateBusy === 'stage' ? <RefreshCw size={16} className="animate-spin" /> : <Download size={16} />} Stage artifact</button></div>
          {updateError && <div role="alert" className="rounded-md border border-error/30 bg-error/15 p-3 text-sm text-error">{updateError}</div>}
          {updatePlan && <dl className="grid grid-cols-1 gap-3 rounded-md border border-border-color bg-bg-secondary/40 p-4 text-xs sm:grid-cols-2"><DataPoint label="Release" value={`${updatePlan.fromVersion} → ${updatePlan.version}`} /><DataPoint label="Rollback" value={updatePlan.rollbackVersion} /><DataPoint label="Release ID" value={updatePlan.releaseId} /><DataPoint label="Artifact" value={`${(updatePlan.artifactSize / 1024 / 1024).toFixed(2)} MiB`} /></dl>}
          {updateStage && <div className="rounded-md border border-success/30 bg-success/10 p-3 text-xs text-success"><div className="font-semibold">{updateStage.reused ? 'Verified staged artifact reused.' : 'Artifact downloaded and verified.'}</div><div className="mono mt-1 break-all text-text-secondary">{updateStage.path}</div><div className="mono mt-1 break-all text-text-muted">SHA-256 {updateStage.sha256}</div></div>}
        </section>

        <section className="card space-y-4" aria-labelledby="trace-title">
          <h3 id="trace-title" className="m-0 flex items-center gap-2 border-b border-border-color pb-3 text-lg"><FileJson size={18} className="text-purple" /> QLOG / NetLog viewer</h3>
          <label className="flex min-h-28 cursor-pointer flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-border-hover bg-bg-primary/50 p-4 text-center hover:border-accent">
            <Upload size={22} className="text-accent" /><span className="text-sm font-semibold">Open a local qlog, qlog-seq, or Chrome NetLog JSON file</span><span className="text-xs text-text-muted">Parsing stays in this control UI; no upload endpoint is used.</span>
            <input type="file" accept=".json,.qlog,.sqlog,application/json" className="sr-only" onChange={(e) => void loadTrace(e.target.files?.[0])} />
          </label>
          {traceError && <div role="alert" className="rounded-md border border-error/30 bg-error/15 p-3 text-sm text-error">{traceError}</div>}
          {trace && <>
            <div className="grid grid-cols-3 gap-3"><MiniStat label="Format" value={trace.format} /><MiniStat label="Events" value={String(trace.totalEvents)} /><MiniStat label="Window" value={trace.firstTime !== null && trace.lastTime !== null ? `${(trace.lastTime - trace.firstTime).toFixed(2)}` : '—'} /></div>
            <div className="flex flex-wrap gap-2">{trace.categories.slice(0, 10).map((category) => <button type="button" key={category.name} onClick={() => setTraceCategory(traceCategory === category.name ? 'all' : category.name)} className={`rounded-full border px-2 py-1 text-[10px] ${traceCategory === category.name ? 'border-accent bg-accent/10 text-accent' : 'border-border-color bg-bg-secondary text-text-secondary'}`}>{category.name} <strong className="text-text-primary">{category.count}</strong></button>)}</div>
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-[1fr_220px]"><input value={traceQuery} onChange={(e) => setTraceQuery(e.target.value)} placeholder="Filter event names or details" className="field-input" /><select value={traceCategory} onChange={(e) => setTraceCategory(e.target.value)} className="field-input"><option value="all">All categories</option>{trace.categories.map((category) => <option key={category.name} value={category.name}>{category.name} ({category.count})</option>)}</select></div>
            <div className="max-h-80 overflow-auto rounded-md border border-border-color"><table className="w-full border-collapse text-left text-xs"><thead className="sticky top-0 bg-bg-secondary text-text-muted"><tr><th className="p-2">Time</th><th className="p-2">Category</th><th className="p-2">Event</th><th className="p-2">Detail</th></tr></thead><tbody>{filteredTraceEvents.slice(0, 120).map((event, index) => <tr key={`${event.time}-${event.category}-${event.name}-${index}`} className="border-t border-border-color/50"><td className="mono p-2 text-text-muted">{event.time ?? '—'}</td><td className="p-2 text-accent">{event.category}</td><td className="p-2 font-semibold text-text-primary">{event.name}</td><td className="mono max-w-sm truncate p-2 text-text-secondary" title={event.detail}>{event.detail}</td></tr>)}</tbody></table></div>
            <p className="mono m-0 text-[10px] text-text-muted">{traceName} · {filteredTraceEvents.length}/{trace.retainedEvents.length} retained events shown after local filter</p>
          </>}
        </section>
      </div>
    </div>
  );
}


function SNIDecoyHandshakePlanner() {
  const [synSeq, setSynSeq] = useState(1000);
  const [serverSeq, setServerSeq] = useState(7000);
  const [fakeInjected, setFakeInjected] = useState(false);
  const [serverConfirmed, setServerConfirmed] = useState(false);
  const [rstSeen, setRSTSeen] = useState(false);
  const [plan, setPlan] = useState<SNIDecoyHandshakePlan | null>(null);
  const [error, setError] = useState<string | null>(null);
  async function analyze() {
    setError(null); setPlan(null);
    try {
      const next = (value:number) => (value + 1) >>> 0;
      setPlan(await controlTransport.json('/api/system/sni-decoy-handshake-plan', parseSNIDecoyHandshakePlan, {
        method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({
          syn_seen:true, syn_seq:synSeq >>> 0,
          syn_ack_seen:true, syn_ack_ack:next(synSeq), server_seq:serverSeq >>> 0,
          third_ack_seen:true, third_ack_seq:next(synSeq), third_ack_ack:next(serverSeq),
          fake_injected:fakeInjected, fake_payload_bytes:517,
          server_ack_seen:serverConfirmed, server_ack:next(synSeq), rst_seen:rstSeen,
        }),
      }));
    } catch (caught) { setError(errorMessage(caught,'SNI decoy handshake planning failed.')); }
  }
  return <div className="space-y-3 rounded-lg border border-border-color bg-bg-primary/60 p-4">
    <h4 className="m-0 text-sm">SNI decoy handshake evidence</h4>
    <p className="m-0 text-xs text-text-muted">Model exact SYN/SYN-ACK/third-ACK sequencing and server confirmation before relay. This planner captures no packets, injects no traffic, and never grants raw-packet authority.</p>
    <div className="grid grid-cols-2 gap-2"><Field label="Client SYN sequence"><input type="number" value={synSeq} onChange={(e)=>setSynSeq(Number(e.target.value)||0)} className="field-input mono" /></Field><Field label="Server SYN sequence"><input type="number" value={serverSeq} onChange={(e)=>setServerSeq(Number(e.target.value)||0)} className="field-input mono" /></Field></div>
    <div className="flex flex-wrap gap-4 text-xs text-text-muted"><label className="flex items-center gap-2"><input type="checkbox" checked={fakeInjected} onChange={(e)=>setFakeInjected(e.target.checked)} /> decoy injected</label><label className="flex items-center gap-2"><input type="checkbox" checked={serverConfirmed} onChange={(e)=>setServerConfirmed(e.target.checked)} /> server ACK observed</label><label className="flex items-center gap-2"><input type="checkbox" checked={rstSeen} onChange={(e)=>setRSTSeen(e.target.checked)} /> server RST observed</label></div>
    <button type="button" onClick={()=>void analyze()} className="btn btn-secondary"><ShieldCheck size={16}/> Classify lifecycle</button>
    {error && <p className="m-0 text-xs text-error">{error}</p>}
    {plan && <div className="space-y-1 rounded border border-border-color bg-bg-secondary/40 p-3 text-xs text-text-muted"><p className="m-0"><strong className="text-text-primary">{plan.state}</strong> · inject {plan.readyToInject?'eligible':'no'} · relay {plan.readyToRelay?'eligible':'no'}</p><p className="m-0 mono">real seq {plan.expectedRealSeq} · fake seq {plan.expectedFakeSeq} · third ACK {plan.expectedThirdACK}</p><p className="m-0">network I/O {plan.performsNetworkIO?'yes':'no'} · raw authority {plan.requiresRawPacketAuthority?'required externally':'not required'}</p>{plan.reasons.length>0 && <p className="m-0 text-warning">{plan.reasons.join(' · ')}</p>}</div>}
  </div>;
}

function GatewayCompositionPlanner() {
  const [preset, setPreset] = useState('websocket-edge');
  const [input, setInput] = useState('[{"id":"listener","role":"listener","healthy":true},{"id":"router","role":"path-router","depends_on":["listener"],"healthy":true},{"id":"reverse","role":"reverse-client","depends_on":["router"],"healthy":true},{"id":"health","role":"health","depends_on":["reverse"],"healthy":true}]');
  const [plan, setPlan] = useState<GatewayCompositionPlan | null>(null);
  const [error, setError] = useState<string | null>(null);
  async function analyze() { setError(null); setPlan(null); try { const services:unknown=preset ? undefined : JSON.parse(input); setPlan(await controlTransport.json('/api/system/gateway-composition-plan', parseGatewayCompositionPlan, { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ preset:preset || undefined, services, max_restarts:4 }) })); } catch (caught) { setError(errorMessage(caught,'Gateway composition planning failed.')); } }
  return <div className="space-y-3 rounded-lg border border-border-color bg-bg-primary/60 p-4"><h4 className="m-0 text-sm">Gateway deployment composition</h4><p className="m-0 text-xs text-text-muted">Preview target-native reverse-TLS, WebSocket-edge, or managed-edge topologies, or inspect an explicit DAG. Presets describe roles and rollback only: the planner downloads nothing and writes no service configuration; no donor installer, credentials, systemd, cron, runit, or Caddy mutation is executed.</p><Field label="Topology preset"><select value={preset} onChange={(e)=>setPreset(e.target.value)} className="field-input"><option value="websocket-edge">WebSocket edge</option><option value="reverse-tls-relay">Reverse TLS relay</option><option value="managed-edge-tunnel">Managed edge tunnel</option><option value="">Custom graph</option></select></Field>{!preset && <Field label="Service graph JSON"><textarea value={input} onChange={(e)=>setInput(e.target.value)} rows={7} className="field-input mono resize-y" /></Field>}<button type="button" onClick={()=>void analyze()} className="btn btn-secondary"><ShieldCheck size={16}/> Compose gateway</button>{error && <p className="m-0 text-xs text-error">{error}</p>}{plan && <div className="space-y-1 text-xs text-text-muted"><p className="m-0"><strong className="text-text-primary">{plan.preset || 'custom'}</strong> · start {plan.startOrder.join(' → ')}</p><p className="m-0"><strong className="text-text-primary">rollback</strong> {plan.rollbackOrder.join(' → ')}</p><p className="m-0">roles {plan.services.map((service)=>`${service.id}:${service.role}`).join(' · ')}</p><p className="m-0">downloads {plan.downloads?'yes':'no'} · writes service config {plan.writesServiceConfig?'yes':'no'} · backoff {plan.restartBackoffSeconds.join('/')}s</p></div>}</div>;
}

function WireGuardIndexTranslationPlanner() {
  const [plan, setPlan] = useState<WireGuardIndexTranslationPlan | null>(null);
  const [error, setError] = useState<string | null>(null);
  async function analyze() {
    setError(null); setPlan(null);
    const now = new Date();
    const expires = new Date(now.getTime() + 120_000);
    try { setPlan(await controlTransport.json('/api/system/wireguard-index-translation-plan', parseWireGuardIndexTranslationPlan, { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ as_of:now.toISOString(), entries:[{ source_receiver_index:7, translated_receiver_index:7007, peer_identity:'peer-preview', expires_at:expires.toISOString(), persisted:true }] }) })); }
    catch (caught) { setError(errorMessage(caught,'WireGuard index translation planning failed.')); }
  }
  return <div className="space-y-3 rounded-lg border border-border-color bg-bg-primary/60 p-4"><h4 className="m-0 text-sm">WireGuard index-translation recovery</h4><p className="m-0 text-xs text-text-muted">Check receiver-index translation, expiry, restart revalidation, and packet-authentication recomputation invariants without mutating a WireGuard packet or restoring cache state.</p><button type="button" onClick={()=>void analyze()} className="btn btn-secondary"><ShieldCheck size={16}/> Check translation contract</button>{error && <p className="m-0 text-xs text-error">{error}</p>}{plan && <div className="space-y-1 text-xs text-text-muted"><p className="m-0">read-only {plan.readOnly?'yes':'no'} · mutates packets {plan.mutatesPackets?'yes':'no'} · restores mappings {plan.restoresMappings?'yes':'no'}</p><p className="m-0">MAC recompute {plan.macRecomputeRequired?'required for live rewrite':'not required'} · persisted revalidate {plan.persistedNeedsRevalidation.join(', ') || 'none'}</p></div>}</div>;
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return <label className="block text-xs text-text-muted"><span className="mb-1 block">{label}</span>{children}</label>;
}

function DataPoint({ label, value }: { label: string; value: string }) {
  return <div><dt className="text-text-muted">{label}</dt><dd className="mono m-0 mt-1 break-all text-text-primary">{value}</dd></div>;
}

function MiniStat({ label, value }: { label: string; value: string }) {
  return <div className="rounded-md border border-border-color bg-bg-secondary/45 p-3 text-center"><div className="mono text-lg font-semibold text-text-primary">{value}</div><div className="text-[10px] uppercase tracking-wide text-text-muted">{label}</div></div>;
}
