#!/usr/bin/env python3
from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import stat
import sys
import zipfile
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INPUT = Path('/mnt/data/input')
DONOR_BASE = Path('/mnt/data/donors')
OUT = ROOT / 'governance' / 'convergence'
OUT.mkdir(parents=True, exist_ok=True)

DONORS = [
    'mhurl-main', 'Iran-configs-main', 'Iran-v2ray-rules-main',
    'JJTcpOverHttpRelayVpn-python_testing_tcp_relay', 'kcp-go-master',
    'l7mp-master', 'l7-protocols-master', 'l7-snake-main',
    'LACUNA-Chain-main', 'libkcp-master', 'libXray-main',
    'load-balancer-master', 'log-demultiplexer-master',
    'luci-app-https-dns-proxy-main', 'marionette-master',
]


def sha_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sha_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def donor_root(name: str) -> Path:
    p = DONOR_BASE / name / name
    if not p.is_dir():
        raise SystemExit(f'missing donor root: {p}')
    return p


def classify(path: str) -> tuple[str, str, str]:
    lower = path.lower()
    name = Path(path).name.lower()
    ext = Path(path).suffix.lower()
    lang = {
        '.go':'go','.rs':'rust','.py':'python','.js':'javascript','.ts':'typescript','.tsx':'typescript',
        '.c':'c','.h':'c','.cpp':'cpp','.cc':'cpp','.hpp':'cpp','.sh':'shell','.yaml':'yaml','.yml':'yaml',
        '.json':'json','.toml':'toml','.proto':'protobuf','.md':'markdown','.org':'org','.html':'html','.css':'css',
    }.get(ext, 'other')
    if name.startswith('license') or '/license' in lower:
        return 'governance', lang, 'descriptive'
    if '/.github/' in '/' + lower or lower.startswith('.github/') or name in {'.travis.yml','.drone.yml','.gitignore','.dockerignore'}:
        return 'repository-administration', lang, 'derived'
    if '/test' in lower or name.endswith('_test.go') or name.startswith('test_') or '/testing/' in '/' + lower or '/benches/' in '/' + lower:
        return 'test', lang, 'derived'
    if '/examples/' in '/' + lower or lower.startswith('examples/'):
        return 'fixture', lang, 'derived'
    if ext in {'.png','.jpg','.jpeg','.gif','.svg','.bin'}:
        return 'media', lang, 'derived'
    if '/kubernetes/' in '/' + lower or '/helm-' in '/' + lower or 'dockerfile' in name or name == 'docker-compose.yml' or '/deployment' in lower:
        return 'deployment', lang, 'authoritative'
    if '/scripts/' in '/' + lower or lower.startswith('scripts/') or ext in {'.sh','.bat'}:
        return 'script', lang, 'authoritative'
    if ext in {'.json','.yaml','.yml','.toml'} or name in {'go.mod','go.sum','cargo.toml','cargo.lock','package.json','package-lock.json','cmakelists.txt','makefile','manifest.in'}:
        return 'configuration', lang, 'authoritative'
    if ext in {'.md','.org','.rst','.txt'} and not any(x in lower for x in ['patterns/','protocols/','malware/','ir_configs']):
        return 'documentation', lang, 'descriptive'
    if any(x in lower for x in ['/htdocs/','/view/','status.js']):
        return 'ui-or-product', lang, 'authoritative'
    if ext in {'.go','.rs','.py','.js','.ts','.tsx','.c','.h','.cpp','.cc','.hpp','.proto'}:
        return 'implementation', lang, 'authoritative'
    return 'fixture', lang, 'derived'


@dataclass
class Rec:
    id: str
    donor: str
    domain: str
    value: str
    path: str
    transformation: str
    topology: str
    disposition: str
    rationale: str
    capability: str
    nodes: str
    invariant: str
    negative: str
    test: str
    operator: str = 'n/a'
    risk: str = 'low'
    parent: str = 'n/a'
    group: str = 'n/a'
    form: str = 'mechanism'
    granularity: str = 'file-or-symbol'
    separability: str = 'context-dependent'
    migration: str = 'none'
    license_note: str = 'No donor code copied unless explicitly stated; provenance retained.'
    deps: str = 'n/a'
    confidence: str = 'high'
    status: str = 'verified'
    symbol: str = 'n/a'


FOCUSED: list[Rec] = [
    Rec('MHURL001','mhurl-main','proxy-parsing','multi-authority URL semantics','url.go','guardrail derivation','negative-to-guardrail','guardrail-derived','Comma-separated URL authority conflicts with LumiNet typed endpoint ownership; preserve interoperability by rejecting ambiguity rather than forking URL syntax.','proxy share-link admission','src/apps/daemon/internal/networking/proxyconfig/types.go#rejectAmbiguousProxyAuthority','Only one network authority is admitted per share link.','Comma or literal-whitespace authority must fail before protocol parsing.','src/apps/daemon/internal/networking/proxyconfig/post_refactor_224_test.go#TestPostRefactor224RejectsAmbiguousMultiAuthority','Profiles/API parser','medium'),
    Rec('MHURL002','mhurl-main','proxy-parsing','URL parser regression cases','url_test.go','oracle extraction','one-to-one','extracted','Donor URL edge cases are useful as parser counterexamples without adopting nonstandard authority mutation.','proxy parser regression oracle','src/apps/daemon/internal/networking/proxyconfig/post_refactor_224_test.go#TestPostRefactor224RejectsAmbiguousMultiAuthority','Standard single-host and bracketed IPv6 URLs remain accepted.','Do not broaden rejection beyond ambiguous multi-authority forms.','src/apps/daemon/internal/networking/proxyconfig/post_refactor_224_test.go#TestPostRefactor224RejectsAmbiguousMultiAuthority'),

    Rec('IRCFG001','Iran-configs-main','proxy-formats','volatile proxy corpus as parser oracle','ir_configs.txt','oracle extraction','idea-to-native','extracted','Live account endpoints are volatile and credential-bearing; convert protocol diversity into synthetic credential-free regression fixtures instead of copying accounts.','proxy-format compatibility corpus','src/apps/daemon/internal/networking/proxyconfig/post_refactor_224_test.go#TestPostRefactor224CredentialFreeFormatCorpus','VMess, VLESS+Reality, Trojan, Shadowsocks, Hysteria2, TUIC and Juicity parsing remains covered.','No live account URL or credential becomes source/runtime state.','src/apps/daemon/internal/networking/proxyconfig/post_refactor_224_test.go#TestPostRefactor224CredentialFreeFormatCorpus','n/a','high'),
    Rec('IRCFG002','Iran-configs-main','secrets','live subscription/account endpoints','README.md','security rejection','negative-to-guardrail','rejected-with-reason','Repository content is an ephemeral service feed, not a safe durable product dependency.','secret/source admission','governance/convergence/post-refactor-224-security-model.md#volatile-account-rejection','Synthetic fixtures carry protocol shape only.','Never persist/copy donor account credentials into LumiNet source.','scripts/checks/check_post_refactor_224_convergence.py#check_secret_guardrails','n/a','high'),

    Rec('IRRULE001','Iran-v2ray-rules-main','routing-policy','reproducible rule generation and provenance','scripts/generate-malware-domains-ips.sh','rederivation','many-to-one','inspired-native','Generation/provenance and normalized category semantics are durable; mutable external lists are not.','routing corpus audit','src/apps/daemon/internal/analysis/diagnostics/routing_corpus_plan.go#PlanRoutingCorpus','Rule provenance, duplicate detection and combined identity are deterministic.','Planner never fetches or installs mutable external data.','src/apps/daemon/internal/analysis/diagnostics/post_refactor_224_test.go#TestPostRefactor224RoutingCorpus','Operations convergence lab','medium'),
    Rec('IRRULE002','Iran-v2ray-rules-main','routing-policy','security/direct category presets','v2rayN/template.json','synthesis','many-to-one','synthesized','Stable operator intents are useful independent of donor lists; express target-native presets rather than importing mutable rule bodies.','routing policy presets','src/apps/daemon/internal/analysis/diagnostics/routing_corpus_plan.go#RoutingPolicyPresets','Balanced-security, security-first and minimal-direct are data-free stable intents.','Presets contain no copied mutable IP/domain corpus.','src/apps/daemon/internal/analysis/diagnostics/post_refactor_224_test.go#TestPostRefactor224RoutingCorpus','Operations convergence lab','low'),
    Rec('IRRULE003','Iran-v2ray-rules-main','routing-policy','mutable IP/domain datasets and injected-IP artifacts','assets/security-jsdelivr.png','security rejection','negative-to-guardrail','rejected-with-reason','Rapidly aging external data would create misleading routing/blocking authority if embedded.','routing authority boundary','governance/convergence/post-refactor-224-security-model.md#mutable-routing-data','Routing data authority remains target-owned and freshness-aware.','Do not copy donor mutable IP/domain datasets into executable policy.','scripts/checks/check_post_refactor_224_convergence.py#check_routing_guardrails','n/a','medium'),

    Rec('JJ001','JJTcpOverHttpRelayVpn-python_testing_tcp_relay','relay-runtime','adaptive polling/resource semantics','src/proxy/tcp_tunnel.py','adaptation','many-to-one','adapted','Client-side cadence/backoff is useful without requiring donor server ownership.','HTTP relay idle polling','src/apps/daemon/internal/integrations/relayclient/adaptive_poll.go#runAdaptiveRelayPolling','Empty successful polls back off 200ms to 4s; traffic and writes restore interactive cadence.','Transport failures remain a distinct retry state.','src/apps/daemon/internal/integrations/relayclient/relay_conn_state_test.go#TestPostRefactor224AdaptiveIdlePolling','n/a','medium'),
    Rec('JJ002','JJTcpOverHttpRelayVpn-python_testing_tcp_relay','relay-runtime','server-held long polling','src/proxy/proxy_server.py','authority rejection','negative-to-guardrail','rejected-with-reason','LumiNet does not own the donor Durable Object/server contract required for 30s wait_ms semantics.','HTTP relay protocol boundary','governance/convergence/post-refactor-224-architecture.md#relay','Only client-controlled cadence is adapted.','Never claim or emit unsupported server-held long poll semantics.','scripts/checks/check_post_refactor_224_convergence.py#check_relay_guardrails','n/a','high'),
    Rec('JJ003','JJTcpOverHttpRelayVpn-python_testing_tcp_relay','tls-security','certificate-disabled probing/fronting','src/core/google_ip_scanner.py','security rejection','negative-to-guardrail','rejected-with-reason','CERT_NONE probing expands trust unsafely and contradicts LumiNet strict TLS evidence.','TLS trust boundary','governance/convergence/post-refactor-224-security-model.md#tls','TLS verification remains strict and explicit.','No certificate-disabled donor scanner is adopted.','scripts/checks/check_post_refactor_224_convergence.py#check_tls_guardrails','n/a','high'),
    Rec('JJ004','JJTcpOverHttpRelayVpn-python_testing_tcp_relay','proxy-runtime','SOCKS/codec/proxy helper stack','src/proxy/socks5.py','supersession','many-to-one','superseded','LumiNet already has typed proxy config/runtime owners and importing a second proxy stack would split authority.','proxy runtime ownership','src/apps/daemon/internal/runtime/proxy#runtime','One canonical daemon proxy runtime remains authoritative.','No parallel donor proxy server is introduced.','scripts/checks/check_post_refactor_224_convergence.py#check_single_proxy_owner','n/a','medium'),

    Rec('KCPGO001','kcp-go-master','kcp','FEC/session tuning primitives','sess.go','adaptation','many-to-one','adapted','Donor exposes proven KCP knobs; target centralizes them behind one bounded policy used by planner and real runtime.','KCP policy/runtime','src/apps/daemon/internal/networking/kcppolicy/policy.go#Resolve;src/apps/daemon/internal/runtime/proxy/kcp_transport.go#resolveKCPPolicy','Planner and runtime share one policy resolver; total FEC shards <=64.','Explicit config overrides, including zero/false, remain authoritative.','src/apps/daemon/internal/networking/kcppolicy/policy_test.go#TestLegacyAndOverrides','Operations convergence lab','high'),
    Rec('KCPGO002','kcp-go-master','kcp','socket/session controls','sess.go','extraction','many-to-one','extracted','ACK delay, write delay, windows, MTU, DSCP, socket buffers, duplication and rate controls are useful when bounded and optional.','KCP runtime controls','src/apps/daemon/internal/runtime/proxy/kcp_transport.go#applyKCPPolicy','Legacy defaults are unchanged unless profile/explicit settings request controls.','No control bypasses policy validation bounds.','src/apps/daemon/internal/runtime/proxy/kcp_policy_test.go#TestPostRefactor224KCPExplicitOverrides','n/a','high'),
    Rec('KCPGO003','kcp-go-master','kcp','AES-GCM/AEAD capability','crypt.go','residual review','one-to-one','reference-only','Donor master exposes AEAD, but exact pinned v5.6.72 API/source is unavailable locally; changing crypto would alter wire compatibility.','KCP crypto compatibility','governance/convergence/post-refactor-224-security-model.md#kcp-crypto','Legacy wire compatibility remains intact.','Do not invent an unverified pinned dependency API or silently rotate wire crypto.','scripts/checks/check_post_refactor_224_convergence.py#check_kcp_guardrails','n/a','high','n/a','kcp-policy','research','file-or-symbol','context-dependent','residual candidate'),
    Rec('KCPGO004','kcp-go-master','kcp','buffer pools/ring buffers/platform batch internals','bufferpool.go','supersession','many-to-one','superseded','These internals belong to the upstream dependency already used by LumiNet; copying them would create a fork.','dependency ownership','src/apps/daemon/go.mod#github.com/xtaci/kcp-go/v5','Upstream kcp-go remains the implementation owner for internal transport machinery.','No vendored parallel KCP internals.','scripts/checks/check_post_refactor_224_convergence.py#check_kcp_guardrails'),

    Rec('LIBKCP001','libkcp-master','kcp','KCP/FEC algorithm evidence','ikcp.c','reference synthesis','many-to-one','reference-only','C/C++ implementation corroborates KCP/FEC semantics but target runtime already depends on Go kcp-go.','KCP algorithm evidence','src/apps/daemon/internal/networking/kcppolicy/policy.go#Resolve','Target adapts policy semantics, not a second KCP implementation.','Do not add a parallel native KCP runtime.','scripts/checks/check_post_refactor_224_convergence.py#check_single_kcp_owner'),
    Rec('LIBKCP002','libkcp-master','kcp','Reed-Solomon FEC bounds/tests','fec.cpp','oracle extraction','many-to-one','inspired-native','FEC tests motivate explicit bounded shard planning independent of donor implementation.','KCP FEC admission','src/apps/daemon/internal/networking/kcppolicy/policy.go#validate','FEC data+parity <=64 and invalid pairs fail closed.','No unbounded shard allocation from configuration.','src/apps/daemon/internal/networking/kcppolicy/policy_test.go#TestFECBounds'),

    Rec('LB001','load-balancer-master','endpoint-selection','round-robin/weighted scheduling','algs/wrr.go','synthesis','many-to-many','recomposed','Weight/load concepts are useful, but must remain subordinate to LumiNet quality evidence.','endpoint selection strategy','src/apps/daemon/internal/analysis/diagnostics/endpoint_pool_plan.go#PlanEndpointPool','Secondary strategies reorder only near-equivalent candidates.','Materially worse endpoint cannot leapfrog due to weight/load/stickiness.','src/apps/daemon/internal/analysis/diagnostics/post_refactor_224_test.go#TestPostRefactor224SecondaryStrategyCannotCrossQualityBand','Operations endpoint planner','medium'),
    Rec('LB002','load-balancer-master','endpoint-selection','standalone balancing service/log stack','main.go','supersession','many-to-one','superseded','A second balancing daemon/Kafka logging stack would duplicate target authority and operations.','endpoint planner ownership','src/apps/daemon/internal/analysis/diagnostics/endpoint_pool_plan.go#PlanEndpointPool','Selection remains inside existing diagnostics/runtime owners.','No donor daemon or Kafka dependency is introduced.','scripts/checks/check_post_refactor_224_convergence.py#check_endpoint_guardrails'),

    Rec('L7MP001','l7mp-master','endpoint-selection','health/session/load-aware endpoint ownership','l7mp.js','recomposition','many-to-many','recomposed','Health/capacity/stickiness semantics strengthen target selection when bounded by existing quality ordering.','endpoint health/circuit planning','src/apps/daemon/internal/analysis/diagnostics/endpoint_pool_plan.go#PlanEndpointPool','Unhealthy, circuit-open and full-capacity endpoints are ineligible; degraded evidence is negative only.','No health/load signal can promote a materially inferior endpoint.','src/apps/daemon/internal/analysis/diagnostics/post_refactor_224_test.go#TestPostRefactor224EndpointHealthCircuitCapacity','Operations endpoint planner','high'),
    Rec('L7MP002','l7mp-master','mesh-routing','service-mesh edge freshness/health evidence','doc/l7mp_service_mesh.md','idea-to-native','idea-to-native','inspired-native','Mesh topology concepts motivate stale/unhealthy edge exclusion without importing L7MP control plane.','mesh route planning','src/apps/daemon/internal/analysis/diagnostics/mesh_route_plan.go#PlanMeshRoute','Stale/unhealthy edges are excluded; degraded edges receive bounded penalty.','Negative health evidence never creates eligibility.','src/apps/daemon/internal/analysis/diagnostics/post_refactor_224_test.go#TestPostRefactor224MeshHealthStalenessAndDegradedPenalty'),
    Rec('L7MP003','l7mp-master','privileged-network','eBPF/UDP offload fast path','kernel-offload/README.md','security rejection','negative-to-guardrail','rejected-with-reason','Privileged kernel fast path would expand deployment authority and is not required for target correctness.','privileged network boundary','governance/convergence/post-refactor-224-security-model.md#privileged-fast-path','Existing target transport owners remain sufficient.','No donor eBPF/offload authority is installed.','scripts/checks/check_post_refactor_224_convergence.py#check_privileged_guardrails','n/a','high'),
    Rec('L7MP004','l7mp-master','deployment','Kubernetes/Helm operator manifests','helm-charts/l7mp-operator/Chart.yaml','reference-only','one-to-many','reference-only','Deployment material provides operational lessons but does not map to LumiNet desktop/daemon deployment topology.','deployment evidence','governance/convergence/post-refactor-224-peer-synthesis.md#l7mp','Symlink/deployment surfaces remain fully accounted.','No Kubernetes operator is imported into LumiNet release.','scripts/checks/check_post_refactor_224_convergence.py#check_surface_evidence'),

    Rec('L7SNAKE001','l7-snake-main','mesh-routing','central health/config/status model','centraldata/centraldata.go','recomposition','many-to-one','recomposed','Health/status concepts reinforce explicit target mesh evidence; donor server/client topology is unnecessary.','mesh health planning','src/apps/daemon/internal/analysis/diagnostics/mesh_route_plan.go#PlanMeshRoute','Mesh evidence is typed and bounded.','No donor control-plane daemon is introduced.','src/apps/daemon/internal/analysis/diagnostics/post_refactor_224_test.go#TestPostRefactor224MeshHealthStalenessAndDegradedPenalty'),
    Rec('L7SNAKE002','l7-snake-main','deployment','Kubernetes chain/endpoint deployment','kubernetes/create-deployment.sh','reference-only','one-to-many','reference-only','Deployment examples are accounted as operational evidence but mismatch LumiNet product/runtime ownership.','deployment evidence','governance/convergence/post-refactor-224-peer-synthesis.md#l7-snake','No runtime authority adopted from deployment samples.','No donor Kubernetes topology is shipped.','scripts/checks/check_post_refactor_224_convergence.py#check_surface_evidence'),

    Rec('L7PROTO001','l7-protocols-master','protocol-evidence','pattern corpus admission','protocols/http.pat','adaptation','many-to-one','adapted','Protocol signatures are valuable as bounded offline evidence, not as packet-inspection authority.','offline L7 signature admission','src/apps/daemon/internal/analysis/diagnostics/l7_signature_plan.go#PlanL7Signatures','RE2-compatible compile, <=256 signatures, <=1KiB each, <=128KiB aggregate, SHA-256 identity.','No live packet capture or classifier installation.','src/apps/daemon/internal/analysis/diagnostics/post_refactor_224_test.go#TestPostRefactor224L7SignatureAdmission','Operations convergence lab','medium'),
    Rec('L7PROTO002','l7-protocols-master','protocol-evidence','malware/file signatures','malware/code_red.pat','guardrail derivation','many-to-one','reference-only','Malware corpus is useful only as classification/test evidence; live DPI would enlarge authority materially.','offline signature evidence','src/apps/daemon/internal/analysis/diagnostics/l7_signature_plan.go#PlanL7Signatures','Patterns are compiled/hashes only.','No traffic inspection/classifier install authority.','scripts/checks/check_post_refactor_224_convergence.py#check_l7_guardrails','n/a','high'),
    Rec('L7PROTO003','l7-protocols-master','protocol-evidence','pcap-like testing corpus and speed scripts','testing/doallspeeds.sh','evaluation extraction','one-to-many','reference-only','Test corpus/benchmark methodology informs regression thinking but is not production behavior.','evaluation evidence','governance/convergence/post-refactor-224-peer-synthesis.md#l7-protocols','Evaluation artifacts remain non-authoritative.','Tests do not imply runtime DPI equivalence.','scripts/checks/check_post_refactor_224_convergence.py#check_surface_evidence'),

    Rec('LOGDEMUX001','log-demultiplexer-master','events','bounded fanout/slow consumer semantics','src/demultiplexer.rs','adaptation','many-to-one','adapted','LumiNet already uses bounded transient WebSocket channels; donor insight is retained as explicit loss observability.','WebSocket backpressure observability','src/apps/daemon/internal/adapters/api/websocket.go#WebSocketStats','Broadcast queue drops and slow-client disconnections are monotonic and observable.','Telemetry does not become a second durable event source.','src/apps/daemon/internal/adapters/api/websocket_metrics_test.go#TestWebSocketBackpressureMetrics','Dashboard','medium'),
    Rec('LOGDEMUX002','log-demultiplexer-master','events','disk event persistence','src/persist.rs','supersession','many-to-one','superseded','LumiNet already persists authoritative jobs separately; another event spool would create competing truth.','event persistence ownership','src/apps/daemon/internal/application/jobs#JobManager','Durable job state remains authoritative; WebSocket remains transient.','No second disk event spool.','scripts/checks/check_post_refactor_224_convergence.py#check_websocket_guardrails','n/a','high'),
    Rec('LOGDEMUX003','log-demultiplexer-master','events','UDP/parser/demux benchmarks','benches/demultiplexer_bench.rs','evaluation extraction','one-to-many','reference-only','Benchmark organization is useful operational evidence but cannot establish target performance equivalence.','evaluation evidence','governance/convergence/post-refactor-224-peer-synthesis.md#log-demultiplexer','Performance claims require target measurements.','Donor benchmark results grant no runtime authority.','scripts/checks/check_post_refactor_224_convergence.py#check_surface_evidence'),

    Rec('LUCI001','luci-app-https-dns-proxy-main','dns','DoH provider catalogue','root/usr/share/https-dns-proxy/providers/net.quad9.json','synthesis','many-to-one','synthesized','Provider metadata is useful as explicit target presets; target keeps URLs credential-free and operator-visible.','DoH provider presets','src/apps/daemon/internal/networking/dns/doh_pool_plan.go#ResolverPoolPresets;src/apps/daemon/internal/integrations/presets/presets.go#GetDoHPresets','Quad9 secured/unsecured/secured+ECS are distinct, named presets.','No provider credential URL is embedded.','src/apps/daemon/internal/integrations/presets/presets_test.go#TestDoHPresetCatalog','Operations convergence lab','low'),
    Rec('LUCI002','luci-app-https-dns-proxy-main','dns','resolver canary/fallback/priority model','root/usr/libexec/rpcd/luci.https-dns-proxy','rederivation','many-to-one','inspired-native','Operational health/fallback concept is valuable but target planner must be read-only and fail closed on unsafe URLs.','DoH resolver evidence pool','src/apps/daemon/internal/networking/dns/doh_pool_plan.go#PlanDoHResolverPool','HTTPS-only admission, bootstrap IP validation, canary/circuit active/reserve/invalid tiers, bounded fallback.','Planner performs no DNS installation or network I/O.','src/apps/daemon/internal/networking/dns/doh_pool_plan_test.go#TestPostRefactor224DoHPool','Operations convergence lab','medium'),
    Rec('LUCI003','luci-app-https-dns-proxy-main','dns','OpenWrt install/UCI mutation authority','root/etc/uci-defaults/40_luci-https-dns-proxy','authority rejection','negative-to-guardrail','rejected-with-reason','OpenWrt-specific installer/mutation authority conflicts with LumiNet host-network ownership.','DNS mutation boundary','governance/convergence/post-refactor-224-security-model.md#dns-authority','Resolver pool remains evidence-only.','No donor installer/UCI mutation path is adopted.','scripts/checks/check_post_refactor_224_convergence.py#check_dns_guardrails','n/a','high'),

    Rec('MAR001','marionette-master','traffic-profile','versioned declarative traffic state graph','marionette/dsl.py','rederivation','idea-to-native','inspired-native','State-machine/profile concept is useful if execution authority is removed and resources are bounded.','declarative traffic profile analysis','src/apps/daemon/internal/analysis/diagnostics/traffic_profile_plan.go#PlanTrafficProfile','<=64 states, bounded actions/transitions/delay/padding/burst/overhead/timeout; graph errors surfaced.','Exec/plugin actions are not admitted or run.','src/apps/daemon/internal/analysis/diagnostics/post_refactor_224_test.go#TestPostRefactor224TrafficProfile','Operations convergence lab','medium'),
    Rec('MAR002','marionette-master','traffic-profile','traffic shaping examples/presets','examples/08_traffic_shaping.py','synthesis','many-to-one','synthesized','Examples motivate target-native interactive/balanced/bulk/bursty presets without executable DSL.','traffic profile presets','src/apps/daemon/internal/analysis/diagnostics/traffic_profile_plan.go#TrafficProfilePresets','Presets remain declarative and within resource bounds.','Presets cannot launch scripts/plugins.','src/apps/daemon/internal/analysis/diagnostics/post_refactor_224_test.go#TestPostRefactor224TrafficProfile','Operations convergence lab'),
    Rec('MAR003','marionette-master','extensions','executable plugins/updater/format actions','marionette/updater.py','security rejection','negative-to-guardrail','rejected-with-reason','Arbitrary executable extension/update authority is incompatible with LumiNet signed/hash-bound admission and single runtime ownership.','extension trust boundary','governance/convergence/post-refactor-224-security-model.md#marionette','Only non-executing graph/profile concepts survive.','No donor script/plugin/updater execution path.','scripts/checks/check_post_refactor_224_convergence.py#check_traffic_guardrails','n/a','high'),
    Rec('MAR004','marionette-master','traffic-profile','example/test lifecycle evidence','examples/tests/test_08_traffic_shaping.py','oracle extraction','one-to-many','reference-only','Examples/tests are evidence for state/profile edge cases, not proof of target behavioral equivalence.','traffic-profile test evidence','governance/convergence/post-refactor-224-peer-synthesis.md#marionette','Reference behavior informs native tests only.','Do not claim donor protocol equivalence.','scripts/checks/check_post_refactor_224_convergence.py#check_surface_evidence'),

    Rec('LACUNA001','LACUNA-Chain-main','security','call-stack spoofing/VEH/shellcode evasion','lacuna_chain.c','security rejection','negative-to-guardrail','guardrail-derived','EDR-evasion/call-stack spoofing is outside legitimate LumiNet runtime authority; review also exposed a stale target StackSpoofing export.','evasion authority guardrail','src/packages/lumicore/src/evasion/mod.rs#module_exports','Historical StackSpoofing source/export is removed.','No shellcode, VEH, stack-spoofing or EDR-bypass mechanism is operationalized.','scripts/checks/check_post_refactor_224_convergence.py#check_lacuna_guardrail','n/a','critical'),
    Rec('LACUNA002','LACUNA-Chain-main','security','shellcode samples/build flow','shellcode/msgbox.asm','security rejection','negative-to-guardrail','rejected-with-reason','Shellcode payload/build mechanics provide no acceptable target product value.','evasion authority guardrail','governance/convergence/post-refactor-224-security-model.md#lacuna','Negative evidence only.','No shellcode bytes/build recipes enter product source or release.','scripts/checks/check_post_refactor_224_convergence.py#check_lacuna_guardrail','n/a','critical'),

    Rec('LIBXRAY001','libXray-main','proxy-formats','Xray parser/wrapper protocol shape','xray/xray.go','oracle extraction','many-to-one','extracted','Protocol diversity is useful as synthetic parser regression evidence; wrapper runtime is not needed.','proxy-format compatibility corpus','src/apps/daemon/internal/networking/proxyconfig/post_refactor_224_test.go#TestPostRefactor224CredentialFreeFormatCorpus','Credential-free fixtures cover supported protocol shapes.','No donor runtime/global Xray wrapper authority is imported.','src/apps/daemon/internal/networking/proxyconfig/post_refactor_224_test.go#TestPostRefactor224CredentialFreeFormatCorpus'),
    Rec('LIBXRAY002','libXray-main','utilities','free-port/file/global-GC helper utilities','nodep/port.go','supersession','many-to-one','superseded','Target already owns port allocation, lifecycle, filesystem and core supervision; importing helpers would duplicate policy.','runtime utility ownership','src/apps/daemon/internal/runtime/proxy#runtime','Existing target utilities remain authoritative.','No donor global-GC/file/port helper becomes a second owner.','scripts/checks/check_post_refactor_224_convergence.py#check_single_proxy_owner'),
    Rec('LIBXRAY003','libXray-main','build','multi-platform wrapper/build scripts','build/main.py','reference-only','one-to-many','reference-only','Build wrappers are operational reference only; LumiNet has distinct Go/Rust/Wails/Android release ownership.','build evidence','governance/convergence/post-refactor-224-peer-synthesis.md#libxray','Build authority remains target-native.','No donor release toolchain is imported.','scripts/checks/check_post_refactor_224_convergence.py#check_surface_evidence'),
]


FOCUSED.extend([
    Rec('IRRULE004','Iran-v2ray-rules-main','routing-policy','generator configuration and category inputs','config.json','reference-only','one-to-many','reference-only','Generator configuration is useful provenance/build evidence but does not become runtime routing authority.','routing corpus provenance','src/apps/daemon/internal/analysis/diagnostics/routing_corpus_plan.go#PlanRoutingCorpus','Inputs remain auditable and normalized.','Configuration does not authorize fetching/installing donor datasets.','scripts/checks/check_post_refactor_224_convergence.py#check_surface_evidence'),
    Rec('JJ005','JJTcpOverHttpRelayVpn-python_testing_tcp_relay','relay-runtime','HTTP/H2/fronting helper stack','src/relay/h2_transport.py','supersession','many-to-one','superseded','Transport helper structure and error handling were reviewed, but LumiNet already owns both HTTP relay adapters and retry state; importing another H2/fronting stack would fork transport authority.','relay transport ownership','src/apps/daemon/internal/integrations/relayclient#relayclient','Existing target relay adapters remain sole runtime owners.','No donor H2/domain-fronting runtime or CA bypass is imported.','scripts/checks/check_post_refactor_224_convergence.py#check_relay_guardrails','n/a','high'),
    Rec('KCPGO005','kcp-go-master','kcp','autotune/entropy/SNMP instrumentation internals','autotune.go','supersession','many-to-one','superseded','These useful internals remain owned by the pinned upstream KCP dependency; target consumes stable public session controls rather than copying implementation internals.','KCP dependency ownership','src/apps/daemon/go.mod#github.com/xtaci/kcp-go/v5','Upstream implementation remains single source for KCP internals.','No copied autotune/entropy/SNMP fork.','scripts/checks/check_post_refactor_224_convergence.py#check_kcp_guardrails'),
    Rec('L7MP005','l7mp-master','endpoint-selection','listener/route/rule/session/config API model','listener.js','decomposition','one-to-many','reference-only','The donor control-plane object model was reviewed completely; only health/load/stickiness/freshness primitives fit target owners, while listener/session/config authority remains superseded.','endpoint and mesh evidence','src/apps/daemon/internal/analysis/diagnostics/endpoint_pool_plan.go#PlanEndpointPool;src/apps/daemon/internal/analysis/diagnostics/mesh_route_plan.go#PlanMeshRoute','Selected primitives are re-expressed in target-native planners.','No L7MP listener/session/OpenAPI server becomes production authority.','scripts/checks/check_post_refactor_224_convergence.py#check_endpoint_guardrails'),
    Rec('L7SNAKE003','l7-snake-main','mesh-routing','slurper/config/banner/server bootstrap surfaces','slurper/slurper.go','supersession','many-to-one','superseded','Bootstrap/config/status transport code is donor-specific control-plane glue; target preserves only typed health/freshness evidence in its existing planner.','mesh planner ownership','src/apps/daemon/internal/analysis/diagnostics/mesh_route_plan.go#PlanMeshRoute','One target planner owns mesh evidence interpretation.','No second gRPC/control-plane daemon is introduced.','scripts/checks/check_post_refactor_224_convergence.py#check_endpoint_guardrails'),
    Rec('LIBKCP003','libkcp-master','kcp','C++ session/server/build harness','kcpserver.go','reference-only','one-to-many','reference-only','Server/build/test harnesses corroborate KCP behavior but are implementation-specific and unnecessary beside target Go KCP runtime.','KCP reference evidence','governance/convergence/post-refactor-224-peer-synthesis.md#libkcp','Reference harnesses do not create runtime ownership.','No C/C++ KCP server is shipped.','scripts/checks/check_post_refactor_224_convergence.py#check_single_kcp_owner'),
    Rec('LIBXRAY004','libXray-main','proxy-formats','share-link parsers/builders','share/parse_share.go','oracle extraction','many-to-one','extracted','Share parsing/serialization examples are valuable compatibility evidence and are represented by credential-free native parser tests.','proxy share parser oracles','src/apps/daemon/internal/networking/proxyconfig/post_refactor_224_test.go#TestPostRefactor224CredentialFreeFormatCorpus','Supported protocol shapes remain covered without copying live credentials.','No donor global wrapper runtime is adopted.','src/apps/daemon/internal/networking/proxyconfig/post_refactor_224_test.go#TestPostRefactor224CredentialFreeFormatCorpus'),
    Rec('LIBXRAY005','libXray-main','runtime-utilities','platform DNS/controller/memory/download wrappers','dns/dns.go','supersession','many-to-one','superseded','Platform wrappers were reviewed but duplicate LumiNet host-network, runtime supervision and update ownership.','platform/runtime ownership','src/apps/daemon/internal#canonical-owners','Existing target platform owners remain authoritative.','No donor DNS/controller/download/global runtime becomes a parallel owner.','scripts/checks/check_post_refactor_224_convergence.py#check_single_proxy_owner','n/a','medium'),
    Rec('LB003','load-balancer-master','endpoint-selection','balancer facade/config/tests','balancer/balancer.go','oracle extraction','many-to-one','reference-only','Facade/config/tests provide comparison cases for scheduling but the standalone service architecture is superseded.','endpoint selection evidence','src/apps/daemon/internal/analysis/diagnostics/endpoint_pool_plan.go#PlanEndpointPool','Scheduling cases inform target tests only.','No independent balancer service/config authority.','src/apps/daemon/internal/analysis/diagnostics/post_refactor_224_test.go#TestPostRefactor224SecondaryStrategyCannotCrossQualityBand'),
    Rec('LOGDEMUX004','log-demultiplexer-master','events','daemon/config/parser bootstrap','src/main.rs','supersession','many-to-one','superseded','Daemon/config glue is donor-specific; only bounded fanout/backpressure insight is adapted into the existing WebSocket owner.','event fanout ownership','src/apps/daemon/internal/adapters/api/websocket.go#Hub','WebSocket hub remains transient and bounded.','No second log-demultiplexer daemon is introduced.','scripts/checks/check_post_refactor_224_convergence.py#check_websocket_guardrails'),
    Rec('LUCI004','luci-app-https-dns-proxy-main','dns','LuCI UI/menu/ACL/test surfaces','htdocs/luci-static/resources/view/https-dns-proxy/overview.js','product inspiration','one-to-many','reference-only','Status/UI/tests demonstrate operator concerns but OpenWrt UI/ACL ownership does not fit LumiNet; operator value is recomposed into the authenticated Operations planning lab.','DNS operator evidence','src/packages/control-ui/src/pages/Operations.tsx#ConvergencePolicyLab','Operator sees resolver evidence without gaining install authority.','No LuCI/RPCD ACL or UI runtime is embedded.','scripts/checks/check_post_refactor_224_convergence.py#check_dns_guardrails'),
    Rec('MAR005','marionette-master','traffic-profile','channel/record/multiplexer transport machinery','marionette/record_layer.py','supersession','many-to-one','superseded','Record/channel/multiplexer code is tightly coupled to Marionette execution and is superseded by LumiNet transport owners; only declarative profile semantics are retained.','transport ownership','src/apps/daemon/internal/runtime/proxy#runtime','Target transport/runtime remains single authority.','No donor record-layer or multiplexer runtime is imported.','scripts/checks/check_post_refactor_224_convergence.py#check_traffic_guardrails'),
    Rec('MAR006','marionette-master','traffic-profile','configuration/model-swap/unit-test corpus','marionette/tests/test_model_swapping.py','oracle extraction','one-to-many','reference-only','Unit tests and model-swap examples provide lifecycle/error counterexamples for the native analyzer, without implying protocol equivalence.','traffic profile evaluation evidence','src/apps/daemon/internal/analysis/diagnostics/traffic_profile_plan.go#PlanTrafficProfile','Native graph validation covers unreachable/dead-end/cycle/resource cases.','Reference tests do not grant executable plugin authority.','scripts/checks/check_post_refactor_224_convergence.py#check_surface_evidence'),
    Rec('L7PROTO004','l7-protocols-master','protocol-evidence','pattern grouping/build scripts','groups.sh','reference-only','one-to-many','reference-only','Grouping/build scripts are useful corpus-management evidence but do not belong in runtime admission.','offline signature corpus governance','src/apps/daemon/internal/analysis/diagnostics/l7_signature_plan.go#PlanL7Signatures','Runtime consumes only explicitly submitted bounded patterns.','No donor build/group script executes in the daemon.','scripts/checks/check_post_refactor_224_convergence.py#check_l7_guardrails'),
])

# Add donor base records so every supporting/admin/media surface has an explicit disposition.

def make_base_records(surfaces_by_donor: dict[str,list[dict]]) -> list[Rec]:
    out=[]
    for i, donor in enumerate(DONORS,1):
        surfaces=surfaces_by_donor[donor]
        candidates=[s['path'] for s in surfaces if s['type']=='file' and Path(s['path']).name.lower().startswith('readme')]
        if not candidates:
            candidates=[s['path'] for s in surfaces if s['type']=='file' and Path(s['path']).name.lower().startswith('license')]
        if not candidates:
            candidates=[s['path'] for s in surfaces if s['type']=='file']
        rep=sorted(candidates)[0]
        out.append(Rec(
            f'BASE{i:02d}',donor,'donor-accountability',f'{donor} complete supporting surface accountability',rep,
            'classification and evidence retention','one-to-many','reference-only',
            'All donor files, symlinks, tests, fixtures, build/deploy/admin/media leaves remain explicitly accounted; focused semantic records supersede this base row where mechanism-specific value exists.',
            'donor evidence accountability','governance/convergence/post-refactor-224-surface-accountability.csv#rows',
            'Every donor surface has a disposition and evidence hash.','Supporting leaves do not imply runtime adoption.',
            'scripts/checks/check_post_refactor_224_convergence.py#check_surface_evidence',risk='low',form='evidence inventory',granularity='repository',separability='context-dependent',status='verified'))
    return out

# Focus-link path rules. First matching focused records are additive; base record is always linked.
RULES: dict[str,list[tuple[re.Pattern[str],list[str]]]] = {
    'mhurl-main': [(re.compile(r'url(_test)?\.go$'),['MHURL001','MHURL002'])],
    'Iran-configs-main': [(re.compile(r'ir_configs\.txt$'),['IRCFG001']), (re.compile(r'README'),['IRCFG002'])],
    'Iran-v2ray-rules-main': [
        (re.compile(r'^scripts/generate-'),['IRRULE001']),
        (re.compile(r'^v2rayN/'),['IRRULE002']),
        (re.compile(r'^(assets/|.*(geoip|geosite|security).*)'),['IRRULE003']),
    ],
    'JJTcpOverHttpRelayVpn-python_testing_tcp_relay': [
        (re.compile(r'src/proxy/tcp_tunnel\.py|src/proxy/proxy_server\.py|src/relay/domain_fronter\.py'),['JJ001','JJ002']),
        (re.compile(r'src/core/google_ip_scanner\.py|src/proxy/mitm\.py|src/core/cert_installer\.py'),['JJ003']),
        (re.compile(r'src/proxy/(socks5|proxy_support|proxy_server|tcp_tunnel)\.py|src/core/codec\.py'),['JJ004']),
    ],
    'kcp-go-master': [
        (re.compile(r'^(sess|kcp|fec|crypt|readloop|tx_|platform_|bufferpool|ringbuffer).*'),['KCPGO001']),
        (re.compile(r'^sess\.go$'),['KCPGO002']),
        (re.compile(r'^crypt\.go$'),['KCPGO003']),
        (re.compile(r'^(bufferpool|ringbuffer|tx_|platform_|readloop).*'),['KCPGO004']),
    ],
    'libkcp-master': [
        (re.compile(r'ikcp\.(c|h)$|sess\.(cpp|h)$'),['LIBKCP001']),
        (re.compile(r'fec|reedsolomon|galois|matrix'),['LIBKCP002']),
    ],
    'load-balancer-master': [
        (re.compile(r'^algs/'),['LB001']),
        (re.compile(r'^(main\.go|log/|docker-compose|logstash)'),['LB002']),
    ],
    'l7mp-master': [
        (re.compile(r'^(l7mp\.js|l7mp-proxy\.js|stream-counter\.js|test/)'),['L7MP001']),
        (re.compile(r'doc/l7mp_service_mesh|k8s-operator/'),['L7MP002']),
        (re.compile(r'(kernel-offload|offload|ebpf|xdp)'),['L7MP003']),
        (re.compile(r'^(helm-charts/|k8s-operator/|Dockerfile)'),['L7MP004']),
    ],
    'l7-snake-main': [
        (re.compile(r'^(centraldata/|pt3status/|configchanger/|checkconfig/|server/|client/)'),['L7SNAKE001']),
        (re.compile(r'^(kubernetes/|Docker/)'),['L7SNAKE002']),
    ],
    'l7-protocols-master': [
        (re.compile(r'^(protocols/|extra/)'),['L7PROTO001']),
        (re.compile(r'(malware/|code_red)'),['L7PROTO002']),
        (re.compile(r'^testing/'),['L7PROTO003']),
    ],
    'log-demultiplexer-master': [
        (re.compile(r'src/(demultiplexer|consumers|udp_listener|parser)\.rs'),['LOGDEMUX001']),
        (re.compile(r'src/persist\.rs'),['LOGDEMUX002']),
        (re.compile(r'^benches/'),['LOGDEMUX003']),
    ],
    'luci-app-https-dns-proxy-main': [
        (re.compile(r'providers/'),['LUCI001']),
        (re.compile(r'(rpcd/luci\.https-dns-proxy|status\.js|overview\.js)'),['LUCI002']),
        (re.compile(r'(uci-defaults|Makefile|htdocs/luci-static)'),['LUCI003']),
    ],
    'marionette-master': [
        (re.compile(r'^marionette/(dsl|action|driver|format_validator)\.py'),['MAR001']),
        (re.compile(r'^examples/.*traffic|^examples/08_traffic_shaping'),['MAR002']),
        (re.compile(r'^marionette/(updater|executable)\.py|^marionette/plugins/'),['MAR003']),
        (re.compile(r'^examples/'),['MAR004']),
    ],
    'LACUNA-Chain-main': [
        (re.compile(r'(lacuna_chain\.c|lacuna_sleep\.c)'),['LACUNA001']),
        (re.compile(r'^shellcode/|build\.sh'),['LACUNA002']),
    ],
    'libXray-main': [
        (re.compile(r'^(xray/|xray_wrapper\.go|nodep/model\.go)'),['LIBXRAY001']),
        (re.compile(r'^nodep/(port|file|measure)\.go|nodep_wrapper\.go'),['LIBXRAY002']),
        (re.compile(r'^(build/|scripts/)'),['LIBXRAY003']),
    ],
}


# Second-order coverage rules for remaining implementation/test/script/deployment leaves.
RULES['Iran-v2ray-rules-main'].append((re.compile(r'^(config\.json|scripts/)'),['IRRULE004']))
RULES['JJTcpOverHttpRelayVpn-python_testing_tcp_relay'].extend([
    (re.compile(r'^(src/relay/|apps_script/|tests/|scripts/|main\.py|setup\.py|start\.)'),['JJ005']),
])
RULES['kcp-go-master'].append((re.compile(r'\.(go)$'),['KCPGO005']))
RULES['l7mp-master'].append((re.compile(r'^(config/|openapi/|cluster\.js|error\.js|listener\.js|monitoring\.js|route\.js|rule\.js|session\.js|stream\.js)'),['L7MP005']))
RULES['l7-snake-main'].append((re.compile(r'\.(go|proto)$'),['L7SNAKE003']))
RULES['libkcp-master'].append((re.compile(r'\.(go|cpp|c|h)$|CMakeLists'),['LIBKCP003']))
RULES['libXray-main'].extend([
    (re.compile(r'^share/'),['LIBXRAY004']),
    (re.compile(r'^(android_wrapper|controller/|desktop_bin/|dns/|dns_wrapper|download_geo/|geo/|memory/)'),['LIBXRAY005']),
])
RULES['load-balancer-master'].append((re.compile(r'^(balancer/|conf/|config\.yaml)'),['LB003']))
RULES['log-demultiplexer-master'].append((re.compile(r'^(src/|Cargo\.|Makefile)'),['LOGDEMUX004']))
RULES['luci-app-https-dns-proxy-main'].append((re.compile(r'^(htdocs/|tests/|root/usr/share/luci/|root/usr/share/rpcd/)'),['LUCI004']))
RULES['marionette-master'].extend([
    (re.compile(r'^marionette/(channel|channel_manual|client|conf|exceptions|multiplexer|record_layer|server)\.py|^marionette/executables/'),['MAR005']),
    (re.compile(r'^(marionette/tests/|setup\.py|MANIFEST\.in|requirements\.txt)'),['MAR006']),
])
RULES['l7-protocols-master'].append((re.compile(r'^(groups\.sh|Makefile)'),['L7PROTO004']))
RULES['JJTcpOverHttpRelayVpn-python_testing_tcp_relay'].append((re.compile(r'^src/core/|^src/proxy/__init__\.py$'),['JJ005']))
RULES['l7mp-master'].append((re.compile(r'^l7mp-openapi\.js$'),['L7MP005']))
RULES['libXray-main'].append((re.compile(r'^xray_wrapper_test\.go$'),['LIBXRAY001']))
RULES['marionette-master'].append((re.compile(r'^marionette/(?:__init__\.py|formats/)'),['MAR001','MAR006']))



def validate_and_inventory():
    all_surfaces=[]
    archive_rows=[]
    surfaces_by_donor={}
    for donor in DONORS:
        archive=INPUT/(donor+'.zip')
        root=donor_root(donor)
        if not archive.is_file(): raise SystemExit(f'missing archive {archive}')
        seen=set(); case_seen={}; unsafe=[]; archive_members={}; zip_files=0; zip_links=0; uncompressed=0
        with zipfile.ZipFile(archive) as z:
            bad=z.testzip()
            if bad: unsafe.append(f'crc:{bad}')
            for info in z.infolist():
                n=info.filename.replace('\\','/')
                if n.startswith('/') or re.match(r'^[A-Za-z]:',n): unsafe.append(f'absolute:{n}')
                parts=[p for p in n.split('/') if p not in ('','.')]
                if '..' in parts: unsafe.append(f'traversal:{n}')
                if n in seen: unsafe.append(f'duplicate:{n}')
                seen.add(n)
                cf=n.casefold()
                if cf in case_seen and case_seen[cf]!=n: unsafe.append(f'case-collision:{case_seen[cf]}:{n}')
                case_seen[cf]=n
                mode=(info.external_attr>>16)&0xFFFF
                ftype=stat.S_IFMT(mode)
                if info.is_dir(): continue
                uncompressed += info.file_size
                rel='/'.join(parts[1:]) if parts and parts[0]==donor else '/'.join(parts)
                data=z.read(info)
                if ftype==stat.S_IFLNK:
                    zip_links += 1
                    target=data.decode('utf-8')
                    # lexical confinement relative to link parent
                    norm=os.path.normpath(os.path.join(os.path.dirname(rel),target))
                    if norm=='..' or norm.startswith('../') or os.path.isabs(target): unsafe.append(f'symlink-escape:{rel}->{target}')
                    archive_members[rel]=('symlink',sha_bytes(target.encode()),len(target.encode()),target)
                else:
                    zip_files += 1
                    archive_members[rel]=('file',sha_bytes(data),len(data),'')
        if unsafe: raise SystemExit(f'unsafe archive {donor}: {unsafe[:10]}')
        tree_members={}
        for p in sorted(root.rglob('*')):
            rel=p.relative_to(root).as_posix()
            if p.is_symlink():
                target=os.readlink(p)
                tree_members[rel]=('symlink',sha_bytes(target.encode()),len(target.encode()),target)
            elif p.is_file():
                tree_members[rel]=('file',sha_file(p),p.stat().st_size,'')
        if set(archive_members)!=set(tree_members):
            miss=sorted(set(archive_members)^set(tree_members))[:20]
            raise SystemExit(f'archive/tree member mismatch {donor}: {miss}')
        for rel,a in archive_members.items():
            b=tree_members[rel]
            if a!=b: raise SystemExit(f'archive/tree byte mismatch {donor}:{rel}')
        rows=[]
        for rel,(typ,sha,size,target) in sorted(tree_members.items()):
            classification,language,authority=classify(rel)
            row={'donor':donor,'path':rel,'sha256':sha,'size_bytes':size,'type':typ,'file_type':typ,'language':language,'classification':classification,'authority_status':authority,'symlink_target':target}
            rows.append(row); all_surfaces.append(row)
        surfaces_by_donor[donor]=rows
        archive_rows.append({
            'donor':donor,'archive':archive.name,'archive_sha256':sha_file(archive),'archive_size_bytes':archive.stat().st_size,
            'regular_files':sum(r['type']=='file' for r in rows),'symlinks':sum(r['type']=='symlink' for r in rows),
            'surface_count':len(rows),'zip_crc':'pass','path_safety':'pass','case_collisions':0,'duplicate_members':0,
            'symlink_confinement':'pass','archive_tree_byte_equality':'pass','uncompressed_bytes':uncompressed,
        })
    return all_surfaces,archive_rows,surfaces_by_donor


def write_csv(path:Path,fieldnames:list[str],rows:list[dict]):
    with path.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=fieldnames,extrasaction='ignore'); w.writeheader(); w.writerows(rows)


def extract_symbols(root:Path, donor:str):
    out=[]
    pats={
      '.go':[(r'^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(', 'function'),(r'^\s*type\s+([A-Za-z_]\w*)\s+', 'type')],
      '.rs':[(r'^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_]\w*)', 'function'),(r'^\s*(?:pub\s+)?(?:struct|enum|trait|type)\s+([A-Za-z_]\w*)','type')],
      '.py':[(r'^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(', 'function'),(r'^\s*class\s+([A-Za-z_]\w*)','type')],
      '.js':[(r'^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)','function'),(r'^\s*(?:export\s+)?class\s+([A-Za-z_$][\w$]*)','type'),(r'^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(?[^=]*=>','function')],
      '.ts':[(r'^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)','function'),(r'^\s*(?:export\s+)?(?:class|interface|type|enum)\s+([A-Za-z_$][\w$]*)','type'),(r'^\s*(?:export\s+)?(?:const|let)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(?[^=]*=>','function')],
      '.tsx':[(r'^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)','function'),(r'^\s*(?:export\s+)?(?:class|interface|type|enum)\s+([A-Za-z_$][\w$]*)','type'),(r'^\s*(?:export\s+)?(?:const|let)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(?[^=]*=>','function')],
      '.c':[(r'^\s*(?:[A-Za-z_]\w*[\s\*]+)+([A-Za-z_]\w*)\s*\([^;]*\)\s*\{?\s*$', 'function'),(r'^\s*(?:typedef\s+)?struct\s+([A-Za-z_]\w*)','type')],
      '.cpp':[(r'^\s*(?:[A-Za-z_]\w*[\s\*&:<>]+)+([A-Za-z_]\w*)\s*\([^;]*\)\s*(?:const\s*)?\{?\s*$', 'function'),(r'^\s*(?:class|struct)\s+([A-Za-z_]\w*)','type')],
      '.h':[(r'^\s*(?:typedef\s+)?struct\s+([A-Za-z_]\w*)','type')],
      '.hpp':[(r'^\s*(?:class|struct)\s+([A-Za-z_]\w*)','type')],
    }
    compiled={e:[(re.compile(p),k) for p,k in ps] for e,ps in pats.items()}
    for p in sorted(root.rglob('*')):
        if not p.is_file() or p.is_symlink() or p.suffix.lower() not in compiled: continue
        rel=p.relative_to(root).as_posix()
        try: lines=p.read_text(errors='replace').splitlines()
        except Exception: continue
        for ln,line in enumerate(lines,1):
            for pat,kind in compiled[p.suffix.lower()]:
                m=pat.search(line)
                if m:
                    name=m.group(1)
                    if name in {'if','for','while','switch','return','sizeof'}: continue
                    out.append({'donor':donor,'path':rel,'line':ln,'kind':kind,'symbol':name,'surface_sha256':sha_file(p)})
                    break
    return out



# Final post-refactor-224 semantic-evidence decisions. These overrides are
# intentionally source-controlled here so regenerating the evidence cannot
# revert record-specific acceptance nodes or the pinned kcp-go AEAD decision.
# They are applied after exact donor hashes are resolved and before CSV output.
AUDITED_LEDGER_OVERRIDES = {
    'BASE01': {'test_node': 'n/a'},
    'BASE02': {'test_node': 'n/a'},
    'BASE03': {'test_node': 'n/a'},
    'BASE04': {'test_node': 'n/a'},
    'BASE05': {'test_node': 'n/a'},
    'BASE06': {'test_node': 'n/a'},
    'BASE07': {'test_node': 'n/a'},
    'BASE08': {'test_node': 'n/a'},
    'BASE09': {'test_node': 'n/a'},
    'BASE10': {'test_node': 'n/a'},
    'BASE11': {'test_node': 'n/a'},
    'BASE12': {'test_node': 'n/a'},
    'BASE13': {'test_node': 'n/a'},
    'BASE14': {'test_node': 'n/a'},
    'BASE15': {'test_node': 'n/a'},
    'IRCFG001': {'test_node': 'src/apps/daemon/internal/networking/proxyconfig/post_refactor_224_test.go#TestPostRefactor224CredentialFreeProxyFormatCorpus'},
    'IRRULE001': {'test_node': 'src/apps/daemon/internal/analysis/diagnostics/routing_corpus_plan_test.go#TestPostRefactor224RoutingCorpusAuditIsProvenanceOnly'},
    'IRRULE002': {'test_node': 'src/apps/daemon/internal/analysis/diagnostics/routing_corpus_plan_test.go#TestPostRefactor224RoutingPolicyPresetsAreStableAndDatasetFree'},
    'IRRULE004': {'test_node': 'n/a'},
    'JJ001': {'test_node': 'src/apps/daemon/internal/integrations/relayclient/relay_conn_state_test.go#TestPostRefactor224IdlePollBackoffIsIndependentBoundedAndResetsOnActivity'},
    'JJ002': {'test_node': 'scripts/checks/check_post_refactor_224_convergence.py#check_server_held_long_poll_rejection'},
    'JJ005': {'test_node': 'scripts/checks/check_post_refactor_224_convergence.py#check_relay_runtime_single_owner'},
    'KCPGO001': {'test_node': 'src/apps/daemon/internal/networking/kcppolicy/policy_test.go#TestResolveLossAdviceIsBoundedAndExplicitOverridesWin'},
    'KCPGO002': {'test_node': 'src/apps/daemon/internal/runtime/proxy/kcp_policy_test.go#TestPostRefactor224ResolveKCPPolicyPreservesExplicitZeroFalse'},
    'KCPGO003': {
        'decision_rationale': 'Exact pinned kcp-go/v5 v5.6.72 exposes NewAESGCMCrypt; LumiNet adds AES-GCM only as an explicit crypt choice while preserving all legacy cipher/default wire behavior.',
        'disposition': 'adapted',
        'invariant': 'AES-GCM is opt-in; legacy AES/CFB/default methods retain their existing semantics and identifiers.',
        'negative_invariant': 'No default crypt migration and no silent wire-compatibility break.',
        'target_capability': 'opt-in authenticated KCP packet encryption',
        'target_nodes': 'src/apps/daemon/internal/runtime/proxy/kcp_transport.go#createKCPBlockCrypt;src/apps/daemon/internal/networking/proxyconfig/post_refactor_224_test.go#TestPostRefactor224KCPAESGCMMethodRoundTrip',
        'test_node': 'src/apps/daemon/internal/runtime/proxy/kcp_policy_test.go#TestPostRefactor224KCPAESGCMIsOptIn',
        'transformation': 'adaptation',
        'validation_status': 'statically-validated',
    },
    'KCPGO004': {'test_node': 'scripts/checks/check_post_refactor_224_convergence.py#check_kcp_upstream_implementation_ownership'},
    'KCPGO005': {'test_node': 'scripts/checks/check_post_refactor_224_convergence.py#check_kcp_upstream_instrumentation_ownership'},
    'L7MP001': {'test_node': 'src/apps/daemon/internal/analysis/diagnostics/endpoint_pool_plan_test.go#TestPostRefactor224EndpointHealthCircuitAndCapacityAdmission'},
    'L7MP002': {'test_node': 'src/apps/daemon/internal/analysis/diagnostics/mesh_route_plan_test.go#TestPostRefactor224MeshHealthStalenessAndDegradedPenalty'},
    'L7MP004': {'test_node': 'n/a'},
    'L7MP005': {'test_node': 'n/a'},
    'L7PROTO001': {'test_node': 'src/apps/daemon/internal/analysis/diagnostics/l7_signature_plan_test.go#TestPostRefactor224L7AdmissionIsBoundedOfflineAndIndividual'},
    'L7PROTO002': {'test_node': 'n/a'},
    'L7PROTO003': {'test_node': 'n/a'},
    'L7PROTO004': {'test_node': 'n/a'},
    'L7SNAKE001': {'test_node': 'src/apps/daemon/internal/analysis/diagnostics/mesh_route_plan_test.go#TestPostRefactor224MeshTypedHealthEvidenceIsBounded'},
    'L7SNAKE002': {'test_node': 'n/a'},
    'L7SNAKE003': {'test_node': 'scripts/checks/check_post_refactor_224_convergence.py#check_mesh_control_plane_supersession'},
    'LACUNA002': {'test_node': 'scripts/checks/check_post_refactor_224_convergence.py#check_shellcode_release_exclusion'},
    'LB001': {'test_node': 'src/apps/daemon/internal/analysis/diagnostics/endpoint_pool_plan_test.go#TestPostRefactor224SecondaryStrategiesCannotCrossQualityBand'},
    'LB002': {'test_node': 'scripts/checks/check_post_refactor_224_convergence.py#check_balancer_service_supersession'},
    'LB003': {'test_node': 'n/a'},
    'LIBKCP001': {'test_node': 'n/a'},
    'LIBKCP002': {'test_node': 'src/apps/daemon/internal/networking/kcppolicy/policy_test.go#TestResolveAdaptiveFECNeverExceedsShardCeiling'},
    'LIBKCP003': {'test_node': 'n/a'},
    'LIBXRAY001': {'test_node': 'src/apps/daemon/internal/networking/proxyconfig/post_refactor_224_test.go#TestPostRefactor224LibXrayProtocolShapeSubset'},
    'LIBXRAY002': {'test_node': 'scripts/checks/check_post_refactor_224_convergence.py#check_libxray_helper_supersession'},
    'LIBXRAY003': {'test_node': 'n/a'},
    'LIBXRAY004': {'test_node': 'src/apps/daemon/internal/networking/proxyconfig/post_refactor_224_test.go#TestPostRefactor224ShareLinkParsersRoundTripCredentialFreeSamples'},
    'LIBXRAY005': {
        'target_nodes': 'src/apps/daemon/internal/platform/system/host_network.go#hostNetworkManager;src/apps/daemon/internal/runtime/proxy/core_manager.go#CoreManager',
        'test_node': 'scripts/checks/check_post_refactor_224_convergence.py#check_libxray_platform_supersession',
    },
    'LOGDEMUX001': {'test_node': 'src/apps/daemon/internal/adapters/api/websocket_metrics_test.go#TestHubBackpressureStatsCountBroadcastDropsAndSlowClients'},
    'LOGDEMUX002': {
        'target_nodes': 'src/apps/daemon/internal/workflows/jobs/manager.go#JobManager',
        'test_node': 'scripts/checks/check_post_refactor_224_convergence.py#check_job_persistence_single_owner',
    },
    'LOGDEMUX003': {'test_node': 'n/a'},
    'LOGDEMUX004': {'test_node': 'scripts/checks/check_post_refactor_224_convergence.py#check_logdemux_daemon_supersession'},
    'LUCI001': {'test_node': 'src/apps/daemon/internal/integrations/presets/presets_test.go#TestPostRefactor224Quad9DoHVariantsRemainDistinct'},
    'LUCI002': {'test_node': 'src/apps/daemon/internal/networking/dns/doh_pool_plan_test.go#TestPostRefactor224ResolverPoolAdmissionCircuitsAndOrdering'},
    'LUCI003': {'test_node': 'scripts/checks/check_post_refactor_224_convergence.py#check_dns_mutation_rejection'},
    'LUCI004': {'test_node': 'n/a'},
    'MAR001': {'test_node': 'src/apps/daemon/internal/analysis/diagnostics/traffic_profile_plan_test.go#TestPostRefactor224TrafficProfileAnalysisAndPresets'},
    'MAR002': {'test_node': 'src/apps/daemon/internal/analysis/diagnostics/traffic_profile_plan_test.go#TestPostRefactor224TrafficBehaviorPresetsStayDeclarativeAndBounded'},
    'MAR003': {'test_node': 'src/apps/daemon/internal/analysis/diagnostics/traffic_profile_plan_test.go#TestPostRefactor224TrafficProfileRejectsExecutableAction'},
    'MAR004': {'test_node': 'n/a'},
    'MAR005': {'test_node': 'scripts/checks/check_post_refactor_224_convergence.py#check_marionette_transport_supersession'},
    'MAR006': {'test_node': 'n/a'},
    'MHURL001': {'test_node': 'src/apps/daemon/internal/networking/proxyconfig/post_refactor_224_test.go#TestPostRefactor224RejectsAmbiguousMultiAuthorityAndPreservesIPv6'},
    'MHURL002': {'test_node': 'src/apps/daemon/internal/networking/proxyconfig/post_refactor_224_test.go#TestPostRefactor224StandardSingleAuthorityRegressionCases'},
}

def apply_audited_ledger_overrides(ledger: list[dict]) -> None:
    by_id = {row['record_id']: row for row in ledger}
    missing = sorted(set(AUDITED_LEDGER_OVERRIDES) - set(by_id))
    if missing:
        raise SystemExit(f'audited override records missing: {missing}')
    for record_id, fields in AUDITED_LEDGER_OVERRIDES.items():
        row = by_id[record_id]
        unknown = sorted(set(fields) - set(row))
        if unknown:
            raise SystemExit(f'audited override fields missing for {record_id}: {unknown}')
        row.update(fields)
    reference_with_test = sorted(row['record_id'] for row in ledger if row['disposition'] == 'reference-only' and row['test_node'] != 'n/a')
    non_reference_without_test = sorted(row['record_id'] for row in ledger if row['disposition'] != 'reference-only' and row['test_node'] == 'n/a')
    if reference_with_test or non_reference_without_test:
        raise SystemExit(f'invalid semantic test-node contract: reference_with_test={reference_with_test} non_reference_without_test={non_reference_without_test}')


def main():
    surfaces, archive_rows, bydonor=validate_and_inventory()
    base=make_base_records(bydonor)
    recs=base+FOCUSED
    rec_by_id={r.id:r for r in recs}
    if len(rec_by_id)!=len(recs): raise SystemExit('duplicate semantic record id')
    base_id={r.donor:r.id for r in base}

    # validate representative paths and fill exact donor hashes
    surface_index={(r['donor'],r['path']):r for r in surfaces}
    ledger=[]
    for r in recs:
        s=surface_index.get((r.donor,r.path))
        if not s: raise SystemExit(f'ledger representative missing: {r.id} {r.donor}:{r.path}')
        ledger.append({
            'record_id':r.id,'parent_record_id':r.parent,'composition_group_id':r.group if r.group!='n/a' else r.capability.replace(' ','-').lower(),
            'donor':r.donor,'domain':r.domain,'value_unit':r.value,'source_granularity':r.granularity,'value_form':r.form,
            'separability':r.separability,'donor_path':r.path,'donor_sha256':s['sha256'],'donor_symbol':r.symbol,
            'transformation':r.transformation,'mapping_topology':r.topology,'disposition':r.disposition,'decision_rationale':r.rationale,
            'target_capability':r.capability,'target_nodes':r.nodes,'invariant':r.invariant,'negative_invariant':r.negative,
            'test_node':r.test,'operator_surface':r.operator,'migration_impact':r.migration,'license_note':r.license_note,
            'risk_tier':r.risk,'dependency_record_ids':r.deps,'evidence_confidence':r.confidence,'validation_status':r.status,
        })

    apply_audited_ledger_overrides(ledger)

    # Surface links and explicit surface-level disposition/rationale.
    surf_rows=[]
    focused_count=0
    for s in surfaces:
        links=[base_id[s['donor']]]
        for pat,ids in RULES.get(s['donor'],[]):
            if pat.search(s['path']):
                links.extend(ids)
        links=list(dict.fromkeys(links))
        focused=[x for x in links if not x.startswith('BASE')]
        if focused: focused_count+=1
        # strongest disposition = first focused; else reference/support
        if focused:
            fr=rec_by_id[focused[0]]
            disp=fr.disposition
            rationale=fr.rationale
        else:
            disp='reference-only'
            rationale='Supporting/package/admin/media/fixture leaf is explicitly retained in donor accountability; no independent target mechanism is justified beyond its donor/context record.'
        surf_rows.append({**s,
            'semantic_record_ids':';'.join(links),
            'surface_disposition':disp,
            'surface_rationale':rationale,
            'notes':'Focused semantic link(s) plus base accountability.' if focused else 'Explicit supporting leaf; base donor evidence only.',
        })

    # Directory/subdirectory Merkle-like accountability.
    dir_rows=[]
    for donor in DONORS:
        rows=[r for r in surf_rows if r['donor']==donor]
        dirs={'.'}
        for r in rows:
            pp=Path(r['path']).parent
            while str(pp) not in ('','.'):
                dirs.add(pp.as_posix()); pp=pp.parent
        for d in sorted(dirs):
            prefix='' if d=='.' else d.rstrip('/')+'/'
            desc=[r for r in rows if d=='.' or r['path'].startswith(prefix)]
            payload=''.join(f"{r['path']}\0{r['sha256']}\0{r['type']}\n" for r in sorted(desc,key=lambda x:x['path'])).encode()
            direct=set()
            for r in desc:
                rel=r['path'][len(prefix):] if prefix else r['path']
                if '/' not in rel: direct.add(r['path'])
            dir_rows.append({'donor':donor,'directory':d,'descendant_surfaces':len(desc),'direct_surfaces':len(direct),'tree_sha256':sha_bytes(payload),'semantic_record_ids':';'.join(sorted(set(x for r in desc for x in r['semantic_record_ids'].split(';'))))})

    symbols=[]
    for donor in DONORS: symbols.extend(extract_symbols(donor_root(donor),donor))
    # Add semantic links from exact surface matrix.
    slinks={(r['donor'],r['path']):r['semantic_record_ids'] for r in surf_rows}
    for x in symbols: x['semantic_record_ids']=slinks.get((x['donor'],x['path']),'')

    write_csv(OUT/'post-refactor-224-archive-accountability.csv',list(archive_rows[0]),archive_rows)
    write_csv(OUT/'post-refactor-224-surface-accountability.csv',list(surf_rows[0]),surf_rows)
    write_csv(OUT/'post-refactor-224-directories.csv',list(dir_rows[0]),dir_rows)
    write_csv(OUT/'post-refactor-224-symbols.csv',list(symbols[0]) if symbols else ['donor','path','line','kind','symbol','surface_sha256','semantic_record_ids'],symbols)
    write_csv(OUT/'post-refactor-224-adoption-ledger.csv',list(ledger[0]),ledger)

    summary={
        'release':'post-refactor-224','donor_archives':len(archive_rows),'surfaces':len(surf_rows),
        'regular_files':sum(r['type']=='file' for r in surf_rows),'symlinks':sum(r['type']=='symlink' for r in surf_rows),
        'directories':len(dir_rows),'symbols':len(symbols),'semantic_records':len(ledger),'focused_surfaces':focused_count,
        'supporting_surfaces':len(surf_rows)-focused_count,'archive_validation':'verified','archive_tree_byte_equality':'verified',
    }
    (OUT/'post-refactor-224-evidence-summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
    print(json.dumps(summary,sort_keys=True))

if __name__=='__main__': main()
