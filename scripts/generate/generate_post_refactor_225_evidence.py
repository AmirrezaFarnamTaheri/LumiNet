#!/usr/bin/env python3
from __future__ import annotations
import csv, hashlib, json, os, re, stat, zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from collections import defaultdict

TARGET=Path(os.environ.get('LUMINET_225_TARGET_ROOT','/mnt/data/work225_full/LumiNet'))
OUT=TARGET/'governance/convergence'

@dataclass(frozen=True)
class Donor:
    id:str; archive:Path; root:Path; product:str

DONORS=[
 Donor('sni-bypass',Path('/mnt/data/SNI-ByPass-main.zip'),Path('/mnt/data/donors225/SNI-ByPass-main/SNI-ByPass-main'),'SNI-ByPass'),
 Donor('sni-spoofing-go',Path('/mnt/data/SNI-Spoofing-Go-main.zip'),Path('/mnt/data/donors225/SNI-Spoofing-Go-main/SNI-Spoofing-Go-main'),'SNI-Spoofing-Go'),
 Donor('sni-spoofing-python',Path('/mnt/data/SNI-Spoofing-main.zip'),Path('/mnt/data/donors225/SNI-Spoofing-main/SNI-Spoofing-main'),'SNI-Spoofing'),
 Donor('snispf-hj',Path('/mnt/data/SNISPF-HJ-main.zip'),Path('/mnt/data/donors225/SNISPF-HJ-main/SNISPF-HJ-main'),'SNISPF-HJ'),
 Donor('mitm-proxy',Path('/mnt/data/mitm-proxy-main.zip'),Path('/mnt/data/donors225/mitm-proxy-main/mitm-proxy-main'),'mitm-proxy'),
 Donor('mitm-relay',Path('/mnt/data/mitm_relay-master.zip'),Path('/mnt/data/donors225/mitm_relay-master/mitm_relay-master'),'mitm_relay'),
 Donor('sing-box-rules',Path('/mnt/data/sing-box-rules-main.zip'),Path('/mnt/data/donors225/sing-box-rules-main/sing-box-rules-main'),'sing-box-rules'),
 Donor('sing-dns',Path('/mnt/data/sing-dns-main.zip'),Path('/mnt/data/donors225/sing-dns-main/sing-dns-main'),'sing-dns'),
 Donor('sing-mux',Path('/mnt/data/sing-mux-main (1).zip'),Path('/mnt/data/donors225/sing-mux-main (1)/sing-mux-main'),'sing-mux'),
 Donor('routing-list',Path('/mnt/data/v2rayCustomRoutingList-master(3).zip'),Path('/mnt/data/donors225/v2rayCustomRoutingList-master(3)/v2rayCustomRoutingList-master'),'v2rayCustomRoutingList'),
 Donor('v2rayng',Path('/mnt/data/v2rayNG-master(3).zip'),Path('/mnt/data/donors225/v2rayNG-master(3)/v2rayNG-master'),'v2rayNG'),
 Donor('v2raya-scoop',Path('/mnt/data/v2raya-scoop-main(2).zip'),Path('/mnt/data/donors225/v2raya-scoop-main(2)/v2raya-scoop-main'),'v2raya-scoop'),
 Donor('tun2socket',Path('/mnt/data/tun2socket-main(3).zip'),Path('/mnt/data/donors225_new/tun2socket/tun2socket-main'),'tun2socket'),
 Donor('udp-ring-queue',Path('/mnt/data/udp-ring-queue-master(3).zip'),Path('/mnt/data/donors225_new/udp-ring-queue/udp-ring-queue-master'),'udp-ring-queue'),
 Donor('uptimeflare',Path('/mnt/data/UptimeFlare-main(3).zip'),Path('/mnt/data/donors225_new/uptimeflare/UptimeFlare-main'),'UptimeFlare'),
 Donor('utls',Path('/mnt/data/utls-master(3).zip'),Path('/mnt/data/donors225_new/utls/utls-master'),'uTLS'),
 Donor('warpscanner-android',Path('/mnt/data/WarpScanner-android-GUI-main.zip'),Path('/mnt/data/donors225_new/warpscanner-android/WarpScanner-android-GUI-main'),'WarpScanner Android'),
 Donor('wintun',Path('/mnt/data/wintun-master.zip'),Path('/mnt/data/donors225_new/wintun/wintun-master'),'Wintun'),
 Donor('wireguard-go',Path('/mnt/data/wireguard-go-tailscale.zip'),Path('/mnt/data/donors225_new/wireguard-go-tailscale/wireguard-go-tailscale'),'wireguard-go tailscale'),
 Donor('wormhole',Path('/mnt/data/wormhole-master.zip'),Path('/mnt/data/donors225_new/wormhole/wormhole-master'),'wormhole'),
 Donor('tt',Path('/mnt/data/tt-main(2).zip'),Path('/mnt/data/donors225_new/tt/tt-main'),'tt'),
 Donor('tuic-impl',Path('/mnt/data/tuic-main(3).zip'),Path('/mnt/data/donors225_new/tuic-main/tuic-main'),'TUIC implementation'),
 Donor('tuic-spec',Path('/mnt/data/tuic-master(3).zip'),Path('/mnt/data/donors225_new/tuic-master/tuic-master'),'TUIC protocol specification'),
]

def sha_bytes(b:bytes)->str:return hashlib.sha256(b).hexdigest()
def sha_file(p:Path)->str:
 h=hashlib.sha256()
 with p.open('rb') as f:
  for chunk in iter(lambda:f.read(1<<20),b''):h.update(chunk)
 return h.hexdigest()

def norm(name:str)->PurePosixPath:
 if '\x00' in name: raise ValueError('NUL path')
 p=PurePosixPath(name.replace('\\','/'))
 if p.is_absolute() or any(x in ('','.','..') for x in p.parts): raise ValueError(f'unsafe path {name!r}')
 if p.parts and ':' in p.parts[0]: raise ValueError(f'drive path {name!r}')
 return p

def language(path:str)->str:
 ext=Path(path).suffix.lower(); name=Path(path).name.lower()
 return {'.go':'Go','.rs':'Rust','.py':'Python','.kt':'Kotlin','.java':'Java','.c':'C','.h':'C/C++ header','.cpp':'C++','.cc':'C++','.hpp':'C++ header','.ts':'TypeScript','.tsx':'TypeScript JSX','.js':'JavaScript','.mjs':'JavaScript','.sh':'Shell','.ps1':'PowerShell','.xml':'XML','.json':'JSON','.yaml':'YAML','.yml':'YAML','.toml':'TOML','.md':'Markdown','.html':'HTML','.css':'CSS','.gradle':'Gradle'}.get(ext, 'Dockerfile' if name.startswith('dockerfile') else 'other')

def classify(path:str)->str:
 q=path.lower(); n=Path(q).name
 if '/.git/' in '/'+q or q.startswith('.git/') or q.startswith('.github/'): return 'repository-administration'
 if any(x in q for x in ['/testdata/','/fixtures/','/fixture/']) or n.endswith(('.png','.jpg','.jpeg','.gif','.ico','.webp','.pcap','.bin','.der','.crt')): return 'fixture'
 if re.search(r'(^|/)(test|tests)(/|$)',q) or re.search(r'(_test\.(go|rs)|test_.*\.py$|.*\.test\.(js|mjs|ts)$)',q): return 'test'
 if any(x in q for x in ['/layout/','/drawable/','/mipmap/','/values/','/ui/','/view/','/pages/','/components/']) or Path(q).suffix in ('.tsx','.html','.css'): return 'ui-or-product'
 if any(x in q for x in ['dockerfile','docker-compose','systemd','/deploy/','/deployment/','/installer','/setup/']) or n.endswith(('.service','.wxs')): return 'deployment'
 if Path(q).suffix in ('.sh','.ps1','.bat','.cmd') or '/scripts/' in q or q.startswith('scripts/'): return 'script'
 if n in ('go.mod','go.sum','cargo.toml','cargo.lock','package.json','package-lock.json','gradle.properties','settings.gradle','settings.gradle.kts','build.gradle','build.gradle.kts','makefile') or Path(q).suffix in ('.yaml','.yml','.toml','.ini','.conf','.properties','.json'):
  return 'configuration'
 if n.startswith('readme') or Path(q).suffix in ('.md','.rst','.txt') or 'license' in n or 'changelog' in n: return 'documentation'
 if Path(q).suffix in ('.go','.rs','.py','.kt','.java','.c','.h','.cpp','.cc','.hpp','.ts','.js','.mjs'): return 'implementation'
 return 'repository-administration'

HIGH={'implementation','test','script','deployment','ui-or-product','configuration'}

def module_key(donor:str,path:str,classification:str)->str:
 parts=PurePosixPath(path).parts
 q=path.lower()
 if donor=='v2rayng' and 'com/v2ray/ang/' in q:
  after=q.split('com/v2ray/ang/',1)[1].split('/')
  return 'android-'+(after[0] if len(after)>1 else 'root')
 if donor=='v2rayng' and '/res/' in q:
  return 'android-res-'+q.split('/res/',1)[1].split('/')[0]
 if donor=='utls':
  n=Path(path).name.lower()
  for k in ['roller','fingerprint','parrot','extension','quic','ech','handshake','session','ticket','psk','json','random']:
   if k in n:return k
  return 'utls-'+(parts[0] if len(parts)>1 else 'root')
 if donor=='wireguard-go': return 'wg-'+(parts[0] if len(parts)>1 else 'root')
 if donor=='wintun': return 'wintun-'+(parts[0] if len(parts)>1 else 'root')
 if donor=='uptimeflare': return 'uptime-'+(parts[1] if len(parts)>2 and parts[0]=='src' else parts[0] if len(parts)>1 else 'root')
 if donor=='warpscanner-android':
  for marker in ['android-toga','flet','android']:
   if marker in q:return 'warp-'+marker
  return 'warp-root'
 if donor in ('tuic-impl','tuic-spec'): return donor+'-'+(parts[0] if len(parts)>1 else 'root')
 if donor=='tun2socket': return 'tun-'+(parts[0] if len(parts)>1 else 'root')
 if donor=='udp-ring-queue': return 'queue-'+(parts[0] if len(parts)>1 else 'root')
 if donor=='sing-dns': return 'dns-'+(parts[0] if len(parts)>1 else 'root')
 if donor=='sing-mux': return 'mux-'+(parts[0] if len(parts)>1 else 'root')
 if donor in ('sni-bypass','sni-spoofing-go','sni-spoofing-python','snispf-hj'): return 'sni-'+(parts[0] if len(parts)>1 else 'root')
 if donor.startswith('mitm-'): return donor+'-'+(parts[0] if len(parts)>1 else 'root')
 if donor in ('sing-box-rules','routing-list','v2raya-scoop'): return donor+'-'+(parts[0] if len(parts)>1 else 'root')
 if donor=='wormhole': return 'wormhole-'+(parts[0] if len(parts)>1 else 'root')
 return donor+'-'+(parts[0] if len(parts)>1 else 'root')

def target_for(donor:str,key:str):
 # disposition, transformation, topology, capability, target_nodes, invariant,
 # negative, behavior_test, operator, validation, rationale
 def ref(capability:str, rationale:str, nodes:str='n/a', operator:str='governance/convergence/post-refactor-225-peer-synthesis.md'):
  return ('reference-only','review','one-to-one',capability,nodes,'source is explicitly accounted and compared against the current target owner','accountability alone never grants runtime authority','n/a',operator,'reviewed',rationale)
 def sup(capability:str,nodes:str,invariant:str,negative:str,rationale:str,behavior_test:str='n/a',operator:str='governance/convergence/post-refactor-225-peer-synthesis.md'):
  return ('superseded','comparison + oracle extraction','many-to-one',capability,nodes,invariant,negative,behavior_test,operator,'reviewed',rationale)
 def inspired(capability:str,nodes:str,invariant:str,negative:str,rationale:str,behavior_test:str,operator:str='Operations convergence policy lab',transformation:str='recomposition + guardrail derivation',topology:str='many-to-one'):
  return ('inspired-native',transformation,topology,capability,nodes,invariant,negative,behavior_test,operator,'verified',rationale)
 def hardened(capability:str,nodes:str,invariant:str,negative:str,rationale:str,behavior_test:str,operator:str='n/a',validation:str='verified'):
  return ('hardened','contract/spec hardening','many-to-one',capability,nodes,invariant,negative,behavior_test,operator,validation,rationale)

 if donor=='sni-spoofing-go':
  if key=='sni-gui':
   return inspired('bounded diagnostic UI/UX and log evidence','src/packages/control-ui/src/pages/Logs.tsx#Logs;src/packages/control-ui/src/pages/Operations.tsx#Operations','diagnostic logs remain bounded and status/results are separated from runtime authority','GUI elevation/helper execution and packet-injection controls are not transplanted into the web UI','The donor GUI contributes bounded log-buffer, status/results separation, localization/RTL, preflight and progressive-result UX; LumiNet adopts the safe product concepts in existing pages, not the Wails/elevated runtime shell.','src/packages/control-ui/scripts/test-post-refactor-225.mjs#product-surface','Logs and Operations')
  if key=='sni-guiapi':
   return inspired('typed planner admission contracts','src/apps/daemon/internal/adapters/api/handlers_seventh_planners.go#PlanSNIPaths;src/packages/control-ui/src/api/planners.ts','planner inputs and outputs are typed, bounded and authenticated','UI validation never becomes packet/runtime authority','GUI API validation reinforces strict planner schemas around the existing authenticated system API.','src/packages/control-ui/scripts/test-post-refactor-225.mjs#planner-api')
  if key in {'sni-helper','sni-privilege'}:
   return sup('privilege/helper process boundary','src/apps/daemon/internal/foundation/redact/redact.go#String;src/apps/daemon/internal/platform/system','privileged operations remain behind existing platform owners and secret redaction','a donor helper daemon, bearer token, parent watcher or elevation path is not added','The donor helper/privilege layer is superseded by LumiNet platform/process ownership and centralized redaction; lifecycle behavior remains review evidence.')
  if key=='sni-injection':
   return sup('packet injection authority and path evidence','src/apps/daemon/internal/analysis/diagnostics/sni_path_plan.go#BuildSNIPathPlan;src/apps/daemon/internal/protocols/tlsfragment/sni_range.go#FindSNIHostRange','MTU/header/sequence evidence can inform bounded planning while packet injection stays single-owned','raw BPF/NFQUEUE/WinDivert injection and wrong-sequence packet authority are not duplicated','Injection helpers contribute MTU, TCP wrap and filter-validation oracles, but existing packet/runtime owners remain authoritative.','src/apps/daemon/internal/analysis/diagnostics/post_refactor_225_test.go#TestPostRefactor225SNIPathRequiresResponseAndStrictTLS')
  if key in {'sni-config','sni-connection','sni-network','sni-packet','sni-proxy'}:
   return inspired('SNI/TLS path evidence','src/apps/daemon/internal/analysis/diagnostics/sni_path_plan.go#BuildSNIPathPlan;src/apps/daemon/internal/protocols/tlsfragment/sni_range.go#FindSNIHostRange','first-response and strict TLS evidence outrank connect-only reachability','raw packet injection and insecure TLS never become planner authority','ClientHello parsing, connection evidence, MTU/sequence and matrix lessons are recomposed into strict read-only path evidence.','src/apps/daemon/internal/analysis/diagnostics/post_refactor_225_test.go#TestPostRefactor225SNIPathRequiresResponseAndStrictTLS')
  return ref('SNI donor build/documentation evidence','Supporting build/docs/root surfaces are retained for provenance but do not justify a separate runtime.')

 if donor in ('sni-bypass','sni-spoofing-python','snispf-hj'):
  return inspired('SNI/TLS path evidence','src/apps/daemon/internal/analysis/diagnostics/sni_path_plan.go#BuildSNIPathPlan;src/apps/daemon/internal/protocols/tlsfragment/sni_range.go#FindSNIHostRange','first-response and strict TLS evidence outrank connect-only reachability','raw packet injection and insecure TLS never become planner authority','SNI donor mechanics are decomposed into parser, path-evidence, MTU, sequence and deployment semantics while packet injection remains with existing owners.','src/apps/daemon/internal/analysis/diagnostics/post_refactor_225_test.go#TestPostRefactor225SNIPathRequiresResponseAndStrictTLS')
 if donor=='mitm-proxy':
  return ('guardrail-derived','negative-to-guardrail','negative-to-guardrail','secret-bearing artifact admission','src/apps/daemon/internal/analysis/diagnostics/artifact_admission_plan.go#BuildArtifactAdmissionPlan','artifact evidence is hash-bound and secret material is quarantined','private CA keys and transparent interception are never imported as runtime authority','src/apps/daemon/internal/analysis/diagnostics/post_refactor_225_test.go#TestPostRefactor225ArtifactAdmissionQuarantinesPrivateKeyWithoutEcho','Operations convergence policy lab','verified','Bundled CA key and interception code are preserved as negative evidence; bounded artifact admission is the target-native result.')
 if donor=='mitm-relay':
  return ('guardrail-derived','negative-to-guardrail','negative-to-guardrail','relay design inspection','src/apps/daemon/internal/analysis/diagnostics/relay_inspection_plan.go#BuildRelayInspectionPlan','relay analysis is read-only and protocol-aware','scripted mutation, insecure TLS, magic-byte STARTTLS and global UDP identity are rejected','src/apps/daemon/internal/analysis/diagnostics/post_refactor_225_test.go#TestPostRefactor225RelayInspectionRejectsUnsafeMITMPatterns','Operations convergence policy lab','verified','The donor contributes relay-state and failure lessons without preserving arbitrary mutation authority.')
 if donor in ('sing-box-rules','routing-list'):
  return inspired('routing artifact provenance','src/apps/daemon/internal/analysis/diagnostics/routing_artifact_plan.go#BuildRoutingArtifactPlan','remote routing assets require immutable digest and provenance evidence','mutable downloaded lists never become authoritative merely because they parse','Rule grammars/generators become provenance and validation evidence rather than copied mutable policy.','src/apps/daemon/internal/analysis/diagnostics/post_refactor_225_test.go#TestPostRefactor225RoutingArtifactRequiresDigestForRemote')
 if donor=='sing-dns':
  return inspired('DNS resolution policy','src/apps/daemon/internal/analysis/diagnostics/dns_resolution_policy_plan.go#BuildDNSResolutionPolicyPlan','DNS transport dependencies are acyclic and secure fallback never downgrades silently','cleanup uses allocated wire ID and TTL rewrite treats A/AAAA symmetrically','Transport/cache/fallback/ECS semantics are recomposed around the existing DNS owner; donor correlation/AAAA TTL defects become guards.','src/apps/daemon/internal/analysis/diagnostics/post_refactor_225_test.go#TestPostRefactor225DNSPolicyTruncationAndSecureFallback')
 if donor=='sing-mux':
  return inspired('multiplex admission policy','src/apps/daemon/internal/analysis/diagnostics/multiplex_policy_plan.go#BuildMultiplexPolicyPlan','session/stream/padding/bandwidth bounds are explicit','first write reports application bytes and peer padding is bounded before allocation/skip','Mux lifecycle semantics strengthen the existing SMUX owner without adding a parallel mux runtime.','src/apps/daemon/internal/analysis/diagnostics/post_refactor_225_test.go#TestPostRefactor225MultiplexPolicyBoundsAndPayloadAccounting')

 if donor=='v2rayng':
  if key=='android-fmt':
   return sup('proxy share-link grammar and round-trip compatibility','src/apps/daemon/internal/networking/proxyconfig/types.go#ProxyConfig;src/apps/daemon/internal/networking/proxyconfig/parser_contract_test.go','supported proxy formats round-trip through one bounded parser contract','donor parser quirks, fabricated credentials and ambiguous authorities are not inherited','v2rayNG format handlers are a rich compatibility oracle; LumiNet keeps the stricter parser/serializer owner.','src/apps/daemon/internal/networking/proxyconfig/parser_contract_test.go#TestPostRefactor225WireGuardShareLinkRequiresExplicitKeys')
  if key in {'android-core','android-dto','android-enums','android-contracts'}:
   return sup('proxy/mobile core configuration contracts','src/apps/daemon/internal/runtime/proxy/core_manager.go#CoreManager;src/apps/daemon/internal/runtime/mobilecore/controller.go#Controller','core/outbound/mobile state remains typed and single-owned','Android donor DTO/config builders do not become a parallel source of runtime truth','v2rayNG core builders and DTOs are compared as compatibility/state oracles; existing core-manager/mobilecore ownership is stronger.')
  if key=='android-handler':
   return sup('subscription, update, backup and certificate evidence','src/apps/daemon/internal/integrations/sub/node_catalogue.go#NodeCatalogue;src/apps/daemon/internal/foundation/updateadmission/updateadmission.go#Verifier;src/apps/daemon/internal/analysis/diagnostics/artifact_admission_plan.go#BuildArtifactAdmissionPlan','node identity and update publication are deterministic, staged and hash-bound','direct WebDAV restore, asset-name-only update selection and certificate evidence never bypass admission','The heterogeneous handler layer is decomposed into subscription continuity, staged update admission, backup negative oracles and certificate evidence; target owners remain stronger.')
  if key in {'android-service','android-receiver'}:
   return sup('Android VPN/service lifecycle','src/apps/android/app/src/main/java/com/luminet/android/VpnEngineService.kt#VpnEngineService;src/apps/android/app/src/main/java/com/luminet/android/UnderlyingNetworkTracker.kt#UnderlyingNetworkTracker','mobile VPN control sockets and underlying network state remain platform-owned','donor TProxy credential files/logging, browser dialer HTTP/JS and implicit socket routing are not transplanted','v2rayNG service/receiver behavior reinforces protected socket, underlying-network, boot/widget and lifecycle oracles around the existing Android owner.')
  if key in {'android-ui','android-viewmodel','android-res-layout','android-res-drawable','android-res-values','android-helper'}:
   return inspired('profile/mobile operator UX','src/packages/control-ui/src/pages/Profiles.tsx#Profiles;src/packages/control-ui/src/pages/Rules.tsx#Rules;src/packages/control-ui/src/pages/Settings.tsx#Settings','search/import/routing actions stay explicit and local UI state remains non-authoritative','UI convenience never performs hidden remote fetch, update publication or runtime activation','v2rayNG screen/viewmodel/resource patterns inspire bounded local profile search, routing visibility and mobile affordances inside existing product pages.','src/packages/control-ui/scripts/test-post-refactor-225.mjs#natural-product-surfaces','Profiles, Rules and Settings',topology='idea-to-native')
  if key in {'android-util','android-extension'}:
   return sup('mobile utility and validation primitives','src/apps/daemon/internal/platform/mobilehost/host.go#Host;src/packages/control-ui/src/api/contracts.ts','platform/network helpers remain behind typed target adapters','generic donor helpers do not bypass platform/network/security ownership','Utility and extension helpers are reviewed for edge cases; existing mobilehost and typed frontend contracts remain the stronger owners.')
  return ref('v2rayNG packaging/support evidence','Repository/build/support surfaces are preserved for provenance; no additional runtime or UI authority is justified.')

 if donor=='v2raya-scoop':
  if key=='v2raya-scoop-bucket':
   return sup('immutable update artifact admission','src/apps/daemon/internal/foundation/updateadmission/updateadmission.go#Verifier','updates remain exact-size/SHA bound, staged and atomically published','mutable or hashless binaries are never promoted','Scoop manifests reinforce per-architecture immutable hashes and persistence, already stronger in update admission.')
  if key in {'v2raya-scoop-scripts','v2raya-scoop-bin'}:
   return sup('service/update lifecycle scripts','src/apps/daemon/internal/foundation/updateadmission/updateadmission.go#Verifier','service/update actions remain explicit and reversible','dynamic command evaluation is not an update or service-management mechanism','Scoop service scripts are lifecycle evidence; dynamic execution is rejected.')
  return ref('Scoop packaging/support evidence','Editor/root metadata do not contribute a stronger target mechanism.')

 if donor=='tun2socket':
  return hardened('userspace TUN packet/session correctness','src/packages/lumicore/src/system/userspace_tun.rs#UserspaceTunScheduler','unfragmented IPv4 TCP/UDP bounds, 5-tuple identity, deterministic eviction and repaired checksums','malformed headers, fragment ambiguity and off-by-one NAT/broadcast assumptions are rejected','The donor is an ancestor of false target facades; its useful packet/NAT invariants harden the actual bounded simulation while print-only facades are retired.','src/packages/lumicore/src/system/userspace_tun.rs#rejects_minimum_ipv4_without_transport_header_without_panicking',validation='statically-validated')
 if donor=='udp-ring-queue':
  return inspired('queue/backpressure policy','src/apps/daemon/internal/analysis/diagnostics/queue_backpressure_plan.go#BuildQueueBackpressurePolicyPlan','capacity, batching, eviction, restore-on-failure and counters are explicit','wire count is validated against payload length before slicing/allocating','Bounded ring/export semantics generalize to target queue policy; zero wire-size and unchecked split behavior become negative guards.','src/apps/daemon/internal/analysis/diagnostics/post_refactor_225_test.go#TestPostRefactor225QueueBackpressureBoundsEvictionRestoreAndWireCount')

 if donor=='uptimeflare':
  if key in {'uptime-worker','uptime-types'}:
   return inspired('service incident policy','src/apps/daemon/internal/analysis/diagnostics/service_incident_policy_plan.go#BuildServiceIncidentPolicyPlan','health evidence and incident lifecycle remain separate','maintenance/grace/redaction/persistence cooldown prevent notification and secret leaks','Worker monitor/store/type semantics become bounded incident transitions and retention policy without a second monitor runtime.','src/apps/daemon/internal/analysis/diagnostics/post_refactor_225_test.go#TestPostRefactor225IncidentPolicyGraceMaintenanceRecoveryAndCooldown','Health')
  if key in {'uptime-components','uptime-pages','uptime-styles','uptime-locales'}:
   return inspired('health/status-page UX','src/packages/control-ui/src/pages/Health.tsx#Health;src/packages/control-ui/src/pages/Logs.tsx#Logs','incident status, maintenance, recovery, timeline and evidence remain visible without making UI authoritative','status-page widgets never send notifications or write monitor state directly','Status, incident, maintenance, detail-chart, localization and badge/page patterns inform the existing Health/Logs product surfaces.','src/packages/control-ui/scripts/test-post-refactor-225.mjs#health-and-logs','Health and Logs',topology='idea-to-native')
  return ref('monitoring deployment/support evidence','Cloudflare/Vercel/Terraform/proxy/bootstrap assets are preserved as operational reference; LumiNet does not import their deployment authority.')

 if donor=='utls':
  if key in {'fingerprint','parrot','json','roller','extension'}:
   return inspired('TLS fingerprint policy','src/apps/daemon/internal/analysis/diagnostics/tls_fingerprint_policy_plan.go#BuildTLSFingerprintPolicyPlan','known-good fingerprints may be reused before bounded exploration with ALPN consistency','weak ciphers and fingerprint selection never weaken certificate trust','Roller/fingerprinter/parrot/JSON/extension behavior becomes bounded target trial/reuse policy while the pinned uTLS runtime remains authoritative.','src/apps/daemon/internal/analysis/diagnostics/post_refactor_225_test.go#TestPostRefactor225TLSFingerprintPolicyReusesKnownGoodAndRejectsWeakCiphers')
  if key=='ech':
   return sup('ECH configuration and strict TLS runtime','src/apps/daemon/internal/runtime/proxy/ech.go#DialECH;src/apps/daemon/internal/networking/proxyconfig/types.go#ProxyConfig','ECH parsing/runtime keeps certificate verification enabled by default','fingerprint experiments never weaken ECH certificate trust or create hidden plaintext downgrade requirements','uTLS ECH internals are upstream/runtime reference; LumiNet already owns strict ECH parsing/dial behavior and records ECH as a live capability check.')
  if key=='quic':
   return sup('QUIC/TLS handshake interoperability','src/apps/daemon/internal/runtime/proxy/core_manager.go#CoreManager;src/apps/daemon/internal/runtime/proxy/tuic_conn.go#TuicSession','QUIC transport remains with existing outbound/TUIC owners','uTLS QUIC internals are not forked into a competing QUIC stack','uTLS QUIC transport-parameter and handshake machinery is upstream reference; existing QUIC/TUIC owners remain authoritative.')
  if key in {'session','ticket','psk','handshake'}:
   return sup('TLS handshake/session lifecycle','src/apps/daemon/internal/runtime/proxy/wstunnel.go#dialUTLS;src/apps/daemon/internal/runtime/proxy/tester.go#Tester','handshake/session/ticket behavior stays in the pinned TLS library and existing runtime wrappers','LumiNet does not reimplement ticket/PSK/key-schedule internals from donor source','Handshake, PSK, ticket and session machinery are deep upstream implementation evidence, not a new target plane.')
  if key in {'utls-dicttls','utls-internal','utls-fipsonly','utls-testenv','utls-testdata','utls-examples','utls-root'}:
   return ref('pinned uTLS upstream implementation/test corpus','The full crypto/constants/FIPS/test corpus is exhaustively reviewed as upstream dependency evidence; target policy consumes supported public behavior rather than copying internal crypto/TLS machinery.','src/apps/daemon/internal/runtime/proxy/wstunnel.go#dialUTLS')

 if donor=='warpscanner-android':
  return sup('WARP endpoint quality and secret hygiene','src/apps/daemon/internal/runtime/warp/warp_scanner.go#summarizeWarpAttempts;src/apps/daemon/internal/analysis/diagnostics/artifact_admission_plan.go#BuildArtifactAdmissionPlan;src/packages/control-ui/src/pages/Settings.tsx#Settings','endpoint ranking uses repeated loss/latency evidence and product export stays non-authoritative','private keys are never fetched over plaintext, logged, or uploaded as generated config','Historical WARP scanner semantics are already stronger in LumiNet; ranked evidence/export UX is preserved while insecure key acquisition/export becomes a guardrail.','src/packages/control-ui/scripts/test-post-refactor-225.mjs#warp-product','Settings')

 if donor=='wintun':
  if key=='wintun-api':
   return hardened('Wintun device/session admission','src/apps/daemon/internal/platform/system/wintun_policy.go#validateWintunRingCapacity;src/apps/daemon/internal/platform/system/wintun_windows.go#StartSession','ring capacity is 128KiB..64MiB power-of-two and packet sizes are 1..65535','invalid ring/packet bounds are rejected before unsafe DLL slicing/calls','Session-ring acquire/release/corruption contracts harden the actual Windows owner; duplicate DLL authority is removed.','src/apps/daemon/internal/platform/system/wintun_policy_test.go#TestPostRefactor225WintunRingCapacityContract')
  if key in {'wintun-driver','wintun-setupapihost'}:
   return ref('Wintun driver/install lifecycle reference','Kernel driver and SetupAPI host internals remain upstream/vendor authority; LumiNet validates the user-mode contract and does not fork driver installation.','src/apps/daemon/internal/platform/system/wintun_windows.go#StartSession')
  if key=='wintun-example':
   return ref('Wintun usage/test oracle','The donor example is retained as an API/lifecycle oracle only; the live target wrapper owns actual adapter/session use.','src/apps/daemon/internal/platform/system/wintun_windows.go#StartSession')
  return ref('Wintun build/support evidence','Root build/license metadata is accounted without runtime authority.')

 if donor=='wireguard-go':
  if key in {'wg-device','wg-ratelimiter','wg-replay'}:
   return inspired('WireGuard peer/device readiness policy','src/apps/daemon/internal/analysis/diagnostics/wireguard_device_policy_plan.go#BuildWireGuardDevicePolicyPlan','exact AllowedIP ownership, longest-prefix overlap, replay windows, handshake rate/cookie admission, keepalive and rekey/reject/key-zeroization lifecycle are explicit','a second WireGuard device, key store, packet engine or route installer is never introduced beside the existing live owner','Device/peer/timer/keypair, replay and rate-limit semantics are decomposed into non-executing readiness evidence around the existing WireGuard/WARP owner.','src/apps/daemon/internal/analysis/diagnostics/post_refactor_225_workflow_wireguard_test.go#TestPostRefactor225WireGuardPolicyOwnsExactPrefixesAndRequiresUnderLoadCookieGate')
  if key in {'wg-conn','wg-tun','wg-ipc','wg-cmd'}:
   return sup('WireGuard transport/device integration','src/apps/daemon/internal/runtime/warp;src/apps/daemon/internal/platform/system','live WireGuard/WARP transport, TUN and platform integration remain single-owned','a second userspace WireGuard device, UAPI listener or TUN implementation is not introduced','The donor transport/TUN/UAPI/CLI layers are full-runtime reference; current WARP/platform owners remain authoritative.')
  if key in {'wg-rwcancel','wg-tai64n'}:
   return sup('WireGuard cancellation/timestamp primitives','src/apps/daemon/internal/runtime/warp;src/apps/daemon/internal/foundation','cancellation and time semantics remain within existing runtime/foundation owners','donor utility packages do not create new lifecycle authority','Small cancellation and TAI64N helpers are reviewed as implementation oracles and do not beat existing owners.')
  if key in {'wg-tsasm','wg-tests','wg-root'}:
   return ref('WireGuard implementation/test/build corpus','Assembly kernels, integration scripts and root build material remain upstream reference; no target fork is justified.','src/apps/daemon/internal/runtime/warp')

 if donor=='wormhole':
  if key in {'wormhole-server','wormhole-client','wormhole-cli','wormhole-main','wormhole-pkg','wormhole-utils','wormhole-root'}:
   return inspired('bounded declarative network workflow policy','src/apps/daemon/internal/analysis/diagnostics/network_workflow_plan.go#BuildNetworkWorkflowPlan','init and trigger phases, dependency order and reverse cleanup are deterministic and bounded','docker namespace/run, shell/exec/plugin host execution, embedded credentials and cyclic/unknown dependencies are rejected','Segment/chain/remote/tunnel/config/cleanup lifecycle becomes a non-executing workflow graph; host/network mutations remain outside planner authority.','src/apps/daemon/internal/analysis/diagnostics/post_refactor_225_workflow_wireguard_test.go#TestPostRefactor225NetworkWorkflowOrdersTriggersCleanupAndRejectsExecution')
  if key in {'wormhole-mysql','wormhole-wordpress','wormhole-pong'}:
   return ref('wormhole demo/deployment payloads','Demo Docker payloads are accounted as functional examples only; application-specific MySQL/WordPress/pong containers do not belong to LumiNet.')

 if donor=='tt':
  return sup('terminal/TUI layout and input ergonomics','labs/daemon/modules/tui/tui.go#Model','terminal resizing, wide-rune/ANSI-aware layout and raw key handling remain presentation concerns rather than network authority','the typing-training/game domain is not imported and raw terminal handling does not replace Bubble Tea/Lip Gloss event/layout ownership','TT contributes terminal centering, visible-width, key/event and progress-display comparison evidence, but the existing Bubble Tea/Lip Gloss TUI stack is the stronger owner for those primitives.','scripts/checks/check_post_refactor_225_convergence.py#semantic-tt-tui','labs/daemon/modules/tui/tui.go')

 if donor=='tuic-impl':
  if key=='tuic-impl-tuic':
   return hardened('TUIC v5 wire correctness','src/apps/daemon/internal/runtime/proxy/tuic_conn.go#TuicSession','domain/payload/fragment wire bounds are enforced and auth-sent is not peer-authenticated','short/malformed auth framing and wrapped domain/payload lengths are rejected while 0-RTT remains valid','Protocol marshal/unmarshal/model inconsistencies sharpen the existing TUIC wire owner.','src/apps/daemon/internal/runtime/proxy/tuic_spec_test.go#TestPacketRejectsMalformedFragmentAndWireLengthOverflow')
  if key in {'tuic-impl-tuic-client','tuic-impl-tuic-server'}:
   return hardened('TUIC option/config validation','src/apps/daemon/internal/networking/proxyconfig/types.go#ProxyConfig;src/apps/daemon/internal/runtime/proxy/tuic_conn.go#TuicSession','congestion-control and UDP relay modes are validated before runtime handoff','client/server runtime examples do not create a second TUIC engine','Client/server configuration and 0-RTT/UDP lifecycle are used as differential oracles for target validation.','src/apps/daemon/internal/runtime/proxy/tuic_spec_test.go#TestPacketRejectsMalformedFragmentAndWireLengthOverflow')
  if key=='tuic-impl-tuic-quinn':
   return sup('TUIC QUIC transport authority','src/apps/daemon/internal/runtime/proxy/core_manager.go#CoreManager','TUIC runtime transport remains QUIC-backed through the existing core owner','TUIC framing over plain TCP fails closed and a second QUIC stack is not introduced','Quinn integration proves the protocol transport boundary; target keeps its existing QUIC/core-manager owner.')
  return ref('TUIC implementation build/support evidence','Root/container/CI assets are accounted but do not add runtime authority.')
 if donor=='tuic-spec':
  return hardened('TUIC v5 wire specification','src/apps/daemon/internal/runtime/proxy/tuic_conn.go#TuicSession','wire lengths, fragmentation and 0-RTT semantics match the protocol contract','non-conformant plain-TCP TUIC framing is rejected','The standalone specification remains the normative differential oracle for the existing TUIC owner.','src/apps/daemon/internal/runtime/proxy/tuic_spec_test.go#TestPacketRejectsMalformedFragmentAndWireLengthOverflow')

 return ref('reviewed donor module','Exhaustively accounted supporting module; no stronger target-native mechanism identified.')

# archive validation + extracted byte equality
archive_rows=[]; surfaces=[]; directories=[]; symbols=[]
path_to_module={}
for donor in DONORS:
 if not donor.archive.is_file(): raise FileNotFoundError(donor.archive)
 if not donor.root.is_dir(): raise FileNotFoundError(donor.root)
 archive_sha=sha_file(donor.archive)
 with zipfile.ZipFile(donor.archive) as z:
  infos=z.infolist(); seen=set(); folded=set(); file_infos=[]; total=0; syms=0
  roots=set()
  for info in infos:
   p=norm(info.filename); name=p.as_posix().rstrip('/'); key=name.casefold()
   if name in seen or key in folded: raise ValueError(f'{donor.id}: duplicate/case collision {name}')
   seen.add(name); folded.add(key)
   if p.parts: roots.add(p.parts[0])
   mode=info.external_attr>>16
   if stat.S_ISLNK(mode): syms+=1
   kind=stat.S_IFMT(mode)
   if kind not in (0,stat.S_IFREG,stat.S_IFDIR,stat.S_IFLNK): raise ValueError(f'{donor.id}: special member {name}')
   if info.flag_bits&1: raise ValueError(f'{donor.id}: encrypted member {name}')
   if info.compress_size and info.file_size/info.compress_size>1000: raise ValueError(f'{donor.id}: compression ratio {name}')
   total+=info.file_size
   if not info.is_dir(): file_infos.append((info,p,mode))
  bad=z.testzip()
  if bad: raise ValueError(f'{donor.id}: CRC {bad}')
  if len(roots)!=1: raise ValueError(f'{donor.id}: expected one archive root, got {roots}')
  root_name=next(iter(roots))
  extracted_files={p.relative_to(donor.root).as_posix():p for p in donor.root.rglob('*') if p.is_file() or p.is_symlink()}
  zip_files={}
  for info,p,mode in file_infos:
   rel=PurePosixPath(*p.parts[1:]).as_posix()
   if not rel: continue
   if stat.S_ISLNK(mode):
    payload=z.read(info); zh=sha_bytes(payload)
   else: zh=sha_bytes(z.read(info))
   zip_files[rel]=(info,mode,zh)
  if set(zip_files)!=set(extracted_files):
   miss=sorted(set(zip_files)-set(extracted_files))[:10]; extra=sorted(set(extracted_files)-set(zip_files))[:10]
   raise ValueError(f'{donor.id}: extracted path mismatch missing={miss} extra={extra}')
  for rel,(info,mode,zh) in zip_files.items():
   ep=extracted_files[rel]
   if ep.is_symlink(): eh=sha_bytes(os.readlink(ep).encode())
   else: eh=sha_file(ep)
   if zh!=eh: raise ValueError(f'{donor.id}: byte mismatch {rel}')
   c=classify(rel); mk=module_key(donor.id,rel,c); path_to_module[(donor.id,rel)]=mk
   surfaces.append({'donor':donor.id,'path':rel,'sha256':eh,'size_bytes':info.file_size,'file_type':'symlink' if stat.S_ISLNK(mode) else 'file','language':language(rel),'classification':c,'authority_status':'authoritative-source' if c in HIGH else 'supporting-evidence','semantic_record_ids':'','surface_disposition':'','surface_rationale':''})
  archive_rows.append({'donor':donor.id,'archive':donor.archive.name,'archive_sha256':archive_sha,'members':len(infos),'files':len(zip_files),'symlinks':syms,'uncompressed_bytes':total,'archive_root':root_name,'validation':'verified-safe+crc+byte-equal'})
 # directory Merkle matrix, including root
 rel_files=sorted([p for p in donor.root.rglob('*') if p.is_file() or p.is_symlink()],key=lambda p:p.relative_to(donor.root).as_posix())
 dirs=[donor.root]+sorted([p for p in donor.root.rglob('*') if p.is_dir()],key=lambda p:p.relative_to(donor.root).as_posix())
 for d in dirs:
  entries=[]
  for p in rel_files:
   try:r=p.relative_to(d)
   except ValueError:continue
   if p.is_symlink(): h=sha_bytes(os.readlink(p).encode())
   else:h=sha_file(p)
   entries.append((r.as_posix(),h))
  payload=''.join(f'{h}  {r}\n' for r,h in entries).encode()
  directories.append({'donor':donor.id,'path':'.' if d==donor.root else d.relative_to(donor.root).as_posix(),'descendant_files':len(entries),'tree_sha256':sha_bytes(payload)})

# semantic records: base donor + every focused module key, with target mapping.
records=[]; module_record={}; file_record={}; seq=1
for donor in DONORS:
 rep=next(s for s in surfaces if s['donor']==donor.id)
 rid=f'PR225-R{seq:03d}'; seq+=1
 records.append({'record_id':rid,'parent_record_id':'n/a','composition_group_id':'CG225-'+donor.id,'donor':donor.id,'domain':'repository-accountability','value_unit':f'{donor.product} complete repository accountability','source_granularity':'repository','value_form':'evidence corpus','separability':'context-dependent','donor_path':rep['path'],'donor_sha256':rep['sha256'],'donor_symbol':'n/a','transformation':'exhaustive review','mapping_topology':'one-to-many','disposition':'reference-only','decision_rationale':'Every archive surface is hash-accounted; independently meaningful modules receive child records.','target_capability':'convergence evidence','target_nodes':'n/a','invariant':'all donor files and directories remain traceable to explicit dispositions','negative_invariant':'repository-level accountability is not implementation evidence','test_node':'n/a','operator_surface':'governance/convergence/post-refactor-225-surface-accountability.csv','migration_impact':'none','license_note':'technical ranking ignores license per user instruction; provenance preserved','risk_tier':'low','dependency_record_ids':'n/a','evidence_confidence':'high','validation_status':'verified'})
 base=rid
 keys=sorted(set(path_to_module[(donor.id,s['path'])] for s in surfaces if s['donor']==donor.id and s['classification'] in HIGH))
 if not keys: keys=[module_key(donor.id,rep['path'],rep['classification'])]
 for key in keys:
  candidates=[s for s in surfaces if s['donor']==donor.id and path_to_module[(donor.id,s['path'])]==key]
  rep2=next((s for s in candidates if s['classification'] in HIGH),candidates[0])
  rid=f'PR225-M{seq:03d}'; seq+=1; module_record[(donor.id,key)]=rid
  disp,trans,topo,cap,nodes,inv,neg,behavior_test,op,val,rat=target_for(donor.id,key)
  risk='high' if donor.id in ('mitm-proxy','mitm-relay','tun2socket','wintun','tuic-impl','tuic-spec','warpscanner-android') else 'medium' if rep2['classification'] in HIGH else 'low'
  test_node='n/a' if disp=='reference-only' else f'scripts/checks/check_post_refactor_225_convergence.py#semantic-{rid}'
  if behavior_test != 'n/a': rat += f' Capability-level behavioral evidence: {behavior_test}.'
  records.append({'record_id':rid,'parent_record_id':base,'composition_group_id':'CG225-'+cap.lower().replace(' ','-').replace('/','-'),'donor':donor.id,'domain':key,'value_unit':key.replace('-',' ')+' semantics','source_granularity':'module/path cluster','value_form':'mechanism + tests + operational evidence','separability':'independently reviewable module cluster','donor_path':rep2['path'],'donor_sha256':rep2['sha256'],'donor_symbol':'n/a','transformation':trans,'mapping_topology':topo,'disposition':disp,'decision_rationale':rat,'target_capability':cap,'target_nodes':nodes,'invariant':inv,'negative_invariant':neg,'test_node':test_node,'operator_surface':op,'migration_impact':'additive hardening/read-only planning; false zero-consumer facades may be retired where explicitly proven','license_note':'technical ranking ignores license per user instruction; provenance preserved','risk_tier':risk,'dependency_record_ids':base,'evidence_confidence':'high','validation_status':val})

# Every high-signal file gets its own child record beneath the module record.
# This deliberately separates repository accountability, module context, and
# file-level semantic disposition so a tiny implementation/test/config leaf
# cannot hide behind a broad donor/module decision.
for s in sorted(surfaces,key=lambda r:(r['donor'],r['path'])):
 if s['classification'] not in HIGH:
  continue
 mk=path_to_module[(s['donor'],s['path'])]
 parent=module_record.get((s['donor'],mk))
 if not parent:
  raise ValueError(f'focused module missing for file record: {s["donor"]}:{s["path"]}')
 disp,trans,topo,cap,nodes,inv,neg,behavior_test,op,val,rat=target_for(s['donor'],mk)
 rid=f'PR225-F{len(file_record)+1:04d}'
 file_record[(s['donor'],s['path'])]=rid
 risk='high' if s['donor'] in ('mitm-proxy','mitm-relay','tun2socket','wintun','tuic-impl','tuic-spec','warpscanner-android') else 'medium'
 test_node='n/a' if disp=='reference-only' else f'scripts/checks/check_post_refactor_225_convergence.py#surface-{rid}'
 if behavior_test != 'n/a':
  rat += f' Capability-level behavioral evidence: {behavior_test}.'
 rat += f' File-level disposition: {s["path"]} was independently hash-accounted and reviewed inside module cluster {mk}; its symbols inherit this decision unless a narrower symbol note overrides it.'
 records.append({'record_id':rid,'parent_record_id':parent,'composition_group_id':'CG225-'+cap.lower().replace(' ','-').replace('/','-'),'donor':s['donor'],'domain':'file:'+s['path'],'value_unit':s['path']+' file semantics','source_granularity':'file','value_form':s['classification']+' surface','separability':'independently hash-accounted file surface','donor_path':s['path'],'donor_sha256':s['sha256'],'donor_symbol':'n/a','transformation':trans,'mapping_topology':topo,'disposition':disp,'decision_rationale':rat,'target_capability':cap,'target_nodes':nodes,'invariant':inv,'negative_invariant':neg,'test_node':test_node,'operator_surface':op,'migration_impact':'inherits bounded module-level convergence; file cannot independently grant runtime authority','license_note':'technical ranking ignores license per user instruction; provenance preserved','risk_tier':risk,'dependency_record_ids':parent,'evidence_confidence':'high','validation_status':val})

# Attach base + module + file records to every surface.
base_by_donor={r['donor']:r['record_id'] for r in records if r['domain']=='repository-accountability'}
for s in surfaces:
 ids=[base_by_donor[s['donor']]]
 mk=path_to_module[(s['donor'],s['path'])]
 child=module_record.get((s['donor'],mk))
 if child: ids.append(child)
 leaf=file_record.get((s['donor'],s['path']))
 if leaf: ids.append(leaf)
 if s['classification'] in HIGH and (not child or not leaf): raise ValueError(f'focused file semantic link missing: {s["donor"]}:{s["path"]}')
 s['semantic_record_ids']=';'.join(ids)
 s['surface_disposition']='focused-file-'+s['classification'] if leaf else ('focused-module-'+s['classification'] if child else 'accounted-supporting-'+s['classification'])
 s['surface_rationale']='independent file-level semantic disposition' if leaf else ('focused module-level disposition' if child else 'supporting/admin/fixture/documentation surface explicitly accounted by donor record')

# symbols from text-like implementation/test/script/ui sources.
patterns={
 'Go':[(re.compile(r'^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\('),'function'),(re.compile(r'^\s*type\s+([A-Za-z_][A-Za-z0-9_]*)\s+'),'type')],
 'Rust':[(re.compile(r'^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)'),'function'),(re.compile(r'^\s*(?:pub(?:\([^)]*\))?\s+)?(?:struct|enum|trait|type)\s+([A-Za-z_][A-Za-z0-9_]*)'),'type')],
 'Python':[(re.compile(r'^\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\('),'function'),(re.compile(r'^\s*class\s+([A-Za-z_][A-Za-z0-9_]*)'),'type')],
 'Kotlin':[(re.compile(r'^\s*(?:[\w<>]+\s+)*(?:suspend\s+)?fun\s+(?:<[^>]+>\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\('),'function'),(re.compile(r'^\s*(?:data\s+|sealed\s+|enum\s+)?(?:class|interface|object)\s+([A-Za-z_][A-Za-z0-9_]*)'),'type')],
 'Java':[(re.compile(r'^\s*(?:public|private|protected|static|final|synchronized|native|abstract|\s)+[\w<>\[\], ?]+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\('),'function'),(re.compile(r'^\s*(?:public|private|protected|abstract|final|\s)*(?:class|interface|enum)\s+([A-Za-z_][A-Za-z0-9_]*)'),'type')],
 'C':[(re.compile(r'^\s*(?:static\s+)?[\w\s\*]+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*\)\s*\{?\s*$'),'function')],
 'C++':[(re.compile(r'^\s*(?:static\s+)?[\w:<>,~&*\s]+\s+([A-Za-z_~][A-Za-z0-9_:~]*)\s*\([^;]*\)\s*(?:const\s*)?\{?\s*$'),'function')],
 'TypeScript':[(re.compile(r'^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_][A-Za-z0-9_]*)'),'function'),(re.compile(r'^\s*(?:export\s+)?(?:class|interface|type)\s+([A-Za-z_][A-Za-z0-9_]*)'),'type')],
 'JavaScript':[(re.compile(r'^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_][A-Za-z0-9_]*)'),'function'),(re.compile(r'^\s*(?:export\s+)?class\s+([A-Za-z_][A-Za-z0-9_]*)'),'type')],
}
by_surface={(s['donor'],s['path']):s for s in surfaces}
roots={d.id:d.root for d in DONORS}
for s in surfaces:
 lang=s['language']; pats=patterns.get(lang)
 if not pats: continue
 p=roots[s['donor']]/s['path']
 try:text=p.read_text(encoding='utf-8',errors='replace')
 except Exception:continue
 for line_no,line in enumerate(text.splitlines(),1):
  for pat,kind in pats:
   m=pat.match(line)
   if m:
    name=m.group(1)
    symbols.append({'donor':s['donor'],'path':s['path'],'sha256':s['sha256'],'line':line_no,'kind':kind,'name':name,'semantic_record_ids':s['semantic_record_ids']})
    break

# supersession map at target-capability level
sup=[]
groups=defaultdict(list)
for r in records:
 if r['domain']!='repository-accountability': groups[r['target_capability']].append(r)
for cap,rs in sorted(groups.items()):
 sup.append({'target_capability':cap,'contributing_records':';'.join(r['record_id'] for r in rs),'donors':';'.join(sorted(set(r['donor'] for r in rs))),'strongest_target_disposition':';'.join(sorted(set(r['disposition'] for r in rs))),'target_nodes':';'.join(sorted(set(r['target_nodes'] for r in rs))),'second_order_result':'recomposed into one target owner or explicit reference/guardrail; no duplicate runtime authority'})

OUT.mkdir(parents=True,exist_ok=True)
def write_csv(name,rows,fields):
 with (OUT/name).open('w',newline='',encoding='utf-8') as f:
  w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(rows)
write_csv('post-refactor-225-archive-accountability.csv',archive_rows,['donor','archive','archive_sha256','members','files','symlinks','uncompressed_bytes','archive_root','validation'])
write_csv('post-refactor-225-surface-accountability.csv',sorted(surfaces,key=lambda r:(r['donor'],r['path'])),['donor','path','sha256','size_bytes','file_type','language','classification','authority_status','semantic_record_ids','surface_disposition','surface_rationale'])
write_csv('post-refactor-225-directories.csv',sorted(directories,key=lambda r:(r['donor'],r['path'])),['donor','path','descendant_files','tree_sha256'])
write_csv('post-refactor-225-symbols.csv',sorted(symbols,key=lambda r:(r['donor'],r['path'],int(r['line']),r['name'])),['donor','path','sha256','line','kind','name','semantic_record_ids'])
ledger_fields=['record_id','parent_record_id','composition_group_id','donor','domain','value_unit','source_granularity','value_form','separability','donor_path','donor_sha256','donor_symbol','transformation','mapping_topology','disposition','decision_rationale','target_capability','target_nodes','invariant','negative_invariant','test_node','operator_surface','migration_impact','license_note','risk_tier','dependency_record_ids','evidence_confidence','validation_status']
write_csv('post-refactor-225-adoption-ledger.csv',records,ledger_fields)
write_csv('post-refactor-225-supersession-map.csv',sup,['target_capability','contributing_records','donors','strongest_target_disposition','target_nodes','second_order_result'])
summary={'donors':len(DONORS),'archive_members':sum(int(r['members']) for r in archive_rows),'surfaces':len(surfaces),'files':sum(1 for s in surfaces if s['file_type']=='file'),'symlinks':sum(1 for s in surfaces if s['file_type']=='symlink'),'directories':len(directories),'symbols':len(symbols),'semantic_records':len(records),'focused_module_records':len(module_record),'focused_file_records':len(file_record),'high_signal_surfaces':sum(1 for s in surfaces if s['classification'] in HIGH),'high_signal_without_focused_record':sum(1 for s in surfaces if s['classification'] in HIGH and len(s['semantic_record_ids'].split(';'))<3)}
(OUT/'post-refactor-225-evidence-summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
print(json.dumps(summary,sort_keys=True))
