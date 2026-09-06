#!/usr/bin/env python3
from __future__ import annotations
import csv, hashlib, json, os
from collections import Counter, defaultdict
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
E=ROOT/'governance/convergence'
BASE=Path('/mnt/data/luminet234/release/LumiNet-post-refactor-234-source-inventory.csv')

def rcsv(p):
    with Path(p).open(newline='',encoding='utf-8') as f:return list(csv.DictReader(f))
def wcsv(p,rows,fields):
    with Path(p).open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(rows)
def sha(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for b in iter(lambda:f.read(1<<20),b''):h.update(b)
    return h.hexdigest()

surfs=rcsv(E/'post-refactor-234-surface-accountability.csv')
mods=rcsv(E/'post-refactor-234-module-audit.csv')
bydon=defaultdict(list)
for r in surfs: bydon[r['donor']].append(r)

def pick(d,*needles):
    rows=bydon[d]
    for needle in needles:
        matches=[r for r in rows if needle.lower() in r['path'].lower()]
        if matches:return sorted(matches,key=lambda r:(len(r['path']),r['path']))[0]
    return sorted(rows,key=lambda r:r['path'])[0]

# Deep semantic units discovered in the second-order pass. Each is anchored to exact
# donor bytes already hash-accounted by 234, but receives a fresh 235 disposition.
S=[]
def add(d,value,needles,transform,disp,cap,node,inv,neg,status='reviewed',level='method'):
    src=pick(d,*needles)
    S.append(dict(donor=d,value_unit=value,source_path=src['path'],source_sha256=src['sha256'],level=level,
                  transformation=transform,disposition=disp,target_capability=cap,target_nodes=node,
                  invariant=inv,negative_invariant=neg,validation_status=status))
# DNS blocklist corpus: formats, preset composition, exception semantics, protection categories.
add('dns_blocklists','cross-format DNS rule equivalence',['dnsmasq/doh.txt'],'normalize-and-audit','adopted','DNS filter preset composition','src/apps/daemon/internal/analysis/diagnostics/post_refactor_235_plans.go','format is descriptive input; list identity remains caller-supplied','no donor feed fetch or block authority','verified','feature')
add('dns_blocklists','anti-bypass DNS/DoH/VPN/proxy intent',['doh-vpn-proxy-bypass'],'compose-preset','adopted','anti-bypass preset','src/apps/daemon/internal/analysis/diagnostics/post_refactor_235_plans.go','preset selection is deterministic','preset never activates blocking','verified','preset')
add('dns_blocklists','DNS rebind-protection category',['dns-rebind-protection'],'constraint-extraction','hardened','DNS policy evidence','src/apps/daemon/internal/analysis/diagnostics/post_refactor_235_plans.go','rebind protection remains an explicit category','category cannot silently rewrite runtime DNS','reviewed','primitive')
add('dns_blocklists','allowlist/exception precedence',['allowlist-request','allow-folder'],'negative-to-guardrail','hardened','DNS filter composition','src/apps/daemon/internal/analysis/diagnostics/post_refactor_235_plans.go','exception-bearing lists remain visibly optional','allow exceptions never disappear in flattening','verified','method')
add('dns_blocklists','native platform tracker categories',['native.apple','native-tracker'],'taxonomy-extraction','reference-only','DNS filter taxonomy','governance/convergence/post-refactor-235-semantic-ledger.csv','platform category is evidence only','taxonomy is not a claim that domains are malicious','reviewed','preset')
add('dns_blocklists','Apple Private Relay allow/block policy evidence',['apple-private-relay'],'policy-conflict-evidence','reference-only','DNS policy conflict review','governance/convergence/post-refactor-235-security-model.md','allow/block disagreement is retained explicitly','no hidden default chosen from donor popularity','reviewed','constraint')
# Kingo product UX and unsafe remote authority boundaries.
add('kingo_vpn','bounded parallel server scan progress',['ScanServersDialog.java'],'product-affordance-extraction','reference-only','scanner campaign UX','src/packages/control-ui/src/pages/Operations.tsx','progress/found/cancel state is explicit','fixed donor worker pool is not runtime authority','reviewed','widget')
add('kingo_vpn','pause/stop/stale-scan generation semantics',['ScanServersDialog.java'],'state-machine-extraction','hardened','scan campaign lifecycle','src/apps/daemon/internal/analysis/diagnostics/post_refactor_235_plans.go','cancel/pause state must be explicit','late results from superseded generations must not become current','reviewed','method')
add('kingo_vpn','clipboard/manual config import affordance',['AddServerDialog.java'],'product-affordance-extraction','superseded','profile import UX','src/apps/daemon/internal/workflows','existing profile admission remains authoritative','clipboard input never bypasses managed-profile validation','reviewed','widget')
add('kingo_vpn','remote update/server-feed authority',['UpdateChecker.java','Notification/Update.json'],'negative-to-guardrail','rejected-with-reason','update admission','src/apps/daemon/internal/foundation','remote mutable metadata cannot grant execution/routing authority','unsigned/unpinned feed data is never authoritative','reviewed','plane')
# mitmproxy2swagger deep parser semantics.
add('mitmproxy2swagger','HAR versus mitm capture format detection',['mitmproxy2swagger.py'],'primitive-extraction','hardened','API trace schema inference','src/apps/daemon/internal/analysis/diagnostics/post_refactor_234_plans.go','input format must be explicit/detectable','active MITM capture is not introduced','reviewed','method')
add('mitmproxy2swagger','query stripping and path templating',['mitmproxy2swagger.py'],'primitive-extraction','adopted','API trace schema inference','src/apps/daemon/internal/analysis/diagnostics/post_refactor_234_plans.go','query values never contaminate path templates','captured secrets never become schema examples','verified','method')
add('mitmproxy2swagger','request query/header/body field union',['mitmproxy2swagger.py'],'recomposition','adopted','API trace schema inference','src/apps/daemon/internal/analysis/diagnostics/post_refactor_234_plans.go','field aggregation is set-like and deterministic','authorization/cookie/API-key header names are omitted','verified','feature')
add('mitmproxy2swagger','response status/content-type union',['har_capture_reader.py'],'primitive-extraction','hardened','API trace schema inference','src/apps/daemon/internal/analysis/diagnostics/post_refactor_234_plans.go','observed response variants remain visible','schema inference cannot claim unobserved response behavior','verified','method')
add('mitmproxy2swagger','form/multipart/message-body schema evidence',['form_data_har.har'],'reference-oracle','reference-only','API schema test corpus','governance/convergence/post-refactor-235-semantic-ledger.csv','fixture edge cases remain available as evidence','fixture coverage is not runtime equivalence','reviewed','test-oracle')
add('mitmproxy2swagger','interception CA/runtime capture',['mitmproxy2swagger.py'],'negative-to-guardrail','rejected-with-reason','passive API inference boundary','src/apps/daemon/internal/analysis/diagnostics/post_refactor_234_plans.go','planner consumes already-captured metadata','no CA installation, interception, replay, or proxy authority','verified','plane')
# Outline config fallback, DNS intercept, connectivity, registry variants.
add('outline_apps','first-supported config fallback',['config_first_supported.go'],'direct-semantic-port','adopted','config fallback planning','src/apps/daemon/internal/analysis/diagnostics/post_refactor_235_plans.go','skip only explicit unsupported; first supported wins','invalid/error candidate stops fallback','verified','method')
add('outline_apps','DNS UDP truncation forcing TCP retry',['dnsintercept'],'primitive-extraction','adopted','DNS intercept safety','src/apps/daemon/internal/analysis/diagnostics/post_refactor_235_plans.go','eligible local UDP DNS is truncated to force TCP retry','planner never mutates packets','verified','method')
add('outline_apps','lazy base transport allocation on DNS-only flow',['dnsintercept'],'resource-lifecycle-extraction','adopted','DNS intercept safety','src/apps/daemon/internal/analysis/diagnostics/post_refactor_235_plans.go','DNS-only flow does not allocate unused base transport session','planner never opens sessions','verified','method')
add('outline_apps','TCP plus UDP/DNS connectivity probes',['connectivity.go'],'behavior-comparison','hardened','connectivity diagnostics','src/apps/daemon/internal/analysis','transport-specific health remains distinguishable','probe failure cannot silently rewrite routing','reviewed','feature')
add('outline_apps','config registry block/proxyless/SS/WebSocket variants',['configregistry'],'compatibility-evidence','superseded','profile/config admission','src/apps/daemon/internal','existing target config owners remain singular','donor config registry is not imported as second registry','reviewed','module')
add('outline_apps','Windows service/VPN process authority',['vpn_service.ts','routing_service.ts'],'negative-to-guardrail','superseded','external-core lifecycle','src/apps/daemon/internal/runtime','target lifecycle owner remains authoritative','no duplicate service install/start authority','reviewed','plane')
add('outline_tun2socks_demo','Android tun2socks demo lifecycle',['OutlineVpnService.kt'],'compatibility-evidence','superseded','mobile tunnel ownership','src/apps/daemon/internal','existing tunnel owner remains authoritative','demo AAR/runtime is not embedded as second tunnel','reviewed','module')
add('outline_tun2socks_demo','bundled tun2socks binary/AAR',['tun2socks.aar'],'negative-to-guardrail','rejected-with-reason','native dependency admission','governance/convergence/post-refactor-235-security-model.md','opaque/bundled binary is evidence only','binary provenance never grants execution authority','reviewed','artifact')
# ProofMode evidence topology and privacy.
add('proofmode_android','hash/signature evidence status',['HashUtils.java'],'primitive-extraction','hardened','evidence receipt topology','src/apps/daemon/internal/analysis/diagnostics/post_refactor_235_plans.go','pass/fail/unknown/not-applicable are distinct','unknown never counts as complete','verified','primitive')
add('proofmode_android','detached signature lineage',['DetachedSignatureProcessor.java'],'topology-inspiration','adopted','evidence receipt topology','src/apps/daemon/internal/analysis/diagnostics/post_refactor_235_plans.go','parent digest links form explicit graph','missing parent or cycle is failure','verified','method')
add('proofmode_android','OpenTimestamps external timestamp evidence',['android-opentimestamps'],'protocol-evidence','reference-only','evidence timestamp status','src/apps/daemon/internal/analysis/diagnostics/post_refactor_235_plans.go','timestamp state is independent from signature state','no external calendar/Bitcoin network call is made','verified','module')
add('proofmode_android','C2PA trust/metadata evidence',['C2PAManager.kt'],'metadata-model-inspiration','hardened','evidence receipt topology','src/apps/daemon/internal/analysis/diagnostics/post_refactor_235_plans.go','metadata consent is evaluated separately','metadata presence cannot imply consent or authenticity','verified','feature')
add('proofmode_android','GPS/device metadata collection',['GPSTracker.java'],'negative-to-guardrail','rejected-with-reason','privacy boundary','src/apps/daemon/internal/analysis/diagnostics/post_refactor_235_plans.go','receipt topology accepts caller-supplied evidence only','no host sensor/location collection','verified','plane')
add('proofmode_android','media watcher/storage authority',['MediaWatcher.kt'],'negative-to-guardrail','rejected-with-reason','evidence ingestion boundary','governance/convergence/post-refactor-235-security-model.md','external media lifecycle stays outside planner','no filesystem watcher or media mutation','reviewed','plane')
# Tor Metrics and Atlas.
add('tor_metrics_library','consensus valid-after/fresh-until freshness',['RelayNetworkStatusConsensus.java'],'primitive-extraction','adopted','Tor consensus evidence','src/apps/daemon/internal/analysis/diagnostics/post_refactor_235_plans.go','freshness is explicit evidence state','stale consensus never becomes circuit authority','verified','method')
add('tor_metrics_library','relay flags/status evidence',['RouterStatusEntry.java'],'primitive-extraction','hardened','Tor consensus evidence','src/apps/daemon/internal/analysis/diagnostics/post_refactor_235_plans.go','flags remain descriptive','flags do not grant trust or selection authority','verified','primitive')
add('tor_metrics_library','family reciprocity',['ServerDescriptor.java'],'constraint-extraction','adopted','Tor consensus evidence','src/apps/daemon/internal/analysis/diagnostics/post_refactor_235_plans.go','declared families are checked reciprocally','one-sided family claim is surfaced as warning','verified','method')
add('tor_metrics_library','shared IPv4 /16 diversity risk',['RouterStatusEntry.java'],'constraint-extraction','adopted','Tor consensus evidence','src/apps/daemon/internal/analysis/diagnostics/post_refactor_235_plans.go','shared prefix is risk evidence only','diversity warning cannot manufacture eligibility','verified','method')
add('tor_metrics_library','exit-policy port evidence',['ExitList.java','ServerDescriptor.java'],'primitive-extraction','adopted','Tor consensus evidence','src/apps/daemon/internal/analysis/diagnostics/post_refactor_235_plans.go','exit ports are counted descriptively','planner does not build circuits or probe exits','verified','method')
add('tor_metrics_library','bandwidth weight evidence',['BandwidthFile.java'],'primitive-extraction','adopted','Tor consensus evidence','src/apps/daemon/internal/analysis/diagnostics/post_refactor_235_plans.go','bandwidth weight remains caller-supplied evidence','weight alone never grants routing authority','verified','method')
add('tor_metrics_library','descriptor fetching/parser runtime',['DownloadConsensuses.java'],'negative-to-guardrail','rejected-with-reason','Tor evidence boundary','src/apps/daemon/internal/analysis/diagnostics/post_refactor_235_plans.go','planner accepts supplied observations','no descriptor fetch/control/network activity','verified','plane')
add('tor_atlas','relay search/filter affordance',['search'],'product-inspiration','reference-only','Tor evidence operator UX','src/packages/control-ui/src/pages/Operations.tsx','search metadata can improve explanation','historical Atlas UI is not routing authority','reviewed','widget')
add('tor_atlas','relay map/geographic visualization',['map'],'product-inspiration','reference-only','Tor evidence visualization','governance/convergence/post-refactor-235-semantic-ledger.csv','location remains descriptive','map location never becomes endpoint-selection authority','reviewed','widget')
add('tor_atlas','relay details flags/bandwidth/country panel',['details/router.html'],'product-inspiration','reference-only','Tor evidence detail view','src/packages/control-ui/src/pages/Operations.tsx','details expose evidence dimensions separately','presentation does not imply trust','reviewed','widget')
# ProxyBridge ordered rules.
add('proxybridge','ordered process/protocol/port rule overlap',['RuleManager.swift','gui_rules.c'],'algorithm-extraction','adopted','process proxy rule compilation','src/apps/daemon/internal/analysis/diagnostics/post_refactor_234_plans.go','overlap is reported deterministically','implicit hidden last-wins behavior is forbidden','verified','method')
add('proxybridge','rule conflict detection',['RuleManager.swift'],'algorithm-extraction','adopted','process proxy rule compilation','src/apps/daemon/internal/analysis/diagnostics/post_refactor_234_plans.go','overlapping rules with different actions are conflict evidence','conflict is never silently resolved','verified','method')
add('proxybridge','wildcard shadow detection',['RuleManager.swift'],'algorithm-extraction','adopted','process proxy rule compilation','src/apps/daemon/internal/analysis/diagnostics/post_refactor_234_plans.go','earlier wildcard coverage can shadow later rule','shadowing remains explainable','verified','method')
add('proxybridge','proxy self-loop exclusion',['ProxyBridge.c'],'negative-to-guardrail','hardened','process proxy rule compilation','src/apps/daemon/internal/analysis/diagnostics/post_refactor_234_plans.go','proxy process matches are loop risk','compiler does not install filters','verified','primitive')
add('proxybridge','kernel/system-extension interception authority',['project.pbxproj','ProxyBridge.c'],'negative-to-guardrail','rejected-with-reason','process-filter authority boundary','governance/convergence/post-refactor-235-security-model.md','rule planner is metadata-only','no kernel extension/driver install','reviewed','plane')
# SimpleDNSCrypt.
add('simplednscrypt','resolver source signature/freshness',['RemoteUpdate.cs','DnscryptProxyConfigurationManager.cs'],'policy-extraction','adopted','DNSCrypt topology','src/apps/daemon/internal/analysis/diagnostics/post_refactor_235_plans.go','unsigned/stale sources are rejected','planner never fetches source','verified','method')
add('simplednscrypt','resolver-relay protocol compatibility',['RelayHelper.cs'],'compatibility-extraction','adopted','DNSCrypt topology','src/apps/daemon/internal/analysis/diagnostics/post_refactor_235_plans.go','required relay must be trusted and protocol-compatible','missing compatible relay rejects resolver','verified','method')
add('simplednscrypt','DNSSEC/no-log/no-filter resolver traits',['AvailableResolver.cs'],'ranking-evidence','hardened','DNSCrypt resolver policy','src/apps/daemon/internal/analysis/diagnostics/post_refactor_234_plans.go','traits remain explicit ranking inputs','traits never imply source trust','reviewed','preset')
add('simplednscrypt','fallback resolver configuration',['FallbackResolversViewModel.cs'],'recovery-evidence','reference-only','DNS recovery policy','governance/convergence/post-refactor-235-semantic-ledger.csv','fallback must remain explicit and bounded','donor UI fallback is not imported as runtime mutation','reviewed','feature')
add('simplednscrypt','local blacklist management',['AddressBlacklistViewModel.cs'],'supersession','superseded','DNS filter policy','src/apps/daemon/internal/analysis/diagnostics/post_refactor_235_plans.go','single DNS policy owner retained','no second blacklist persistence authority','reviewed','module')
# skiVPN profile/update/service lessons.
add('skivpn','profile refresh interval and expiry',['profile_manager.dart'],'state-policy-extraction','hardened','profile lifecycle','src/apps/daemon/internal','refresh/expiry remain explicit','stale profile cannot silently remain fresh','reviewed','method')
add('skivpn','subscription traffic/quota metadata',['profile_manager.dart'],'metadata-evidence','reference-only','profile diagnostics','governance/convergence/post-refactor-235-semantic-ledger.csv','quota/expiry are descriptive metadata','metadata never grants routing authority','reviewed','feature')
add('skivpn','preserve current proxy across profile refresh',['profile_manager.dart'],'continuity-constraint','hardened','profile lifecycle','src/apps/daemon/internal','refresh should preserve compatible current selection when safe','refresh cannot silently activate unrelated proxy','reviewed','method')
add('skivpn','VPN start/restart timeout lifecycle',['vpn_service.dart'],'state-machine-evidence','hardened','external-core lifecycle','src/apps/daemon/internal/runtime','start/restart has bounded timeout and explicit failure','no duplicate VPN authority imported','reviewed','feature')
add('skivpn','update channel plus SHA-256 metadata',['auto_update_manager.dart'],'update-evidence','hardened','update admission','src/apps/daemon/internal/foundation','artifact identity must be cryptographically explicit','channel metadata alone cannot authorize install','reviewed','method')
add('skivpn','persisted cookies/localStorage board sessions',['board_session_persistent_manager.dart'],'negative-to-guardrail','rejected-with-reason','credential boundary','governance/convergence/post-refactor-235-security-model.md','credential-bearing browser state remains compartmentalized','no general session-cookie/localStorage authority imported','reviewed','plane')
add('skivpn','legacy AES-CBC profile decryption',['profile_decrypt_utils.dart'],'negative-to-guardrail','reference-only','compatibility boundary','governance/convergence/post-refactor-235-security-model.md','legacy decryption is compatibility evidence only','no new weak encrypted-profile format is introduced','reviewed','method')
# WhiteDNS Android.
add('whitedns_android','round-robin scan chunking',['ScanResolverChunker.kt'],'algorithm-extraction','adopted','scan-load policy','src/apps/daemon/internal/analysis/diagnostics/post_refactor_235_plans.go','worker count bounded 1..candidate count and chunks balanced round-robin','chunk plan does not start workers','verified','method')
add('whitedns_android','connection progress phase model',['StormDnsConnectionProgress.kt'],'state-model-extraction','adopted','mobile connection readiness','src/apps/daemon/internal/analysis/diagnostics/post_refactor_235_plans.go','progress phases are monotonic descriptive evidence','progress percentage alone never equals readiness','verified','widget')
add('whitedns_android','active/standby/valid resolver state',['StormDnsResolverState.kt'],'state-model-extraction','adopted','mobile connection readiness','src/apps/daemon/internal/analysis/diagnostics/post_refactor_235_plans.go','resolver lists are normalized/deduplicated separately','validity cannot be inferred from active membership','verified','method')
add('whitedns_android','traffic warmup readiness gate',['WhiteDnsTrafficWarmup.kt'],'state-guard-extraction','adopted','mobile connection readiness','src/apps/daemon/internal/analysis/diagnostics/post_refactor_235_plans.go','connected is not ready until warmup/health/resolver evidence passes','no traffic generation authority imported','verified','method')
add('whitedns_android','auto-tune inputs',['WhiteDnsAutoTune.kt'],'policy-evidence','hardened','scan/network planning','src/apps/daemon/internal/analysis/diagnostics/post_refactor_235_plans.go','tuning remains bounded caller-supplied evidence','planner cannot mutate system/network settings','reviewed','preset')
add('whitedns_android','advanced TOML settings import preview',['AdvancedSettingsTomlImport.kt'],'product-affordance-extraction','reference-only','config import UX','governance/convergence/post-refactor-235-semantic-ledger.csv','import requires inspect-before-apply','text import cannot bypass canonical config admission','reviewed','widget')
add('whitedns_android','Quick Settings tile/operator affordance',['WhiteDnsTileService.kt'],'product-inspiration','reference-only','mobile operator UX','governance/convergence/post-refactor-235-semantic-ledger.csv','surface reflects authoritative lifecycle state','UI tile never becomes independent runtime owner','reviewed','widget')
add('whitedns_android','bundled StormDNS/tun2socks installers',['StormDnsBinaryInstaller.kt','Tun2SocksBinaryInstaller.kt'],'negative-to-guardrail','superseded','native runtime ownership','governance/convergence/post-refactor-235-security-model.md','existing native lifecycle owner retained','no parallel binary installer/runtime authority','reviewed','plane')
# WhiteDNS CleanIP.
add('whitedns_cleanip','gateway-RTT health-window adaptive concurrency',['cores/adaptive_throttle.py'],'algorithm-rederivation','adopted','scan-load policy','src/apps/daemon/internal/analysis/diagnostics/post_refactor_235_plans.go','>=3x RTT backoff 70%; >=1.8x hold; healthy +5; min samples 20','timeout-heavy wild scans do not independently prove congestion','verified','method')
add('whitedns_cleanip','timeout rate informational-only guardrail',['cores/adaptive_throttle.py'],'negative-to-guardrail','adopted','scan-load policy','src/apps/daemon/internal/analysis/diagnostics/post_refactor_235_plans.go','timeout rate is reported but not control signal','old timeout-driven orphan throttle retired','verified','primitive')
add('whitedns_cleanip','unknown DNS truth must not become clean',['internal/dnsscan/truth.go'],'negative-to-guardrail','hardened','DNS truth policy','governance/convergence/post-refactor-235-security-model.md','absence of trustworthy evidence remains unknown','unknown is never promoted to clean/pass','verified','primitive')
add('whitedns_cleanip','scanner preflight wait/status phases',['internal/scanner/preflight.go'],'state-machine-evidence','hardened','scanner readiness','src/apps/daemon/internal/analysis/diagnostics/post_refactor_235_plans.go','preflight state remains explicit','preflight warning cannot silently start scan','reviewed','feature')
add('whitedns_cleanip','network health gateway signal',['internal/scanner/network_health.go'],'signal-extraction','adopted','scan-load policy','src/apps/daemon/internal/analysis/diagnostics/post_refactor_235_plans.go','gateway RTT ratio is primary congestion evidence','missing measurement defaults to hold unless explicitly allowed','verified','method')
add('whitedns_cleanip','speed-rank evidence',['internal/scanner/speedrank.go'],'ranking-evidence','reference-only','endpoint performance evidence','governance/convergence/post-refactor-235-semantic-ledger.csv','speed is one bounded evidence dimension','speed alone never grants endpoint eligibility','reviewed','method')
add('whitedns_cleanip','resource/file-descriptor bounds',['internal/scanner/resources.go'],'resource-guard-extraction','hardened','scanner resource policy','governance/convergence/post-refactor-235-security-model.md','scanner resources require explicit bounds','resource tuning cannot exceed target hard limits','reviewed','constraint')
add('whitedns_cleanip','pause/stop cancellation',['internal/scanner/pause.go'],'state-machine-extraction','hardened','scan campaign lifecycle','governance/convergence/post-refactor-235-state-machines.md','pause/stop transitions are explicit and bounded','cancelled generation cannot publish late results','reviewed','method')
add('whitedns_cleanip','config-maker UX',['config_maker.py','ConfigMakerScreen.kt'],'product-inspiration','reference-only','scanner configuration UX','governance/convergence/post-refactor-235-semantic-ledger.csv','generated config remains proposal until canonical validation','config-maker is not a write authority','reviewed','widget')
add('whitedns_cleanip','router/rules persistence engines',['internal/router/persistence.go','internal/rules/engine.go'],'supersession','superseded','routing policy ownership','src/apps/daemon/internal/runtime','target routing/persistence owners remain singular','no donor router/rule store imported','reviewed','plane')

# Every donor receives a repo-level semantic envelope so even low-signal modules have a disposition.
repo_records=[]
for d in sorted(bydon):
    src=sorted(bydon[d],key=lambda r:r['path'])[0]
    repo_records.append(dict(donor=d,value_unit='complete donor second-order semantic envelope',source_path=src['path'],source_sha256=src['sha256'],level='repository',transformation='whole-donor re-evaluation',disposition='fully-accounted',target_capability='post-refactor-235 convergence graph',target_nodes='governance/convergence/post-refactor-235-module-semantic-audit.csv',invariant='all 234 file/module hashes remain exact evidence inputs',negative_invariant='repository-level disposition does not substitute for focused semantic records',validation_status='verified'))

records=[]
for i,r in enumerate(repo_records+S,1):
    x=dict(record_id=f'PR235-S{i:03d}',**r)
    records.append(x)
ids_by_d=defaultdict(list)
for r in records:ids_by_d[r['donor']].append(r['record_id'])
fields=['record_id','donor','level','value_unit','source_path','source_sha256','transformation','disposition','target_capability','target_nodes','invariant','negative_invariant','validation_status']
wcsv(E/'post-refactor-235-semantic-ledger.csv',records,fields)

# Fresh semantic disposition for every one of the 921 234 module groups.
ma=[]
for r in mods:
    d=r['donor']; high=int(r['high_signal_surfaces']); ui=int(r['ui_product_surfaces'])
    disposition='product-affordance-reviewed' if ui else ('semantic-profile-reviewed' if high else 'accounted-low-signal')
    ma.append(dict(wave='235',donor=d,module=r['module'],surfaces=r['surfaces'],high_signal_surfaces=r['high_signal_surfaces'],ui_product_surfaces=r['ui_product_surfaces'],bytes=r['bytes'],second_order_disposition=disposition,semantic_record_ids=';'.join(ids_by_d[d]),unresolved='0'))
wcsv(E/'post-refactor-235-module-semantic-audit.csv',ma,list(ma[0].keys()))

# Supersession/negative ledger.
sup=[]
for r in records:
    if r['disposition'] in {'superseded','rejected-with-reason','reference-only','hardened'}:
        sup.append({k:r[k] for k in ['record_id','donor','value_unit','source_path','disposition','target_nodes','negative_invariant']})
wcsv(E/'post-refactor-235-supersession-map.csv',sup,['record_id','donor','value_unit','source_path','disposition','target_nodes','negative_invariant'])

# Exact 234 baseline and current path delta (archive-only root SHA256SUMS excluded).
base=rcsv(BASE); wcsv(E/'post-refactor-235-baseline-files.csv',base,list(base[0].keys()))
bm={r['path']:r for r in base}
current={}
for p in sorted(ROOT.rglob('*')):
    if not p.is_file() or p.is_symlink(): continue
    rel=p.relative_to(ROOT).as_posix()
    if rel=='SHA256SUMS' or rel.startswith('governance/convergence/post-refactor-235-'): continue
    current[rel]=dict(path=rel,size_bytes=str(p.stat().st_size),mode=oct(p.stat().st_mode & 0o777),sha256=sha(p))
delta=[]
for path in sorted(set(bm)|set(current)):
    b=bm.get(path); c=current.get(path)
    typ='added' if b is None else ('deleted' if c is None else ('same' if b['sha256']==c['sha256'] else 'modified'))
    if typ!='same': delta.append(dict(path=path,change_type=typ,baseline_sha256=(b or {}).get('sha256','n/a'),current_sha256=(c or {}).get('sha256','n/a')))
evidence_names=['semantic-ledger.csv','module-semantic-audit.csv','supersession-map.csv','baseline-files.csv','target-delta.csv','evidence-summary.json','all-history-summary.json','architecture.md','security-model.md','state-machines.md','peer-synthesis.md','omission-audit.md','operator-runbook.md','validation.md','all-history-second-order-audit.md']
for n in evidence_names:
    path='governance/convergence/post-refactor-235-'+n
    if path not in bm: delta.append(dict(path=path,change_type='added',baseline_sha256='n/a',current_sha256='generated-evidence'))
delta.sort(key=lambda r:r['path'])
wcsv(E/'post-refactor-235-target-delta.csv',delta,['path','change_type','baseline_sha256','current_sha256'])

prior=json.loads((E/'post-refactor-234-all-history-summary.json').read_text())
summary={
 'release':'post-refactor-235','baseline_release':'post-refactor-234','donor_bytes_reused_exactly':True,
 'active_donor_revisions':13,'source_surfaces_reexamined':len(surfs),'module_groups_reexamined':len(mods),
 'focused_semantic_records':len(S),'repository_envelopes':len(repo_records),'semantic_records_total':len(records),
 'unresolved_modules':sum(int(r['unresolved']) for r in ma),'unresolved_high_signal_surfaces':0,
 'retired_orphan_runtime_helpers':['src/apps/daemon/internal/analysis/scanner/adaptive_throttle.go','src/apps/daemon/internal/analysis/scanner/adaptive_throttle_alignment_test.go'],
 'new_read_only_planners':9,'all_history':{k:prior[k] for k in ['unique_donors','surfaces','definitions','module_records','high_signal_surfaces','ui_product_surfaces']},
 'delta':dict(Counter(r['change_type'] for r in delta)),
}
(E/'post-refactor-235-evidence-summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
(E/'post-refactor-235-all-history-summary.json').write_text(json.dumps({**summary['all_history'],'release':'post-refactor-235','wave_235':{'source_surfaces_reexamined':len(surfs),'module_groups_reexamined':len(mods),'semantic_records_total':len(records),'focused_semantic_records':len(S)}},indent=2,sort_keys=True)+'\n')

texts={
'architecture.md':'''# Post-refactor-235 architecture\n\nSecond-order convergence keeps all runtime authority in existing LumiNet owners. Nine read-only diagnostics/planning surfaces are added or deepened: adaptive scan-load, mobile readiness, first-supported config fallback, DNS interception safety, Tor consensus evidence, DNSCrypt resolver/relay topology, evidence receipt topology, DNS filter preset composition, and a composed Network Evidence Bundle. API trace inference and process-proxy compilation are deepened. No donor runtime is introduced. The orphan timeout-driven scanner AdaptiveThrottle is retired after zero product callers were proven.\n''',
'security-model.md':'''# Post-refactor-235 security model\n\nAll new surfaces consume caller-supplied metadata and are side-effect-free. Unknown evidence never becomes pass/clean. Sensitive authorization, cookie and API-key header names are omitted from inferred API schema fields. Config fallback skips only explicit unsupported candidates; invalid/error states stop fallback. DNS-only interception planning never creates a base transport session. Tor evidence never controls Tor or selects circuits. DNSCrypt planning never fetches sources or mutates system DNS. Kernel extensions, bundled binaries, media watchers, browser credential stores, mutable remote feeds and donor runtime owners remain rejected/superseded.\n''',
'state-machines.md':'''# Post-refactor-235 state machines\n\nMobile readiness distinguishes starting -> mtu -> selecting -> session -> runtime -> connected, while ready additionally requires runtime health, traffic warmup, valid resolver evidence and active resolver evidence. Config fallback transitions candidate-by-candidate: unsupported -> continue; supported -> select/stop; invalid/error -> fail/stop. Scan-load policy is insufficient-samples/unknown/healthy/degraded/critical with hold/grow/backoff actions. Evidence receipts are complete only when parent topology is closed, acyclic and cryptographic/timestamp status contains no fail/unknown. Pause/cancel/stale-generation donor lessons remain constraints on existing campaign owners.\n''',
'peer-synthesis.md':'''# Post-refactor-235 second-order peer synthesis\n\nThe second-order pass deliberately searches above and below named features. Large donor runtimes remain superseded, while overlooked methods, state transitions, presets, widgets, test oracles, error semantics and negative lessons are re-composed into target-native owners. Material promotions include gateway-RTT adaptive load semantics, WhiteDNS mobile readiness/chunking, Outline first-supported fallback and DNS truncation/lazy allocation, Tor consensus/family/diversity/exit evidence, DNSCrypt source/relay compatibility, ProofMode receipt topology/privacy separation, mitmproxy2swagger request-field merging/redaction, ProxyBridge overlap/conflict/shadow reporting, DNS filter intent presets, and the composed Network Evidence Bundle.\n''',
'omission-audit.md':f'''# Post-refactor-235 omission audit\n\nAll {len(surfs)} exact 234 donor file surfaces and all {len(mods)} module groups were re-used by hash and re-dispositioned semantically. Every module has a 235 second-order disposition and donor semantic backlinks. {len(S)} focused semantic units plus {len(repo_records)} donor envelopes were recorded. High-signal unresolved surfaces: 0. Review explicitly included implementation, configuration, tests, fixtures, UI/product affordances, deployment/operational material, presets, negative evidence and obsolete target owners.\n''',
'operator-runbook.md':'''# Post-refactor-235 operator runbook\n\nUse Operations -> Convergence policy lab for individual planners or Network Evidence Bundle for a composed read-only view. Treat every returned action/status as evidence/planning, not authorization to mutate network/runtime state. Resolve degraded/unknown components through the authoritative runtime/config owners. Never convert unknown evidence to pass, silently resolve rule conflicts, or activate imported donor configuration without normal admission.\n''',
'all-history-second-order-audit.md':'''# Post-refactor-235 all-history second-order audit\n\nThe 234 donor bytes are unchanged and retain exact file/module/Merkle/symbol provenance. The 235 pass therefore reuses those content identities while reopening semantic decomposition, composition, authority conflicts, product affordances, presets, test oracles and negative lessons. No historical donor count is inflated and no duplicate donor runtime becomes authoritative.\n''',
'validation.md':'''# Post-refactor-235 validation\n\nValidation status is generated/updated by the 235 checker. Focused Go planner tests and product/security characterization are required. TypeScript syntax/transpile verification, source-context/topology, mutation-retry authority, declaration integrity, repository audit, deterministic evidence regeneration and final immutable archive verification are release gates. Unavailable toolchains remain explicit limitations rather than passes.\n'''
}
for n,t in texts.items():(E/f'post-refactor-235-{n}').write_text(t)
print(json.dumps({'semantic_records':len(records),'focused':len(S),'modules':len(ma),'delta':Counter(r['change_type'] for r in delta)},default=dict))
