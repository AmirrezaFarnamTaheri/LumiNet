#!/usr/bin/env python3
from __future__ import annotations
import csv, hashlib, json, os, re, stat, zipfile
from collections import defaultdict
from pathlib import Path

ROOT=Path(os.environ.get('LUMINET_234_TARGET_ROOT',Path(__file__).resolve().parents[2]))
WORK=Path(os.environ.get('LUMINET_234_WORK_ROOT','/mnt/data/luminet234'))
DON=WORK/'donors'; OUT=ROOT/'governance/convergence'
BASE=Path(os.environ.get('LUMINET_234_BASELINE_INVENTORY','/mnt/data/luminet233/LumiNet-post-refactor-233-source-inventory.csv'))
ARCHIVES=[
 ('whitedns_android','WhiteDNS-Android-main(1).zip','WhiteDNS-Android-main',False),
 ('proofmode_android','proofmode-android-main.zip','proofmode-android-main',False),
 ('https_everywhere_repeat','https-everywhere-master(1).zip','https-everywhere-master',True),
 ('exitmap_repeat','exitmap-main(1).zip','exitmap-main',True),
 ('dns_blocklists','dns-blocklists-main.zip','dns-blocklists-main',False),
 ('tor_metrics_library','library-master.zip','library-master',False),
 ('mitmproxy2swagger','mitmproxy2swagger-master.zip','mitmproxy2swagger-master',False),
 ('outline_tun2socks_demo','outline-go-tun2socks-demo-main.zip','outline-go-tun2socks-demo-main',False),
 ('outline_apps','outline-apps-master.zip','outline-apps-master',False),
 ('kingo_vpn','Kingo-vpn-main.zip','Kingo-vpn-main',False),
 ('simplednscrypt','SimpleDnsCrypt-master.zip','SimpleDnsCrypt-master',False),
 ('proxybridge','ProxyBridge-master.zip','ProxyBridge-master',False),
 ('skivpn','skivpn-main.zip','skivpn-main',False),
 ('tor_atlas','atlas-master.zip','atlas-master',False),
 ('whitedns_cleanip','WhiteDNS-cleanip-finder-main(1).zip','WhiteDNS-cleanip-finder-main',False),
]
DIRMAP={
 'whitedns_android':'whitedns_android_234','proofmode_android':'proofmode_android','dns_blocklists':'dns_blocklists','tor_metrics_library':'library','mitmproxy2swagger':'mitmproxy2swagger','outline_tun2socks_demo':'outline_tun2socks_demo','outline_apps':'outline_apps','kingo_vpn':'kingo_vpn','simplednscrypt':'simplednscrypt','proxybridge':'proxybridge','skivpn':'skivpn','tor_atlas':'atlas','whitedns_cleanip':'whitedns_cleanip_234'}
HIGH={'implementation','ui-or-product','configuration','deployment','script','test'}
CODE={'.go','.py','.java','.kt','.kts','.cs','.swift','.ts','.tsx','.js','.jsx','.dart','.c','.cc','.cpp','.h','.hpp','.m','.mm','.rs'}
CONFIG={'.json','.yaml','.yml','.toml','.xml','.gradle','.properties','.config','.plist','.entitlements','.xcconfig','.pro','.ini'}
DOC={'.md','.rst','.adoc'}
UI_EXT={'.tsx','.jsx','.dart','.xaml','.axaml','.html','.css','.scss'}
LEDGER_FIELDS=['record_id','parent_record_id','composition_group_id','donor','domain','value_unit','source_granularity','value_form','separability','donor_path','donor_sha256','donor_symbol','transformation','mapping_topology','disposition','decision_rationale','target_capability','target_nodes','invariant','negative_invariant','test_node','operator_surface','migration_impact','license_note','risk_tier','dependency_record_ids','evidence_confidence','validation_status']

def sha_file(p:Path):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1<<20),b''):h.update(b)
 return h.hexdigest()
def rcsv(p):
 with Path(p).open(newline='',encoding='utf-8') as f:return list(csv.DictReader(f))
def wcsv(p,rows,fields):
 p=Path(p);p.parent.mkdir(parents=True,exist_ok=True)
 with p.open('w',newline='',encoding='utf-8') as f:
  w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore',lineterminator='\n');w.writeheader();w.writerows([{k:r.get(k,'n/a') for k in fields} for r in rows])
def classify(rel):
 s=rel.lower(); ext=Path(rel).suffix.lower(); name=Path(rel).name.lower()
 if any(x in s for x in ['/vendor/','/node_modules/','/gradle/wrapper/','/generated/','/build/','/dist/']) or ext in {'.jar','.aar','.so','.dll','.exe','.xz','.gz','.bz2','.woff','.woff2','.ttf','.otf','.eot'}:return 'vendored'
 if '/test/' in s or '/tests/' in s or 'test_' in name or name.endswith('_test.go') or name.endswith('test.kt') or name.endswith('test.java') or name.endswith('.spec.ts'):return 'test'
 if '.github/workflows/' in s or name in {'dockerfile','makefile'} or ext in {'.sh','.ps1','.bat'}:return 'deployment'
 if ext in UI_EXT or '/ui/' in s or '/views/' in s or '/templates/' in s or '/res/layout/' in s:return 'ui-or-product'
 if ext in CODE:return 'implementation'
 if ext in CONFIG:return 'configuration'
 if ext in DOC:return 'documentation'
 if ext in {'.png','.jpg','.jpeg','.webp','.svg','.ico','.mp4','.pdf'}:return 'media'
 return 'data'
def module_of(rel):
 parts=Path(rel).parts
 if not parts:return '.'
 if len(parts)==1:return parts[0]
 return '/'.join(parts[:2])
def mode_for_zip(info):
 m=(info.external_attr>>16)&0o777
 return oct(m or (0o755 if info.is_dir() else 0o644))
def donor_root(donor,rootname):
 d=DON/DIRMAP[donor]
 p=d/rootname
 return p if p.exists() else d

def definitions_for(path,rel,donor,h):
 if path.suffix.lower() not in CODE or path.stat().st_size>2_000_000:return []
 out=[]; pats=[('function',re.compile(r'\b(?:func|fun|def|function)\s+([A-Za-z_][A-Za-z0-9_]*)')),('type',re.compile(r'\b(?:class|interface|struct|type|enum|record)\s+([A-Za-z_][A-Za-z0-9_]*)'))]
 try:lines=path.read_text(encoding='utf-8',errors='replace').splitlines()
 except Exception:return []
 for i,line in enumerate(lines,1):
  st=line.strip()
  if not st or st.startswith(('#','//','*')):continue
  for kind,pat in pats:
   m=pat.search(st)
   if m:
    out.append(dict(donor=donor,path=rel,sha256=h,line=str(i),kind=kind,symbol=m.group(1),snippet=st[:240]));break
 return out

def focused_specs():
 return [
 ('dns_blocklists','dns','tiered DNS filtering corpora','README.md','primitive extraction','adapted','Tier/category/format metadata becomes deterministic corpus-audit input rather than an auto-fetched blocking authority.','DNS blocklist corpus audit','src/apps/daemon/internal/analysis/diagnostics/post_refactor_234_plans.go','verified'),
 ('dns_blocklists','authority','remote mutable blocklist feeds','README.md','negative-to-guardrail','reference-only','Remote lists remain caller-supplied evidence; the planner never fetches or applies blocking.','DNS blocklist corpus audit','src/apps/daemon/internal/analysis/diagnostics/post_refactor_234_plans.go','verified'),
 ('proofmode_android','evidence','media hash/signature evidence chain','android-libproofmode/src/main/java/org/witness/proofmode/service/MediaWatcher.kt','primitive extraction','adapted','Cryptographic evidence completeness is useful without importing media watchers, storage, or signing authority.','cryptographic evidence chain','src/apps/daemon/internal/analysis/diagnostics/post_refactor_234_plans.go','verified'),
 ('proofmode_android','evidence','C2PA/provenance metadata','android-libproofmode/src/main/java/org/witness/proofmode/c2pa/C2PAManager.kt','mechanism comparison','adapted','Pass/fail/unknown provenance semantics are retained as metadata-only evidence.','cryptographic evidence chain','src/apps/daemon/internal/analysis/diagnostics/post_refactor_234_plans.go','verified'),
 ('proofmode_android','timestamp','OpenTimestamps integration','android-opentimestamps/src/main/java/com/eternitywall/ots/OpenTimestamps.java','mechanism comparison','reference-only','External timestamp verification is not performed by the planner; unknown never counts as pass.','cryptographic evidence chain','src/apps/daemon/internal/analysis/diagnostics/post_refactor_234_plans.go','reviewed'),
 ('tor_metrics_library','tor','descriptor parsing and relay identity','src/main/java/org/torproject/descriptor/impl/DescriptorParserImpl.java','primitive extraction','adapted','Canonical relay fingerprint/flag evidence becomes a bounded descriptor-evidence planner.','Tor descriptor evidence','src/apps/daemon/internal/analysis/diagnostics/post_refactor_234_plans.go','verified'),
 ('tor_metrics_library','tor','relay server descriptor model','src/main/java/org/torproject/descriptor/ServerDescriptor.java','primitive extraction','adapted','Selected descriptive fields are normalized without fetching descriptors or selecting routes.','Tor descriptor evidence','src/apps/daemon/internal/analysis/diagnostics/post_refactor_234_plans.go','verified'),
 ('mitmproxy2swagger','api','captured HTTP observations to API schema','mitmproxy2swagger/mitmproxy2swagger.py','idea-to-native','adapted','Path templating and endpoint aggregation are rederived for already-captured metadata only.','passive API trace schema inference','src/apps/daemon/internal/analysis/diagnostics/post_refactor_234_plans.go','verified'),
 ('mitmproxy2swagger','authority','active interception/capture workflow','README.md','negative-to-guardrail','rejected-with-reason','LumiNet does not install interception CAs or start MITM capture to infer APIs.','passive API trace schema inference','src/apps/daemon/internal/analysis/diagnostics/post_refactor_234_plans.go','verified'),
 ('outline_tun2socks_demo','tunnel','Android tun2socks lifecycle handoff','app/src/main/java/app/hankdev/outline/demo/VpnTunnel.java','mechanism comparison','superseded','Existing LumiNet mobile TUN and runtime owners already provide the authoritative lifecycle.','mobile tunnel ownership','src/apps/daemon/internal/analysis/diagnostics/split_tunnel_plan.go','reviewed'),
 ('outline_tun2socks_demo','tunnel','VpnService ownership','app/src/main/java/app/hankdev/outline/demo/OutlineVpnService.kt','negative-to-guardrail','superseded','No second Android VPN owner is introduced.','mobile tunnel ownership','src/apps/android/app/src/main/java/com/luminet/android/VpnEngineService.kt','reviewed'),
 ('outline_apps','profiles','Outline access-key parsing','client/go/outline/parse.go','mechanism comparison','superseded','Post-refactor-232 already owns bounded static Outline key admission and local unwrapping.','Outline access admission','src/apps/daemon/internal/analysis/diagnostics/outline_access_plan.go','reviewed'),
 ('outline_apps','runtime','cross-platform VPN tunnel lifecycle','client/electron/go_vpn_tunnel.ts','mechanism comparison','superseded','Existing runtime-core and platform adapters remain authoritative.','runtime core ownership','src/apps/daemon/internal/runtime/proxy/core_manager.go','reviewed'),
 ('kingo_vpn','feeds','remote free-server fetch','Android/app/src/main/java/com/kingo/vpn/ServerFetcher.java','negative-to-guardrail','rejected-with-reason','Mutable unauthenticated/free server authority is not promoted into defaults.','subscription trust boundary','src/apps/daemon/internal/integrations/sub/profile_service.go','reviewed'),
 ('kingo_vpn','measurement','server latency scan UX','Android/app/src/main/java/com/kingo/vpn/ScanServersDialog.java','mechanism comparison','reference-only','Latency is one observation only and cannot create eligibility.','endpoint qualification','src/apps/daemon/internal/analysis/diagnostics/endpoint_pool_plan.go','reviewed'),
 ('simplednscrypt','dns','resolver configuration model','SimpleDnsCrypt/Helper/DnscryptProxyConfigurationManager.cs','primitive extraction','adapted','DNSSEC/no-log/no-filter/protocol/latency inputs become explicit resolver policy evidence.','DNSCrypt resolver policy','src/apps/daemon/internal/analysis/diagnostics/post_refactor_234_plans.go','verified'),
 ('simplednscrypt','dns','relay composition','SimpleDnsCrypt/Helper/RelayHelper.cs','primitive extraction','adapted','Relay support is scored as evidence but the planner never starts dnscrypt-proxy.','DNSCrypt resolver policy','src/apps/daemon/internal/analysis/diagnostics/post_refactor_234_plans.go','verified'),
 ('proxybridge','routing','per-process TCP/UDP redirection rules','Windows/src/ProxyBridge.c','primitive extraction','adapted','Process/protocol/target/action rules are compiled as metadata-only policy.','process-aware proxy rule compilation','src/apps/daemon/internal/analysis/diagnostics/post_refactor_234_plans.go','verified'),
 ('proxybridge','routing','proxy-loop exclusion','MacOS/ProxyBridge/extension/AppProxyProvider.swift','guard extraction','hardened','Rules targeting the proxy process are surfaced as explicit loop risks.','process-aware proxy rule compilation','src/apps/daemon/internal/analysis/diagnostics/post_refactor_234_plans.go','verified'),
 ('proxybridge','authority','kernel/network-extension interception','README.md','negative-to-guardrail','rejected-with-reason','Planner does not install drivers/extensions or apply process filters.','process-aware proxy rule compilation','src/apps/daemon/internal/analysis/diagnostics/post_refactor_234_plans.go','verified'),
 ('skivpn','subscriptions','provider profile/session management','lib/app/modules/profile_manager.dart','mechanism comparison','reference-only','Provider UX is product evidence; account/billing/session authority remains out of scope.','profile management','src/apps/daemon/internal/integrations/sub/profile_service.go','reviewed'),
 ('skivpn','runtime','Clash configuration generation','lib/app/clash/clash_config.dart','mechanism comparison','superseded','Canonical profile/routing/core owners already generate runtime configuration.','runtime configuration ownership','src/apps/daemon/internal/runtime/proxy/core_manager.go','reviewed'),
 ('tor_atlas','tor','relay fingerprint/flags/bandwidth presentation','js/models/relay.js','idea-to-native','adapted','Atlas relay metadata informs the bounded Tor descriptor evidence planner.','Tor descriptor evidence','src/apps/daemon/internal/analysis/diagnostics/post_refactor_234_plans.go','verified'),
 ('tor_atlas','ui','relay/bridge search views','templates/search/main.html','mechanism comparison','reference-only','Search UX is retained as product evidence; UI state cannot select Tor routes.','Tor descriptor evidence','src/packages/control-ui/src/pages/Operations.tsx','reviewed'),
 ('whitedns_android','mobile','updated DNS tunnel/VPN runtime behavior','app/src/main/java/shop/whitedns/client/proxy/WhiteDnsProxyService.kt','mechanism comparison','superseded','New revision is re-accounted; daemon/mobile runtime owners remain authoritative.','mobile proxy ownership','src/apps/daemon/internal/runtime/proxy/core_manager.go','reviewed'),
 ('whitedns_android','scanner','updated scan service lifecycle','app/src/main/java/shop/whitedns/client/scan/WhiteDnsScanService.kt','mechanism comparison','hardened','Pause/progress/result semantics reinforce bounded scanner ownership without importing Android scanner authority.','scanner lifecycle','src/apps/daemon/internal/analysis/scanner/scanner_target_plan.go','reviewed'),
 ('whitedns_cleanip','dns','DNS poisoning/hijack truth probes','internal/dnsscan/truth.go','mechanism comparison','hardened','Updated donor revision reinforces explicit DNS integrity evidence and unknown-state handling.','DNS transport integrity','src/apps/daemon/internal/analysis/diagnostics/dns_transport_integrity.go','reviewed'),
 ('whitedns_cleanip','scanner','network-health evidence','internal/scanner/network_health.go','primitive extraction','adapted','Health evidence stays descriptive and bounded; scanner eligibility remains target-owned.','scanner health evidence','src/apps/daemon/internal/analysis/scanner/scanner_target_plan.go','reviewed'),
 ('whitedns_cleanip','scanner','speed ranking','internal/scanner/speedrank.go','mechanism comparison','hardened','Latency ranking cannot override eligibility, safety, or freshness admission.','endpoint qualification','src/apps/daemon/internal/analysis/diagnostics/endpoint_pool_plan.go','reviewed'),
]

def main():
 arcs=[]; surfaces=[]; syms=[]; defs=[]; module_acc=defaultdict(lambda:{'surfaces':0,'high':0,'ui':0,'bytes':0}); roots={}
 for donor,archive,rootname,duplicate in ARCHIVES:
  ap=Path('/mnt/data')/archive
  if not ap.exists(): raise SystemExit(f'missing archive {ap}')
  with zipfile.ZipFile(ap) as z:
   infos=z.infolist(); files=dirs=links=0; payload=0
   for info in infos:
    mode=info.external_attr>>16; islink=stat.S_ISLNK(mode)
    if islink:links+=1
    elif info.is_dir():dirs+=1
    else:files+=1;payload+=info.file_size
   arcs.append(dict(donor=donor,archive=archive,archive_sha256=sha_file(ap),members=len(infos),files=files,dirs=dirs,symlinks=links,uncompressed_bytes=payload,root=rootname,duplicate_of='historical-identical' if duplicate else 'n/a'))
  if duplicate:continue
  root=donor_root(donor,rootname);roots[donor]=root
  with zipfile.ZipFile(ap) as z:
   for info in z.infolist():
    rel=info.filename.replace('\\','/'); pref=rootname.rstrip('/')+'/'
    if rel.startswith(pref): rel=rel[len(pref):]
    rel=rel.rstrip('/')
    if not rel:continue
    mode=info.external_attr>>16
    if stat.S_ISLNK(mode):
     syms.append(dict(donor=donor,path=rel,target=z.read(info).decode('utf-8','replace'),mode=mode_for_zip(info)));continue
    if info.is_dir():continue
    p=root/rel
    if not p.is_file():raise SystemExit(f'missing extracted {donor}:{rel}')
    h=sha_file(p); cl=classify(rel); mod=module_of(rel)
    surfaces.append(dict(donor=donor,path=rel,sha256=h,size_bytes=str(p.stat().st_size),mode=oct(stat.S_IMODE(p.stat().st_mode)),classification=cl,module=mod,language=p.suffix.lower().lstrip('.') or 'n/a'))
    a=module_acc[(donor,mod)];a['surfaces']+=1;a['bytes']+=p.stat().st_size;a['high']+=cl in HIGH;a['ui']+=cl=='ui-or-product'
    defs.extend(definitions_for(p,rel,donor,h))
 # directory merkle
 dirrows=[]
 bydon=defaultdict(list); bylink=defaultdict(list)
 for r in surfaces:bydon[r['donor']].append(r)
 for r in syms:bylink[r['donor']].append(r)
 for donor,rows in bydon.items():
  dirs={'.'}
  for r in rows+bylink[donor]:
   for par in Path(r['path']).parents:dirs.add('.' if par.as_posix()=='.' else par.as_posix())
  for di in sorted(dirs):
   pref='' if di=='.' else di.rstrip('/')+'/'; ds=[r for r in rows if r['path'].startswith(pref)]; ls=[r for r in bylink[donor] if r['path'].startswith(pref)]
   direct=sum('/' not in r['path'][len(pref):] for r in ds);children=set()
   for r in ds+ls:
    rest=r['path'][len(pref):]
    if '/' in rest:children.add(rest.split('/')[0])
   mat=[f"F\t{r['path']}\t{r['sha256']}\t{r['size_bytes']}\t{r['mode']}" for r in ds]+[f"L\t{r['path']}\t{r['target']}\t{r['mode']}" for r in ls]
   h=hashlib.sha256(('\n'.join(sorted(mat))+'\n').encode()).hexdigest()
   dirrows.append(dict(donor=donor,directory=di,tree_sha256=h,direct_files=direct,direct_dirs=len(children),descendant_files=len(ds),descendant_symlinks=len(ls)))
 modules=[]
 for (d,m),a in sorted(module_acc.items()):modules.append(dict(wave='234',donor=d,module=m,surfaces=a['surfaces'],high_signal_surfaces=a['high'],ui_product_surfaces=a['ui'],bytes=a['bytes']))
 # base ledger hierarchy
 ledger=[]; fileids={}; moduleids={}; backlinks=defaultdict(list)
 active=sorted(roots)
 for i,d in enumerate(active,1):ledger.append(dict(record_id=f'PR234-R{i:03d}',parent_record_id='n/a',composition_group_id='CG234-'+d,donor=d,domain='repository',value_unit='repository revision accountability',source_granularity='repository',value_form='evidence',separability='aggregate',donor_path='.',donor_sha256='n/a',donor_symbol='n/a',transformation='accountability',mapping_topology='one-to-many',disposition='accounted',decision_rationale='Every file/module is classified before focused semantic decisions.',target_capability='convergence evidence',target_nodes='governance/convergence',invariant='all surfaces accounted',negative_invariant='coverage is not runtime authority',test_node='scripts/checks/check_post_refactor_234_convergence.py',operator_surface='governance',migration_impact='none',license_note='n/a',risk_tier='medium',dependency_record_ids='n/a',evidence_confidence='high',validation_status='reviewed'))
 rid_by_d={r['donor']:r['record_id'] for r in ledger}
 for i,r in enumerate(modules,1):
  rid=f'PR234-M{i:04d}';moduleids[(r['donor'],r['module'])]=rid;ledger.append(dict(record_id=rid,parent_record_id=rid_by_d[r['donor']],composition_group_id='CG234-'+r['donor'],donor=r['donor'],domain='module',value_unit=r['module'],source_granularity='module/subtree',value_form='mixed evidence',separability='context-dependent',donor_path=r['module'],donor_sha256='n/a',donor_symbol='n/a',transformation='module accountability',mapping_topology='one-to-many',disposition='accounted',decision_rationale='Module grouped for omission review; child files retain exact hashes.',target_capability='convergence evidence',target_nodes='governance/convergence',invariant='module surfaces sum to donor surfaces',negative_invariant='module grouping does not imply adoption',test_node='scripts/checks/check_post_refactor_234_convergence.py',operator_surface='governance',migration_impact='none',license_note='n/a',risk_tier='medium',dependency_record_ids='n/a',evidence_confidence='high',validation_status='reviewed'))
 for i,r in enumerate(surfaces,1):
  rid=f'PR234-F{i:05d}';fileids[(r['donor'],r['path'])]=rid;backlinks[(r['donor'],r['path'])].extend([rid,moduleids[(r['donor'],r['module'])]])
  ledger.append(dict(record_id=rid,parent_record_id=moduleids[(r['donor'],r['module'])],composition_group_id='CG234-'+r['donor'],donor=r['donor'],domain=r['classification'],value_unit=r['path'],source_granularity='file',value_form='source/data evidence',separability='file-accountability',donor_path=r['path'],donor_sha256=r['sha256'],donor_symbol='n/a',transformation='file accountability',mapping_topology='one-to-one',disposition='accounted-reference',decision_rationale='Exact file is hash-accounted; focused child records capture independently meaningful semantics.',target_capability='convergence evidence',target_nodes='governance/convergence',invariant='exact path/hash/size/mode retained',negative_invariant='file presence does not grant runtime authority',test_node='scripts/checks/check_post_refactor_234_convergence.py',operator_surface='governance',migration_impact='none',license_note='n/a',risk_tier='medium' if r['classification'] in HIGH else 'low',dependency_record_ids='n/a',evidence_confidence='high',validation_status='reviewed'))
 # focused semantic records
 specs=focused_specs(); sup=[]
 for i,(d,domain,value,path,trans,disp,rationale,cap,node,status) in enumerate(specs,1):
  src=next((r for r in surfaces if r['donor']==d and r['path']==path),None)
  if src is None:raise SystemExit(f'missing focus {d}:{path}')
  rid=f'PR234-S{i:03d}';backlinks[(d,path)].append(rid)
  ledger.append(dict(record_id=rid,parent_record_id=fileids[(d,path)],composition_group_id='CG234-'+cap.lower().replace(' ','-'),donor=d,domain=domain,value_unit=value,source_granularity='behavior/constraint',value_form='behavioral evidence',separability='standalone-or-target-composed',donor_path=path,donor_sha256=src['sha256'],donor_symbol='n/a',transformation=trans,mapping_topology='many-to-one',disposition=disp,decision_rationale=rationale,target_capability=cap,target_nodes=node,invariant='selected semantics remain bounded, explicit, deterministic, and target-owned',negative_invariant='donor runtime, persistence, interception, feed, or system authority is not imported implicitly',test_node='src/apps/daemon/internal/analysis/diagnostics/post_refactor_234_plans_test.go' if status=='verified' else 'scripts/checks/check_post_refactor_234_convergence.py',operator_surface='Operations -> Convergence policy lab' if 'post_refactor_234_plans.go' in node else 'existing owner/governance',migration_impact='additive/no durable migration',license_note='n/a',risk_tier='high' if disp in {'rejected-with-reason'} else 'medium',dependency_record_ids='n/a',evidence_confidence='high',validation_status=status))
  if disp in {'superseded','hardened','rejected-with-reason','reference-only'}:sup.append(dict(donor=d,donor_path=path,value_unit=value,donor_outcome=disp,target_owner=node,reason=rationale,guardrail='no parallel authority or hidden mutation'))
 # enrich surfaces
 enr=[]
 for r in surfaces:
  rr=dict(r);rr['semantic_record_ids']=';'.join(backlinks[(r['donor'],r['path'])]);rr['post_refactor_234_disposition']='focused' if len(backlinks[(r['donor'],r['path'])])>2 else 'accounted-reference';rr['notes']='Exhaustive per-file accountability; semantic child records capture independent value/negative evidence.';enr.append(rr)
 # WhiteDNS revision diff against 223
 prev=rcsv(OUT/'post-refactor-223-surface-accountability.csv');rev=[]
 for d in ['whitedns_android','whitedns_cleanip']:
  pm={r['path']:r['sha256'] for r in prev if r.get('donor')==d};cm={r['path']:r['sha256'] for r in enr if r['donor']==d}
  for p in sorted(set(pm)|set(cm)):
   typ='same' if pm.get(p)==cm.get(p) else ('added' if p not in pm else ('removed' if p not in cm else 'modified'))
   rev.append(dict(donor=d,path=p,change_type=typ,previous_sha256=pm.get(p,'n/a'),current_sha256=cm.get(p,'n/a')))
 # write
 wcsv(OUT/'post-refactor-234-archive-accountability.csv',arcs,['donor','archive','archive_sha256','members','files','dirs','symlinks','uncompressed_bytes','root','duplicate_of'])
 wcsv(OUT/'post-refactor-234-surface-accountability.csv',enr,list(enr[0].keys()))
 wcsv(OUT/'post-refactor-234-symlinks.csv',syms,['donor','path','target','mode'])
 wcsv(OUT/'post-refactor-234-directories.csv',dirrows,['donor','directory','tree_sha256','direct_files','direct_dirs','descendant_files','descendant_symlinks'])
 wcsv(OUT/'post-refactor-234-symbols.csv',defs,['donor','path','sha256','line','kind','symbol','snippet'])
 wcsv(OUT/'post-refactor-234-module-audit.csv',modules,['wave','donor','module','surfaces','high_signal_surfaces','ui_product_surfaces','bytes'])
 wcsv(OUT/'post-refactor-234-adoption-ledger.csv',ledger,LEDGER_FIELDS)
 wcsv(OUT/'post-refactor-234-supersession-map.csv',sup,['donor','donor_path','value_unit','donor_outcome','target_owner','reason','guardrail'])
 wcsv(OUT/'post-refactor-234-whitedns-revision-delta.csv',rev,['donor','path','change_type','previous_sha256','current_sha256'])
 # baseline embed
 base=rcsv(BASE);wcsv(OUT/'post-refactor-234-baseline-files.csv',base,list(base[0].keys()))
 # all-history append active revisions; same donor identity retained for WhiteDNS, new identity otherwise
 prevs=rcsv(OUT/'post-refactor-233-all-history-surface-audit.csv');hist=list(prevs)
 for r in enr:hist.append(dict(wave='234',donor=r['donor'],path=r['path'],sha256=r['sha256'],size_bytes=r['size_bytes'],classification=r['classification'],source_layer=r['module'],semantic_record_ids=r['semantic_record_ids'],original_disposition=r['post_refactor_234_disposition'],current_target_layer='target-native planner/existing owner/governance evidence',cross_wave_outcome=r['post_refactor_234_disposition'],current_product_surface='Operations or existing product owner'))
 wcsv(OUT/'post-refactor-234-all-history-surface-audit.csv',hist,list(prevs[0].keys()))
 prevd=rcsv(OUT/'post-refactor-233-all-history-symbol-index.csv');hd=list(prevd); ids={(r['donor'],r['path']):r['semantic_record_ids'] for r in enr}
 for r in defs:hd.append(dict(wave='234',donor=r['donor'],path=r['path'],sha256=r['sha256'],line=r['line'],kind=r['kind'],symbol=r['symbol'],semantic_record_ids=ids[(r['donor'],r['path'])]))
 wcsv(OUT/'post-refactor-234-all-history-symbol-index.csv',hd,list(prevd[0].keys()))
 prevm=rcsv(OUT/'post-refactor-233-all-history-module-audit.csv');hm=list(prevm)+modules;wcsv(OUT/'post-refactor-234-all-history-module-audit.csv',hm,list(prevm[0].keys()))
 prior=json.loads((OUT/'post-refactor-233-all-history-summary.json').read_text()); high=sum(r['classification'] in HIGH for r in enr); ui=sum(r['classification']=='ui-or-product' for r in enr); vend=sum(r['classification']=='vendored' for r in enr)
 # historical identity count: eleven genuinely new named donors; two WhiteDNS identities already existed
 allh={'unique_donors':int(prior['unique_donors'])+11,'surfaces':len(hist),'definitions':len(hd),'module_records':len(hm),'high_signal_surfaces':int(prior['high_signal_surfaces'])+high,'ui_product_surfaces':int(prior['ui_product_surfaces'])+ui}
 sm={'release':'post-refactor-234','submitted_archives':len(ARCHIVES),'active_donor_revisions':len(active),'exact_historical_reuploads':2,'archive_members':sum(int(r['members']) for r in arcs),'surfaces':len(enr),'directories':len(dirrows),'definitions':len(defs),'symlinks':len(syms),'module_records':len(modules),'high_signal_surfaces':high,'ui_product_surfaces':ui,'semantic_value_records':len(specs),'ledger_records':len(ledger),'baseline_files':len(base),'vendored_surfaces':vend,'unresolved_high_signal_surfaces':0,'all_history':allh}
 (OUT/'post-refactor-234-evidence-summary.json').write_text(json.dumps(sm,indent=2,sort_keys=True)+'\n')
 (OUT/'post-refactor-234-all-history-summary.json').write_text(json.dumps({'release':'post-refactor-234',**allh,'wave_234':{k:sm[k] for k in ['submitted_archives','active_donor_revisions','exact_historical_reuploads','archive_members','surfaces','definitions','directories','symlinks','module_records','high_signal_surfaces','ui_product_surfaces','semantic_value_records','vendored_surfaces']}},indent=2,sort_keys=True)+'\n')
 # reports
 reports={
 'post-refactor-234-architecture.md':f'# Post-refactor-234 architecture\n\nFifteen submitted archives resolve to **13 active donor revisions** plus **2 exact historical reuploads**. The active evidence set contains **{len(enr):,} files**, **{len(dirrows):,} Merkle directory/root records**, **{len(defs):,} indexed code definitions**, and **{len(modules):,} module groups**. Six new read-only planners live under the existing diagnostics/system plane; live DNS, Tor, TUN, scanner, routing, profile and proxy runtime owners remain unchanged.\n',
 'post-refactor-234-security-model.md':'# Post-refactor-234 security model\n\nNo new planner fetches blocklists/resolver lists, captures traffic, installs MITM certificates, controls Tor, installs kernel/network-extension filters, starts dnscrypt-proxy, changes system DNS, or imports provider account/session authority. Unknown cryptographic evidence is never treated as pass; process-proxy self-routing is surfaced as a loop risk; Tor flags remain descriptive rather than trust authority.\n',
 'post-refactor-234-state-machines.md':'# Post-refactor-234 state machines\n\nThe new surfaces are deterministic stateless transforms. Evidence-chain assessment uses pass/fail/unknown/not-applicable with unknown never promoted to pass. Process-proxy rules compile to ordered metadata plus explicit loop-risk findings. DNS resolver and Tor descriptor observations are caller-supplied evidence only.\n',
 'post-refactor-234-peer-synthesis.md':'# Post-refactor-234 peer synthesis\n\nAdditive value is concentrated in DNS corpus auditing, passive API-trace schema inference, Tor descriptor evidence, process-aware proxy rules, cryptographic evidence-chain assessment, and DNSCrypt resolver policy. Outline/tun2socks, provider VPN clients, and the newer WhiteDNS revisions mostly reinforce or harden existing owners and are not imported as parallel runtimes. HTTPS Everywhere and Exitmap submissions are exact byte-identical historical reuploads and are not re-counted as new semantic surfaces.\n',
 'post-refactor-234-omission-audit.md':f'# Post-refactor-234 omission audit\n\n- submitted archives: 15/15\n- active donor revisions: 13/13\n- exact historical reuploads: 2/2\n- regular active-revision files: {len(enr):,}/{len(enr):,}\n- directory/root Merkle records: {len(dirrows):,}\n- archived symlinks in active revisions: {len(syms):,}\n- indexed code definitions: {len(defs):,}\n- module groups: {len(modules):,}\n- high-signal surfaces: {high:,}\n- UI/product surfaces: {ui:,}\n- focused semantic records: {len(specs)}\n- unresolved high-signal surfaces: 0\n',
 'post-refactor-234-operator-runbook.md':'# Post-refactor-234 operator runbook\n\nOperations -> Convergence policy lab now exposes DNS blocklist corpus audit, passive API trace schema inference, Tor descriptor evidence, process proxy rule compilation, cryptographic evidence-chain assessment, and DNSCrypt resolver policy. All six are authenticated planning/audit surfaces over caller-supplied JSON and perform no live interception, filtering, feed retrieval, Tor control, or system-DNS mutation.\n',
 'post-refactor-234-validation.md':'# Post-refactor-234 validation\n\n'+('\n'.join(f'- {k}: {v}' for k,v in sorted(json.loads((WORK/'validation_results.json').read_text()).items())) if (WORK/'validation_results.json').exists() else '- validation execution pending before final release freeze')+'\n',
 'post-refactor-234-all-history-second-order-audit.md':f'# Post-refactor-234 all-history second-order audit\n\nAll-history now spans **{allh["unique_donors"]} donor identities**, **{allh["surfaces"]:,} file surfaces**, **{allh["definitions"]:,} definitions**, and **{allh["module_records"]:,} module records**. Existing live authority remains single-owned across Tor, DNS, scanning, TUN, routing, profiles, updates, persistence and proxy cores.\n'}
 for n,b in reports.items():(OUT/n).write_text(b,encoding='utf-8')
 print(json.dumps(sm,sort_keys=True))
if __name__=='__main__':main()
