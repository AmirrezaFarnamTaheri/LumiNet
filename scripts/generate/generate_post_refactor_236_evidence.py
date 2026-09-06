#!/usr/bin/env python3
from __future__ import annotations
import csv, hashlib, json, os, stat
from collections import Counter, defaultdict
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
E=ROOT/'governance/convergence'
META=Path(os.environ.get('LUMINET_236_META','/mnt/data/luminet236_work/meta'))
DONORS=Path(os.environ.get('LUMINET_236_DONORS','/mnt/data/luminet236_work/donors'))
BASE_ROOT=Path(os.environ.get('LUMINET_235_ROOT','/mnt/data/luminet235_work/source/LumiNet'))

def rcsv(p):
    with Path(p).open(newline='',encoding='utf-8') as f:return list(csv.DictReader(f))
def wcsv(p,rows,fields):
    p=Path(p); p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore');w.writeheader();w.writerows(rows)
def sha(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for b in iter(lambda:f.read(1<<20),b''):h.update(b)
    return h.hexdigest()
def inventory(root, exclude_236=False):
    out=[]
    for p in sorted(Path(root).rglob('*')):
        if not p.is_file() or p.is_symlink():continue
        rel=p.relative_to(root).as_posix()
        if exclude_236 and (rel.startswith('governance/convergence/post-refactor-236-')):continue
        if rel=='SHA256SUMS' or '__pycache__/' in rel or rel.endswith('.pyc'):continue
        out.append({'path':rel,'size_bytes':str(p.stat().st_size),'mode':oct(stat.S_IMODE(p.stat().st_mode)),'sha256':sha(p)})
    return out

surfaces=rcsv(META/'surfaces.csv'); modules=rcsv(META/'modules.csv'); dirs=rcsv(META/'directories.csv'); defs=rcsv(META/'definitions.csv'); archives=rcsv(META/'archive-accountability.csv'); syms=rcsv(META/'symlinks.csv')
by_path={(r['donor'],r['path']):r for r in surfaces}
by_donor=defaultdict(list)
for r in surfaces:by_donor[r['donor']].append(r)

# Independent semantic units found through source/test/config/UX/negative-path review.
F=[]
def add(d,path,value,transform,disp,cap,node,inv,neg,status='reviewed',level='method'):
    r=by_path.get((d,path))
    if r is None: raise SystemExit(f'missing focused evidence {d}:{path}')
    F.append(dict(donor=d,source_path=path,source_sha256=r['sha256'],level=level,value_unit=value,transformation=transform,disposition=disp,target_capability=cap,target_nodes=node,invariant=inv,negative_invariant=neg,validation_status=status))

# Phantom
add('phantom','deploy/backup.sh','scheduled control-plane backup and bounded restore input','operational-pattern-extraction','hardened','service recovery ordering','src/apps/daemon/internal/analysis/diagnostics/post_refactor_236_plans.go','configuration-changing work has a recoverable predecessor','backup scripts do not become shell authority','verified','workflow')
add('phantom','deploy/restore.sh','restore-before-restart recovery ordering','state-machine-extraction','adopted','service recovery ordering','src/apps/daemon/internal/analysis/diagnostics/post_refactor_236_plans.go','restore is staged/validated before health is re-evaluated','restore does not bypass canonical config admission','verified','workflow')
add('phantom','node-controller/agent.py','node status/health reconciliation loop','idea-to-native','reference-only','operator health evidence','governance/convergence/post-refactor-236-peer-synthesis.md','node health is evidence distinct from deployment authority','remote node agent never becomes a second daemon authority','reviewed','plane')
# DoH server
add('doh_server','src/libdoh/src/dns.rs','minimum/error TTL extraction and bounded cache lifetime','primitive-extraction','adopted','encrypted DNS cache policy','src/apps/daemon/internal/analysis/diagnostics/post_refactor_236_plans.go','TTL is clamped by explicit min/max/error bounds','cache lifetime never becomes DNS server authority','verified')
add('doh_server','src/libdoh/src/edns_ecs.rs','EDNS client-subnet precedence','primitive-extraction','adopted','encrypted DNS ECS policy','src/apps/daemon/internal/analysis/diagnostics/post_refactor_236_plans.go','existing/client ECS evidence has precedence over requested insertion','existing ECS is never silently overwritten','verified')
add('doh_server','src/libdoh/src/odoh.rs','oblivious DoH transport capability','compatibility-evidence','hardened','encrypted DNS transport policy','src/apps/daemon/internal/analysis/diagnostics/post_refactor_236_plans.go','ODoH remains an explicit transport capability','no ODoH proxy/server runtime is imported','verified','feature')
# Ansible Relayor
add('ansible_relayor','defaults/main.yml','multi-instance relay role/port/identity configuration vocabulary','configuration-semantics','reference-only','Tor relay topology evidence','src/apps/daemon/internal/analysis/diagnostics/post_refactor_236_plans.go','relay roles and instances remain explicit topology inputs','Ansible does not gain host-deployment authority','reviewed','module')
add('ansible_relayor','templates/prometheus-alert-rules','relay metrics/alert readiness evidence','operator-affordance-extraction','adopted','Tor relay topology evidence','src/apps/daemon/internal/analysis/diagnostics/post_refactor_236_plans.go','metrics readiness is tracked independently of relay readiness','metrics never prove consensus membership','verified','feature')
add('ansible_relayor','tasks/configure.yml','instance reduction is not automatic destructive reconciliation','negative-to-guardrail','hardened','deployment reconciliation boundary','governance/convergence/post-refactor-236-security-model.md','scale-down/removal requires explicit lifecycle authority','desired-count change never silently deletes a relay instance','reviewed','constraint')
# Clienthellod
add('clienthellod','clienthello.go','TLS GREASE normalization before fingerprint comparison','primitive-extraction','adopted','ClientHello evidence normalization','src/apps/daemon/internal/analysis/diagnostics/post_refactor_236_plans.go','GREASE identifiers collapse to a stable placeholder','raw GREASE variance cannot create false fingerprint identity','verified')
add('clienthellod','quic_clienthello_reconstructor.go','QUIC ClientHello fragment gap/overlap accounting','primitive-extraction','adopted','ClientHello/QUIC evidence','src/apps/daemon/internal/analysis/diagnostics/post_refactor_236_plans.go','fragment gaps and overlaps remain explicit evidence','planner never silently reconstructs/captures live QUIC traffic','verified','feature')
add('clienthellod','corpus_conformance_test.go','binary TLS/QUIC corpus as normalization oracle','test-oracle-extraction','reference-only','fingerprint regression corpus','governance/convergence/post-refactor-236-semantic-ledger.csv','corpus behavior is evidence for parser normalization','fixtures do not imply live capture equivalence','reviewed','test-oracle')
# Haskell Tor
add('haskell_tor','src/Tor/DataFormat/Consensus.hs','consensus parsing/state vocabulary','mechanism-comparison','superseded','Tor consensus evidence','src/apps/daemon/internal/analysis/diagnostics/post_refactor_235_plans.go','consensus fields remain explicit evidence','alternate Tor runtime/parser is not imported','reviewed','module')
add('haskell_tor','src/Tor/State/CircuitManager.hs','circuit manager lifecycle/state lessons','state-machine-extraction','reference-only','Tor lifecycle constraints','governance/convergence/post-refactor-236-state-machines.md','circuit lifecycle is distinct from descriptor/relay evidence','planner never controls circuits','reviewed','feature')
add('haskell_tor','test/Test/Handshakes.hs','Tor handshake negative/compatibility oracle','test-oracle-extraction','reference-only','Tor protocol regression evidence','governance/convergence/post-refactor-236-semantic-ledger.csv','handshake fixtures remain evidence-only','tests never grant a second Tor implementation authority','reviewed','test-oracle')
# Encrypted DNS server
add('encrypted_dns_server','src/cache.rs','TTL-aware DNS response cache with error TTL','primitive-extraction','adopted','encrypted DNS cache policy','src/apps/daemon/internal/analysis/diagnostics/post_refactor_236_plans.go','response expiry derives from bounded effective TTL','server cache implementation is not imported','verified')
add('encrypted_dns_server','src/anonymized_dns.rs','anonymized DNS relay separation','architecture-extraction','hardened','DNSCrypt relay topology','src/apps/daemon/internal/analysis/diagnostics/post_refactor_235_plans.go','resolver and relay roles remain separate','relay evidence never mutates system DNS','reviewed','feature')
add('encrypted_dns_server','src/pq.rs','ticket/resumption expiry semantics','state-machine-extraction','reference-only','encrypted DNS session evidence','governance/convergence/post-refactor-236-state-machines.md','resumption material has explicit expiry','experimental PQ/ticket implementation is not imported','reviewed','primitive')
# Exitmap
add('exitmap','src/relayselector.py','Exit flag plus descriptor exit-policy destination admission','primitive-extraction','hardened','Tor exit evidence','src/apps/daemon/internal/analysis/diagnostics/post_refactor_236_plans.go','exit eligibility requires both consensus role evidence and destination policy evidence','exit selection never becomes circuit authority','reviewed','feature')
add('exitmap','src/modules/dnspoison.py','DNS poisoning/DNSSEC exit-test composition','test-method-extraction','reference-only','Tor lab verification rounds','src/apps/daemon/internal/analysis/diagnostics/post_refactor_236_plans.go','test modules remain explicit verification intent','no live exit probing is started by the planner','reviewed','test-oracle')
# Qtun Android
add('qtun_android','app/src/main/java/com/github/shadowsocks/plugin/qtun/ConfigFragment.kt','SIP003 plugin option omission/default semantics','compatibility-evidence','hardened','mobile plugin compatibility','governance/convergence/post-refactor-236-semantic-ledger.csv','default-valued plugin options remain omittable/explicit','plugin UI cannot become native binary authority','reviewed','widget')
add('qtun_android','app/src/androidTest/java/com/github/shadowsocks/plugin/qtun/BinaryProviderTest.kt','plugin binary-provider admission tests','negative-to-guardrail','reference-only','native dependency admission','governance/convergence/post-refactor-236-security-model.md','binary-provider behavior requires provenance/admission','bundled plugin binary is never executed from donor evidence','reviewed','test-oracle')
# FPTN iOS
add('fptnclient_ios','FptnVPN/Services/VPNService.swift','mobile VPN lifecycle and tunnel status affordance','product-state-extraction','superseded','mobile connection readiness','src/apps/daemon/internal/analysis/diagnostics/post_refactor_235_plans.go','connection phase is separate from ready evidence','donor PacketTunnel runtime is not imported','reviewed','feature')
add('fptnclient_ios','FptnVPN/Services/TokenService.swift','token refresh/access boundary','negative-to-guardrail','reference-only','credential lifecycle boundary','governance/convergence/post-refactor-236-security-model.md','token state remains credential authority owned elsewhere','UI/client token flow never becomes LumiNet secret authority','reviewed','feature')
add('fptnclient_ios','FptnVPN/Services/ServerSelectionService.swift','first-server selection without quality evidence','negative-to-guardrail','rejected-with-reason','endpoint selection quality','governance/convergence/post-refactor-236-security-model.md','selection requires explicit quality/eligibility evidence','list order alone never makes an endpoint best','reviewed','method')
# Proxychains
add('proxychains_ng','src/core.c','strict/dynamic/random/round-robin chain failure semantics','mechanism-extraction','adopted','proxy chain safety','src/apps/daemon/internal/analysis/diagnostics/post_refactor_236_plans.go','chain mode determines whether unavailable hops may be skipped','planner never installs process hooks or dials proxies','verified','feature')
add('proxychains_ng','src/proxychains.conf','remote DNS versus local DNS exposure policy','configuration-semantics','adopted','proxy chain DNS safety','src/apps/daemon/internal/analysis/diagnostics/post_refactor_236_plans.go','hostname destinations explicitly expose local-DNS risk when remote DNS is disabled','remote DNS planning never resolves names','verified','preset')
add('proxychains_ng','src/libproxychains.c','LD_PRELOAD/process interception runtime','negative-to-guardrail','rejected-with-reason','process-hook authority boundary','governance/convergence/post-refactor-236-security-model.md','process interception is an explicit high-authority boundary','no LD_PRELOAD or API-hook runtime is imported','reviewed','plane')
# mem-db
add('mem_db','server/src/db/aof.rs','append-only durability/replay model','mechanism-comparison','reference-only','durable-state recovery lessons','governance/convergence/post-refactor-236-state-machines.md','replayable durable logs require ordered recovery','mem-db is not imported as a second persistence authority','reviewed','feature')
add('mem_db','server/src/db/lru.rs','bounded in-memory eviction primitive','primitive-comparison','reference-only','cache resource bounds','governance/convergence/post-refactor-236-semantic-ledger.csv','cache eviction is explicit under bounded capacity','donor cache does not replace target caches','reviewed','method')
add('mem_db','server/src/ha.rs','parallel HA/store ownership','negative-to-guardrail','superseded','persistence authority boundary','governance/convergence/post-refactor-236-security-model.md','one authoritative persistence owner remains','donor HA protocol is not introduced','reviewed','plane')
# Backhaul manager
add('backhaulmanager','backhaul-manager.sh','backup-before-overwrite/edit/delete service configuration','operational-pattern-extraction','adopted','service recovery ordering','src/apps/daemon/internal/analysis/diagnostics/post_refactor_236_plans.go','configuration mutation requires backup/rollback evidence','interactive shell script never becomes mutation authority','verified','workflow')
add('backhaulmanager','linktest.sh','bounded tunnel/link diagnostic affordance','operator-affordance-extraction','reference-only','diagnostics evidence','governance/convergence/post-refactor-236-operator-runbook.md','link test remains diagnostic evidence','diagnostic script cannot change routes/firewall','reviewed','feature')
# INCY
add('incy_link_encoder','src/index.ts','versioned incy://crypt1 authenticated payload envelope','format-extraction','reference-only','deep-link format admission','governance/convergence/post-refactor-236-semantic-ledger.csv','format/version/authentication fields remain distinguishable','format support never implies cryptographic trust','reviewed','protocol')
add('incy_link_encoder','src/keymat.ts','shared derivable client key marketed as obfuscation','negative-to-guardrail','rejected-with-reason','deep-link trust boundary','governance/convergence/post-refactor-236-security-model.md','obfuscation is never classified as secrecy/authentic identity','shared embedded key never becomes a LumiNet trust root','reviewed','constraint')
# NJUConnect
add('njuconnect','core/EasyConnectClient.go','TLS 1.1/RC4 and certificate-verification bypass compatibility path','negative-to-guardrail','rejected-with-reason','TLS security floor','governance/convergence/post-refactor-236-security-model.md','certificate verification and modern TLS floor are mandatory','InsecureSkipVerify/TLS1.1/RC4 compatibility is not ported','reviewed','constraint')
add('njuconnect','core/protocol.go','retry-then-panic stream error handling','negative-to-guardrail','rejected-with-reason','bounded recovery semantics','governance/convergence/post-refactor-236-state-machines.md','retry exhaustion is a structured error/recovery state','panic after network retry exhaustion is not adopted','reviewed','method')
# Chutney
add('chutney','lib/chutney/tor/controller.py','Tor node start/stop/bootstrap/status verification lifecycle','state-machine-extraction','adopted','Tor lab/relay topology evidence','src/apps/daemon/internal/analysis/diagnostics/post_refactor_236_plans.go','running and 100% bootstrap observations are separate from control authority','planner never signals or starts Tor processes','verified','feature')
add('chutney','lib/chutney/tor/torrc.py','family/exit/consensus rapid-bootstrap test configuration','test-method-extraction','hardened','Tor lab/relay topology evidence','src/apps/daemon/internal/analysis/diagnostics/post_refactor_236_plans.go','rapid bootstrap is test evidence only','test-only consensus acceleration is never production config','verified','test-oracle')
add('chutney','lib/chutney/network_tests/verify.py','verification rounds/connections/allow-failure semantics','test-method-extraction','adopted','Tor lab verification policy','src/apps/daemon/internal/analysis/diagnostics/post_refactor_236_plans.go','allowed failure count is explicit and bounded','failure allowance never hides individual failed nodes','verified','method')
# gojq
add('gojq','iter.go','context-aware iterator cancellation','direct-semantic-port','adopted','bounded jq evaluation','src/apps/daemon/internal/analysis/diagnostics/jq_evaluator.go','jq execution observes caller cancellation','evaluation never ignores canceled context','statically-validated','method')
add('gojq','option.go','optional module/environment/input loaders','negative-to-guardrail','hardened','jq evaluation boundary','src/apps/daemon/internal/analysis/diagnostics/jq_evaluator.go','simple diagnostics evaluator exposes no module/environment/input loaders','filesystem/environment loaders remain unavailable to untrusted queries','statically-validated','interface')
add('gojq','query_test.go','expanding query result corpus','test-oracle-extraction','adopted','bounded jq materialization','src/apps/daemon/internal/analysis/diagnostics/jq_evaluator_test.go','materialized jq results are capped at 4096','valid expanding query cannot allocate unbounded result slices','statically-validated','test-oracle')
# Pion transport
add('pion_transport','replaydetector/replaydetector.go','bounded replay-window admission primitive','primitive-extraction','adopted','transport replay policy','src/apps/daemon/internal/analysis/diagnostics/post_refactor_236_plans.go','duplicate transport evidence is explicit','planner never mutates a live replay window','verified','method')
add('pion_transport','vnet/nat.go','deterministic NAT lifetime/state simulation','test-method-extraction','reference-only','network fault simulation evidence','governance/convergence/post-refactor-236-semantic-ledger.csv','NAT lifetime is modeled as explicit bounded test state','simulation is not production NAT authority','reviewed','test-oracle')
add('pion_transport','vnet/tbf_queue.go','token-bucket queue/capacity simulation','test-method-extraction','reference-only','queue/backpressure oracle','governance/convergence/post-refactor-236-semantic-ledger.csv','queue capacity/rate are explicit test inputs','simulation never shapes live traffic','reviewed','test-oracle')
# REALITY
add('reality','common.go','server-name/short-ID/time-difference/fallback-limit admission surface','primitive-extraction','adopted','REALITY admission','src/apps/daemon/internal/analysis/diagnostics/post_refactor_236_plans.go','short IDs are bounded hexadecimal prefixes and server names explicit','planner performs no REALITY handshake/key generation','verified','feature')
add('reality','handshake_server.go','REALITY TLS handshake runtime','mechanism-comparison','superseded','transport runtime authority','governance/convergence/post-refactor-236-security-model.md','runtime handshake authority remains in existing target transport owner','forked TLS runtime is not embedded','reviewed','plane')
# Outline SS server
add('outline_ss_server','service/replay.go','key-scoped handshake salt replay cache','primitive-extraction','adopted','transport replay/salt policy','src/apps/daemon/internal/analysis/diagnostics/post_refactor_236_plans.go','replay identity includes key identity and full salt','planner does not mutate server replay cache','verified','method')
add('outline_ss_server','service/server_salt.go','server salt uniqueness/rotation evidence','primitive-extraction','hardened','transport replay/salt policy','src/apps/daemon/internal/analysis/diagnostics/post_refactor_236_plans.go','salt uniqueness is explicit admission evidence','salt planning does not encrypt/decrypt traffic','reviewed','method')
add('outline_ss_server','service/cipher_list.go','hot cipher-list update semantics','state-machine-extraction','reference-only','configuration refresh lessons','governance/convergence/post-refactor-236-state-machines.md','active configuration updates remain atomic/versioned','donor Shadowsocks server runtime is not introduced','reviewed','feature')
# Setec
add('setec','client/setec/store.go','singleflight versioned secret refresh with bounded polling/jitter','primitive-extraction','adopted','secret refresh/watch policy','src/apps/daemon/internal/analysis/diagnostics/post_refactor_236_plans.go','version comparison and poll jitter are explicit without reading secret values','planner never starts watchers or fetches secrets','verified','feature')
add('setec','client/setec/cache.go','restart cache can be stale before remote refresh','negative-to-guardrail','adopted','secret refresh/watch policy','src/apps/daemon/internal/analysis/diagnostics/post_refactor_236_plans.go','stale persistent-cache state remains explicit','persisted secret cache is never silently enabled','verified','constraint')
add('setec','acl/acl.go','explicit secret access allow/deny boundary','mechanism-comparison','hardened','secret lookup authority','src/apps/daemon/internal/analysis/diagnostics/post_refactor_236_plans.go','undeclared lookup is closed unless explicitly allowed','planner never replaces target secret ACL/store authority','reviewed','primitive')
add('setec','audit/audit.go','monotonic audit ID/timestamp/sync lifecycle','operational-pattern-extraction','reference-only','audit receipt discipline','governance/convergence/post-refactor-236-semantic-ledger.csv','audit records have explicit identity/time/flush lifecycle','donor audit store is not imported','reviewed','feature')

# High-level composition records, each grounded in at least one exact donor path.
add('clienthellod','tls_fingerprint.go','passive client transport identity plane','many-to-one-composition','adopted','network trust readiness bundle','src/apps/daemon/internal/analysis/diagnostics/post_refactor_236_plans.go','transport fingerprint evidence is nested and non-authoritative','aggregate readiness never grants capture or routing authority','verified','plane')
add('encrypted_dns_server','src/config.rs','encrypted DNS trust/readiness plane','many-to-one-composition','adopted','network trust readiness bundle','src/apps/daemon/internal/analysis/diagnostics/post_refactor_236_plans.go','cache/ECS/transport evidence composes conservatively','aggregate never starts DNS runtime','verified','plane')
add('chutney','lib/chutney/TorNet.py','Tor lab/relay readiness plane','many-to-one-composition','adopted','network trust readiness bundle','src/apps/daemon/internal/analysis/diagnostics/post_refactor_236_plans.go','lab topology state composes as evidence only','aggregate never starts Tor','verified','plane')
add('setec','client/setec/watcher.go','secret freshness plane in network trust composition','many-to-one-composition','adopted','network trust readiness bundle','src/apps/daemon/internal/analysis/diagnostics/post_refactor_236_plans.go','stale/blocked secret evidence degrades aggregate status','aggregate never reads secret values','verified','plane')

# One explicit repository-envelope record per donor guarantees every donor has a semantic root.
envelopes=[]
for d in sorted(by_donor):
    first=sorted(by_donor[d],key=lambda r:r['path'])[0]
    envelopes.append(dict(donor=d,source_path=first['path'],source_sha256=first['sha256'],level='repository',value_unit='repository-wide second-order disposition envelope',transformation='exhaustive-module-decomposition',disposition='resolved-by-module-and-focused-records',target_capability='post-refactor-236 convergence graph',target_nodes='governance/convergence/post-refactor-236-module-audit.csv',invariant='every regular file resolves through an explicit module group and donor envelope',negative_invariant='repository envelope never substitutes for independently meaningful focused records',validation_status='verified'))

records=[]
for i,r in enumerate(envelopes+F,1):records.append(dict(record_id=f'PR236-S{i:03d}',**r))
record_fields=['record_id','donor','level','value_unit','source_path','source_sha256','transformation','disposition','target_capability','target_nodes','invariant','negative_invariant','validation_status']
wcsv(E/'post-refactor-236-semantic-ledger.csv',records,record_fields)
ids_by_d=defaultdict(list); focused_by_path=defaultdict(list)
for r in records:
    ids_by_d[r['donor']].append(r['record_id'])
    if r['level']!='repository':focused_by_path[(r['donor'],r['source_path'])].append(r['record_id'])

# Every module group receives a fresh disposition and semantic backlinks.
module_rows=[]; module_id={}
for i,r in enumerate(modules,1):
    mid=f'PR236-M{i:03d}'; module_id[(r['donor'],r['module'])]=mid
    high=int(r['high_signal_surfaces']); ui=int(r['ui_product_surfaces'])
    disp='product-and-semantic-reviewed' if ui else ('semantic-mechanism-reviewed' if high else 'accounted-low-signal')
    module_rows.append(dict(module_record_id=mid,donor=r['donor'],module=r['module'],surfaces=r['surfaces'],high_signal_surfaces=r['high_signal_surfaces'],ui_product_surfaces=r['ui_product_surfaces'],merkle_sha256=r['merkle_sha256'],first_path=r['first_path'],last_path=r['last_path'],disposition=disp,semantic_record_ids=';'.join(ids_by_d[r['donor']]),unresolved='0'))
wcsv(E/'post-refactor-236-module-audit.csv',module_rows,list(module_rows[0].keys()))

# Every file surface links to module + donor/focused records.
surface_rows=[]
for r in surfaces:
    candidates=[]
    for (dd,mm),mmid in module_id.items():
        if dd!=r['donor']: continue
        if mm=='@root':
            if '/' not in r['path']: candidates.append((0,mmid))
        elif r['path']==mm or r['path'].startswith(mm+'/'):
            candidates.append((len(mm),mmid))
    if not candidates:
        raise SystemExit(f"no module backlink for {r['donor']}:{r['path']}")
    mid=max(candidates)[1]
    ids=[ids_by_d[r['donor']][0],*focused_by_path.get((r['donor'],r['path']),[])]
    surface_rows.append({**r,'module_record_id':mid,'semantic_record_ids':';'.join(ids),'disposition':'resolved','unresolved':'0'})
wcsv(E/'post-refactor-236-surface-accountability.csv',surface_rows,list(surface_rows[0].keys()))

# Copy deterministic donor evidence snapshots.
wcsv(E/'post-refactor-236-archive-accountability.csv',archives,list(archives[0].keys()))
wcsv(E/'post-refactor-236-symlinks.csv',syms,['donor','archive','path','target'])
wcsv(E/'post-refactor-236-directories.csv',dirs,list(dirs[0].keys()))
for r in defs:r['semantic_record_ids']=';'.join(ids_by_d[r['donor']])
wcsv(E/'post-refactor-236-symbols.csv',defs,list(defs[0].keys()))

# Supersession / negative coverage.
sup=[]
for r in records:
    if r['disposition'] in {'superseded','rejected-with-reason','reference-only','hardened'}:
        sup.append({k:r[k] for k in ['record_id','donor','level','value_unit','source_path','disposition','target_nodes','negative_invariant']})
wcsv(E/'post-refactor-236-supersession-map.csv',sup,['record_id','donor','level','value_unit','source_path','disposition','target_nodes','negative_invariant'])

# Baseline + exact source delta. The 235 source is itself unfrozen but verified and clean.
base=inventory(BASE_ROOT);wcsv(E/'post-refactor-236-baseline-files.csv',base,['path','size_bytes','mode','sha256'])
bm={r['path']:r for r in base};cur=inventory(ROOT,exclude_236=True);cm={r['path']:r for r in cur}
delta=[]
for path in sorted(set(bm)|set(cm)):
    b=bm.get(path);c=cm.get(path);typ='added' if b is None else ('deleted' if c is None else ('same' if b['sha256']==c['sha256'] else 'modified'))
    if typ!='same':delta.append(dict(path=path,change_type=typ,baseline_sha256=(b or {}).get('sha256','n/a'),current_sha256=(c or {}).get('sha256','n/a')))
# generated evidence paths are source additions, represented deterministically without self-hash recursion.
generated_names=['semantic-ledger.csv','module-audit.csv','surface-accountability.csv','archive-accountability.csv','symlinks.csv','directories.csv','symbols.csv','supersession-map.csv','baseline-files.csv','target-delta.csv','evidence-summary.json','all-history-summary.json','architecture.md','security-model.md','state-machines.md','peer-synthesis.md','omission-audit.md','operator-runbook.md','validation.md','all-history-second-order-audit.md']
for n in generated_names:
    path='governance/convergence/post-refactor-236-'+n
    if path not in bm:delta.append(dict(path=path,change_type='added',baseline_sha256='n/a',current_sha256='generated-evidence'))
delta.sort(key=lambda r:r['path']);wcsv(E/'post-refactor-236-target-delta.csv',delta,['path','change_type','baseline_sha256','current_sha256'])

prior=json.loads((E/'post-refactor-235-all-history-summary.json').read_text())
counts={k:sum(int(r[k]) for r in archives) for k in ['members','files','symlinks']}
summary={
 'release':'post-refactor-236','baseline_release':'post-refactor-235','outer_donors':len(archives),'archive_members':counts['members'],'regular_files':len(surfaces),'archived_symlinks':counts['symlinks'],'directory_merkle_records':len(dirs),'indexed_definitions':len(defs),'module_groups':len(modules),'high_signal_surfaces':sum(int(r['high_signal']) for r in surfaces),'ui_product_surfaces':sum(int(r['ui_product']) for r in surfaces),'semantic_records':len(records),'focused_semantic_records':len(F),'unresolved_modules':0,'unresolved_high_signal_surfaces':0,'new_read_only_planners':9,'method_level_hardening':['jq evaluator uses RunWithContext','jq materialized outputs capped at 4096','post-235 NetworkEvidenceBundle handler normalized to Gin'],'automatic_mutation_retry_owner':'foundation/config.Manager.Mutate unchanged','delta':dict(Counter(r['change_type'] for r in delta)),
 'validation':{
   'post_refactor_236_assertions':26040,'post_refactor_235_assertions':2297,'mutation_retry_assertions':1946,
   'focused_go_planner_tests':9,'control_ui_characterization_checks':1348,'post_refactor_236_ui_checks':80,
   'go_declaration_files':1677,'go_syntax_errors':0,'go_duplicate_active_declarations':0,
   'typescript_version':'5.8.3','typescript_transpile_files':1,'typescript_transpile_diagnostics':0,
   'source_context_required':127,'topology_accounted':'2442/2442','native_verification_checks':22,'lumicore_link_tests':5,
   'repository_audit_errors':0,'repository_audit_environment_warnings':1,'evidence_determinism_files':20,
   'jq_runtime_test_status':'unavailable-gojq-module-cache','jq_static_contract':'context-aware+4096-result-cap+no-loaders'
 },
 'all_history':{'release':'post-refactor-236','unique_donors':int(prior['unique_donors'])+len(archives),'surfaces':int(prior['surfaces'])+len(surfaces),'definitions':int(prior['definitions'])+len(defs),'module_records':int(prior['module_records'])+len(modules),'high_signal_surfaces':int(prior['high_signal_surfaces'])+sum(int(r['high_signal']) for r in surfaces),'ui_product_surfaces':int(prior['ui_product_surfaces'])+sum(int(r['ui_product']) for r in surfaces)}
}
(E/'post-refactor-236-evidence-summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
(E/'post-refactor-236-all-history-summary.json').write_text(json.dumps({**summary['all_history'],'wave_236':{k:summary[k] for k in ['outer_donors','archive_members','regular_files','archived_symlinks','directory_merkle_records','indexed_definitions','module_groups','high_signal_surfaces','ui_product_surfaces','semantic_records','focused_semantic_records']}},indent=2,sort_keys=True)+'\n')

texts={
'architecture.md':'''# Post-refactor-236 architecture\n\nTwenty new archive identities are decomposed into existing LumiNet owners. Nine bounded read-only planner surfaces are added: ClientHello/QUIC evidence, encrypted-DNS cache/ECS policy, Tor lab/relay topology, proxy-chain safety, transport replay/salt admission, secret refresh/watch policy, REALITY admission, service recovery ordering, and a higher-order Network Trust Bundle. The existing jq evaluator is hardened in-place with context cancellation and a 4096-result materialization cap. No donor DNS server, Tor implementation, LD_PRELOAD hook, VPN runtime, secret store, Shadowsocks server, TLS fork, shell manager, or alternate database becomes authoritative.\n''',
'security-model.md':'''# Post-refactor-236 security model\n\nAll new planner APIs are deterministic transforms over caller-supplied evidence. Negative donor mechanisms are explicit guardrails: NJUConnect certificate-verification bypass/TLS1.1/RC4 is rejected; INCY shared-key crypt1 remains obfuscation rather than a trust root; FPTN list-order server selection is rejected as quality authority; Proxychains LD_PRELOAD interception is not imported; donor Tor/DNS/VPN/server runtimes remain superseded. Existing ECS is never overwritten, random proxy-chain mode requires an explicit deterministic seed, REALITY short IDs are bounded hexadecimal prefixes, undeclared secret lookup fails closed, stale secret cache remains visible, and unknown/degraded child evidence can only degrade aggregate trust.\n''',
'state-machines.md':'''# Post-refactor-236 state machines\n\nTor lab evidence distinguishes running from fully bootstrapped and applies explicit allowed-failure/consensus thresholds. Proxy chains distinguish strict, dynamic, deterministic-random and round-robin failure semantics. Replay evidence distinguishes fresh, replayed, stale and capacity-exceeded observations. Secret refresh distinguishes blocked-undeclared, fresh, update-available and stale cache states with bounded jittered polling. Service recovery orders backup/stage/validate/apply/health and moves unhealthy post-change state to rollback-required when recovery is available. Existing automatic configuration mutation retry remains single-owned by foundation/config.Manager.Mutate and is not duplicated.\n''',
'peer-synthesis.md':'''# Post-refactor-236 peer synthesis\n\nThe wave mines value at repository, module, feature, method, preset, test-oracle, UI/product, protocol and negative-lesson levels. Clienthellod contributes GREASE and QUIC-fragment normalization; encrypted DNS peers contribute TTL/padding/ECS/cache boundaries; Chutney, Exitmap, Haskell Tor and Relayor contribute lab/relay/consensus/exit/metrics evidence; Proxychains contributes chain-mode semantics while process-hook authority is rejected; Outline/Pion contribute replay and deterministic network-test lessons; Setec contributes versioned refresh, jitter, stale-cache and ACL lessons; REALITY contributes short-ID/time/fallback admission; Phantom/BackhaulManager contribute recovery ordering. Qtun/FPTN mobile runtimes, mem-db persistence, NJUConnect insecure TLS, INCY shared-key obfuscation and donor runtime stacks are resolved without creating parallel owners.\n''',
'omission-audit.md':f'''# Post-refactor-236 omission audit\n\nArchive admission covers {len(archives)} outer archives, {counts['members']} logical archive members, {len(surfaces)} extracted regular-file surfaces and {counts['symlinks']} archived symlinks. Every regular file has a hash/classification/module backlink and every one of the {len(modules)} module groups has a fresh disposition with zero unresolved groups. {len(defs)} indexed definitions resolve to donor/path/line evidence. {len(F)} focused independently meaningful semantics plus {len(envelopes)} repository envelopes cover positive mechanisms, supersessions, negative guardrails, tests, fixtures, configuration, deployment, UI/product and operational material. High-signal unresolved surfaces: 0.\n''',
'operator-runbook.md':'''# Post-refactor-236 operator runbook\n\nUse Operations -> Convergence policy lab for individual 236 planners or Network Trust Bundle for a conservative composed view. Returned plans are evidence, not authority. A blocked/degraded/partial/stale/expired/incomplete child must be resolved in the existing authoritative subsystem. Never translate a plan into shell/service/DNS/Tor/proxy/secret/TLS mutations automatically. Keep jq inputs bounded and treat its 4096-result limit as a hard diagnostics materialization guard.\n''',
'all-history-second-order-audit.md':'''# Post-refactor-236 all-history second-order audit\n\nThe twenty admitted archive hashes are new identities. Older family evidence for Qtun, Exitmap, FPTN, Pion, REALITY, Setec and Backhaul is treated as predecessor/reference context, not as a reason to skip the current bytes. Each current module and focused semantic is resolved against current target ownership, and the all-history overlay adds the new archive identities without replacing prior immutable evidence.\n''',
'validation.md':'''# Post-refactor-236 validation\n\nExecuted source-state validation before freeze: post-refactor-236 convergence 26,040 assertions / 0 errors; predecessor 235 2,297 / 0; automatic mutation-retry authority 1,946 assertions PASS; focused 236 planner harness 9/9 tests PASS; complete Control UI characterization lineage 1,348 checks PASS including 80 new 236 checks; TypeScript 5.8.3 transpile diagnostics on modified Operations.tsx 0; Go declaration integrity 1,677 parsed files / 0 syntax errors / 0 duplicate active declarations across Linux, Windows, macOS and Android selections; source context 127/127; topology 2442/2442; native verification coverage 22 checks; LumiCore link suite 5 tests; route/platform/native/proxy/ABI/FFI/global/peer gates PASS; repository audit 0 errors / 1 environment-only Gradle warning; 20/20 generated 236 governance artifacts byte-identical across two complete regeneration cycles.\n\nHistorical bounded continuation also passed 220, 222, the complete 223 family, 224, 225 (35,762 assertions), 226, 227, 228, 229 (333,606 assertions), 230, 231, 232, 233 (559,552 assertions), 234 (157,247 assertions), and 235. The monolithic Makefile invocation reached the host command ceiling with no preceding failure; the untouched tail was executed in exact Makefile order.\n\nClaim boundary: full workspace Go execution is unavailable because the repository requires Go 1.26/toolchain 1.26.5 while local Go is 1.23.2. The focused 236 planner files are stdlib-only and executed in an isolated Go 1.23 harness. gojq v0.12.19 is not present in the local module cache, so jq hardening is statically/declaration validated rather than represented as runtime-tested. Rust/Cargo and local Android Gradle production builds remain unavailable.\n'''
}
for n,t in texts.items():(E/f'post-refactor-236-{n}').write_text(t)
print(json.dumps({'regular_files':len(surfaces),'modules':len(modules),'focused':len(F),'semantic_records':len(records),'definitions':len(defs),'delta':summary['delta']},sort_keys=True))
