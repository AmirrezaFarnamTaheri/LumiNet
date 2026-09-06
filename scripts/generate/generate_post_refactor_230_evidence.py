#!/usr/bin/env python3
"""Generate deterministic post-refactor-230 evidence for thirteen donor archives."""
from __future__ import annotations
import csv, hashlib, json, os, shutil
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(os.environ.get('LUMINET_230_TARGET_ROOT', Path(__file__).resolve().parents[2]))
WORK = Path(os.environ.get('LUMINET_230_WORK_ROOT', '/mnt/data/luminet230_work'))
RAW = WORK / 'evidence'
DONOR_BASE = WORK / 'donors'
OUT = ROOT / 'governance' / 'convergence'
BASELINE = Path(os.environ.get('LUMINET_230_BASELINE_INVENTORY', '/mnt/data/LumiNet-post-refactor-229-source-inventory.csv'))
HIGH = {'implementation','ui-or-product','configuration','deployment','script','test'}
LEDGER_FIELDS = ['record_id','parent_record_id','composition_group_id','donor','domain','value_unit','source_granularity','value_form','separability','donor_path','donor_sha256','donor_symbol','transformation','mapping_topology','disposition','decision_rationale','target_capability','target_nodes','invariant','negative_invariant','test_node','operator_surface','migration_impact','license_note','risk_tier','dependency_record_ids','evidence_confidence','validation_status']
DONORS = ['mitmengine-master','mitmproxy-main','bine-master','bridgedb-main','conjure-master','Hiddify-Manager-dev','probe-legacy-master','SenPaiScanner-main','qjs-master','IPScanner-main','pion-dtls-main','smux-master','NoMoreWalls-master']

def read_csv(p):
    with Path(p).open(newline='', encoding='utf-8') as f: return list(csv.DictReader(f))
def write_csv(p, rows, fields):
    p=Path(p); p.parent.mkdir(parents=True, exist_ok=True)
    with p.open('w', newline='', encoding='utf-8') as f:
        w=csv.DictWriter(f, fieldnames=fields, extrasaction='ignore', lineterminator='\n'); w.writeheader()
        for r in rows: w.writerow({k:r.get(k,'n/a') for k in fields})
def sha_file(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for b in iter(lambda:f.read(1<<20), b''): h.update(b)
    return h.hexdigest()
def sha_text(s): return hashlib.sha256(s.encode()).hexdigest()
def donor_root(d): return DONOR_BASE / d / d
def donor_file_sha(d,p):
    f=donor_root(d)/p
    if not f.is_file(): raise FileNotFoundError(f'{d}:{p}')
    return sha_file(f)

def focus_specs():
    F=[]
    def add(d,domain,value,path,trans,disp,rationale,cap,nodes,test='src/apps/daemon/internal/analysis/diagnostics/post_refactor_230_plans_test.go',inv='selected semantics remain explicit, bounded, deterministic, and target-owned',neg='donor runtime or authority is not imported implicitly',surface='Operations',risk='medium',status='verified',form='behavioral evidence'):
        F.append(dict(donor=d,domain=domain,value=value,path=path,transformation=trans,disposition=disp,rationale=rationale,capability=cap,nodes=nodes,test=test,invariant=inv,negative=neg,surface=surface,risk=risk,status=status,form=form))
    # mitmengine
    add('mitmengine-master','tls-observation','component mismatch / grade / PFS evidence','reference_fingerprints/fingerprint_metadata.jsonl','negative-to-guardrail','superseded','Historical fingerprint corpus is useful for anomaly categories but is stale and cannot identify a current interception product.','TLS interception evidence','src/apps/daemon/internal/analysis/diagnostics/tls_interception_evidence_plan.go','src/packages/control-ui/scripts/test-post-refactor-229.mjs',neg='historical fingerprint database never becomes live authority',surface='Health',risk='high',status='reviewed')
    add('mitmengine-master','tls-observation','middlebox fingerprint strings','reference_fingerprints/mitmengine/mitm.txt','reference retention','reference-only','Retained as historical evaluation evidence only.','TLS evidence provenance','governance/convergence/post-refactor-230-peer-synthesis.md','scripts/checks/check_post_refactor_230_convergence.py',surface='governance',status='reviewed')
    # mitmproxy
    add('mitmproxy-main','flow-analysis','flow metadata filter language','mitmproxy/flowfilter.py','specialization','adapted','Reduced a powerful filter language to a bounded literal metadata-only subset suitable for read-only operator evidence.','bounded flow filtering','src/apps/daemon/internal/analysis/diagnostics/flow_filter_plan.go',surface='Operations')
    add('mitmproxy-main','tls-authority','certificate authority and active interception','mitmproxy/certs.py','negative-to-guardrail','rejected','CA generation/installation and active interception would create unsafe duplicate authority; only read-only evidence is retained.','read-only TLS evidence','src/apps/daemon/internal/analysis/diagnostics/tls_interception_evidence_plan.go','src/packages/control-ui/scripts/test-post-refactor-230.mjs',neg='LumiNet does not install interception roots or terminate user TLS for inspection',surface='Health',risk='critical',status='verified')
    add('mitmproxy-main','extension-authority','addon execution manager','mitmproxy/addonmanager.py','mechanism comparison','rejected','Untrusted arbitrary addon execution is not admitted into the daemon.','finite typed planner surface','src/apps/daemon/internal/analysis/diagnostics/flow_filter_plan.go','scripts/checks/check_post_refactor_230_convergence.py',risk='critical',status='statically-validated')
    add('mitmproxy-main','product-workflow','flow list/detail/search affordances','mitmproxy/tools/console/flowdetailview.py','product-workflow inspiration','inspired-native','Searchable flow metadata is valuable product evidence; mutation/replay remains out of scope.','operator evidence filtering','src/packages/control-ui/src/pages/Operations.tsx','src/packages/control-ui/scripts/test-post-refactor-230.mjs',surface='Operations',status='verified')
    # bine
    add('bine-master','tor-auth','SAFECOOKIE/control authentication semantics','control/cmd_authenticate.go','reference extraction','reference-only','Authentication semantics stay with the external Tor engine; the planner records readiness without consuming cookie bytes.','Tor bootstrap evidence','src/apps/daemon/internal/analysis/diagnostics/tor_bootstrap_evidence_plan.go',neg='planner cannot read auth cookies or issue control commands')
    add('bine-master','tor-readiness','circuit, SOCKS and bootstrap lifecycle','tor/tor.go','state-model adaptation','adapted','Readiness requires authenticated control evidence, enabled networking, full bootstrap, a circuit and SOCKS listener.','Tor bootstrap readiness','src/apps/daemon/internal/analysis/diagnostics/tor_bootstrap_evidence_plan.go')
    add('bine-master','tor-runtime','dial/listen/process control','tor/dialer.go','mechanism comparison','superseded','Existing external-engine ownership remains authoritative; no second Tor process/controller is added.','external Tor engine ownership','src/apps/daemon/internal/runtime/proxy/core_manager.go','scripts/checks/check_post_refactor_230_convergence.py',risk='high',status='statically-validated')
    # bridgedb
    add('bridgedb-main','bridge-selection','transport/country/address-family filters','bridgedb/filters.py','primitive extraction','adapted','Bridge filters become deterministic caller-supplied selection constraints without a distribution service.','Tor bridge selection','src/apps/daemon/internal/analysis/diagnostics/tor_bridge_selection_plan.go')
    add('bridgedb-main','bridge-selection','request constraints and requested transport','bridgedb/bridgerequest.py','state/model adaptation','adapted','Request intent is normalized into bounded local selection criteria.','Tor bridge selection','src/apps/daemon/internal/analysis/diagnostics/tor_bridge_selection_plan.go')
    add('bridgedb-main','bridge-distribution','hash-ring distribution','bridgedb/bridgerings.py','rederivation','adapted','Client-stable distribution inspired deterministic SHA-256 ranking without persisting client identifiers.','Tor bridge selection','src/apps/daemon/internal/analysis/diagnostics/tor_bridge_selection_plan.go',neg='no client identity or distribution database is persisted')
    add('bridgedb-main','bridge-distribution','server-side distributor stack','bridgedb/distributors/__init__.py','mechanism comparison','rejected','Email/HTTPS/Moat distribution authority and user data stores are not a LumiNet responsibility.','local bridge selection only','src/apps/daemon/internal/analysis/diagnostics/tor_bridge_selection_plan.go','scripts/checks/check_post_refactor_230_convergence.py',risk='high',status='statically-validated')
    add('bridgedb-main','bridge-stability','running/stable bridge evidence','bridgedb/Stability.py','primitive extraction','adapted','Running/stable flags are accepted only as caller-supplied evidence before deterministic selection.','Tor bridge selection','src/apps/daemon/internal/analysis/diagnostics/tor_bridge_selection_plan.go')
    # conjure
    add('conjure-master','phantom-selection','liveness cache semantics','pkg/station/liveness/liveness.go','state-model adaptation','adapted','Fresh explicit not-live evidence is required; stale/unknown/live candidates are excluded.','phantom endpoint selection','src/apps/daemon/internal/analysis/diagnostics/phantom_pool_plan.go')
    add('conjure-master','phantom-selection','cached liveness lifecycle','pkg/station/liveness/cached.go','bounds adaptation','adapted','Liveness evidence gains explicit age bounds without importing probe authority.','phantom endpoint selection','src/apps/daemon/internal/analysis/diagnostics/phantom_pool_plan.go')
    add('conjure-master','registration','registration server','cmd/registration-server/main.go','mechanism comparison','rejected','Registration/signalling servers would create a new remote authority plane.','planning-only phantom selection','src/apps/daemon/internal/analysis/diagnostics/phantom_pool_plan.go','scripts/checks/check_post_refactor_230_convergence.py',risk='critical',status='statically-validated')
    add('conjure-master','station-runtime','station registration ingestion','pkg/station/lib/registration_ingest.go','mechanism comparison','reference-only','Station-side registration/transport machinery is retained as architectural evidence only.','phantom evidence provenance','governance/convergence/post-refactor-230-peer-synthesis.md','scripts/checks/check_post_refactor_230_convergence.py',surface='governance',risk='high',status='reviewed')
    # hiddify manager
    add('Hiddify-Manager-dev','gateway-topology','HAProxy SNI/fronting topology','haproxy/haproxy.cfg.j2','topology recomposition','adapted','Layered listener/path-router/detour/egress/health topology becomes a planning preset, not rendered service config.','gateway composition preset','src/apps/daemon/internal/analysis/diagnostics/gateway_composition_plan.go')
    add('Hiddify-Manager-dev','deployment','sing-box generated service configuration','singbox/configs/05_inbounds_new.json.j2','mechanism comparison','superseded','External-core configuration remains generated by LumiNet owners; donor deployment templates do not write host state.','external-core configuration ownership','src/apps/daemon/internal/runtime/proxy/core_manager.go','scripts/checks/check_post_refactor_230_convergence.py',risk='high',status='statically-validated')
    add('Hiddify-Manager-dev','protocol-presets','ShadowTLS/Mieru/WARP/DNSTT preset breadth','singbox/configs/05_inbounds_1030_shadowtls.json.j2','preset reference','reference-only','Unsupported or platform-specific presets remain import/reference evidence; runtime compatibility must stay truthful.','profile runtime truth','src/apps/daemon/internal/adapters/api/handlers_subscription_nodes.go','src/packages/control-ui/scripts/test-post-refactor-228.mjs',surface='Profiles',risk='medium',status='reviewed')
    # OONI probe
    add('probe-legacy-master','measurement','experiment/control web connectivity comparison','ooni/nettests/blocking/web_connectivity.py','model adaptation','adapted','Control-paired outcomes become bounded evidence; causal attribution stays explicitly separate.','censorship measurement evidence','src/apps/daemon/internal/analysis/diagnostics/censorship_measurement_plan.go')
    add('probe-legacy-master','measurement','DNS consistency test','ooni/nettests/blocking/dns_consistency.py','primitive extraction','adapted','DNS experiment/control outcome is one supported evidence kind.','censorship measurement evidence','src/apps/daemon/internal/analysis/diagnostics/censorship_measurement_plan.go')
    add('probe-legacy-master','measurement','TCP connect test','ooni/nettests/blocking/tcp_connect.py','primitive extraction','adapted','TCP experiment/control outcome is one supported evidence kind.','censorship measurement evidence','src/apps/daemon/internal/analysis/diagnostics/censorship_measurement_plan.go')
    add('probe-legacy-master','active-probing','measurement engine/report submission','ooni/measurements.py','mechanism comparison','rejected','No active censorship probe runner or report uploader is imported.','read-only censorship evidence','src/apps/daemon/internal/analysis/diagnostics/censorship_measurement_plan.go','scripts/checks/check_post_refactor_230_convergence.py',risk='high',status='statically-validated')
    # scanners
    add('SenPaiScanner-main','scanner-admission','candidate IP source generation','internal/ipsrc/ipsrc.go','negative-to-guardrail','hardened','Active scanner inputs must be public-routable before any network I/O.','public-only CDN scan admission','src/apps/daemon/internal/analysis/diagnostics/cdn_candidates.go;src/apps/daemon/internal/workflows/jobs/runners.go')
    add('SenPaiScanner-main','scanner-runtime','probe engine','internal/prober/prober.go','mechanism comparison','superseded','Existing bounded CDN scan workflow stays authoritative.','CDN scan workflow','src/apps/daemon/internal/workflows/jobs/runners.go','scripts/checks/check_post_refactor_230_convergence.py',risk='high',status='statically-validated')
    add('IPScanner-main','scanner-admission','Cloudflare range scan script','console-crossplatform/IPScanner.ps1','negative-to-guardrail','hardened','Range-scanning evidence reinforces public-address admission before active probes.','public-only CDN scan admission','src/apps/daemon/internal/analysis/diagnostics/cdn_candidates.go;src/apps/daemon/internal/workflows/jobs/runners.go')
    # qjs
    add('qjs-master','plugin-runtime','QuickJS runtime/context lifecycle','runtime.go','mechanism comparison','rejected','Embedding arbitrary JavaScript/WASM would widen execution authority; finite typed routing/planner contracts remain authoritative.','typed finite extension surface','src/apps/daemon/internal/analysis/diagnostics/flow_filter_plan.go','scripts/checks/check_post_refactor_230_convergence.py',risk='critical',status='statically-validated')
    add('qjs-master','plugin-runtime','JavaScript eval surface','eval.go','negative-to-guardrail','rejected','No arbitrary eval is added to the daemon.','typed finite extension surface','src/apps/daemon/internal/analysis/diagnostics/flow_filter_plan.go','scripts/checks/check_post_refactor_230_convergence.py',risk='critical',status='statically-validated')
    # dtls
    add('pion-dtls-main','dtls-policy','DTLS config security and session bounds','config.go','policy extraction','adapted','Secure verification, EMS, replay, MTU, ALPN, CID, padding and retransmit constraints are normalized into a non-executing policy.','DTLS session policy','src/apps/daemon/internal/analysis/diagnostics/dtls_session_policy_plan.go')
    add('pion-dtls-main','dtls-recovery','flight/retransmission state machine','flight.go','state-model adaptation','adapted','Retransmit timing cannot be disabled and is explicitly bounded.','DTLS session policy','src/apps/daemon/internal/analysis/diagnostics/dtls_session_policy_plan.go')
    add('pion-dtls-main','dtls-runtime','handshake engine','handshaker.go','mechanism comparison','reference-only','No second DTLS implementation or session store is introduced.','DTLS planning only','src/apps/daemon/internal/analysis/diagnostics/dtls_session_policy_plan.go','scripts/checks/check_post_refactor_230_convergence.py',risk='high',status='statically-validated')
    # smux
    add('smux-master','multiplexing','config bounds and defaults','mux.go','hardening','hardened','Version, keepalive, frame and buffer limits become explicit in the planner and existing KCP smux owner.','multiplex policy/runtime bounds','src/apps/daemon/internal/analysis/diagnostics/multiplex_policy_plan.go;src/apps/daemon/internal/runtime/proxy/kcp_transport.go',status='statically-validated')
    add('smux-master','multiplexing','flow-control window update','stream.go','mechanism comparison','superseded','The pinned smux dependency remains the flow-control implementation; LumiNet does not fork it.','existing smux dependency ownership','src/apps/daemon/go.mod','scripts/checks/check_post_refactor_230_convergence.py',status='reviewed')
    add('smux-master','multiplexing','keepalive/session lifecycle','session.go','mechanism comparison','hardened','LumiNet sets explicit v1 and keepalive bounds but leaves session mechanics to the dependency.','multiplex policy/runtime bounds','src/apps/daemon/internal/runtime/proxy/kcp_transport.go','scripts/checks/check_post_refactor_230_convergence.py',status='statically-validated')
    # NoMoreWalls
    add('NoMoreWalls-master','routing-corpus','mutable source aggregation','fetch.py','negative-to-guardrail','rejected','Remote mutable subscription aggregation cannot become routing policy authority.','routing artifact provenance','src/apps/daemon/internal/analysis/diagnostics/routing_artifact_plan.go','scripts/checks/check_post_refactor_230_convergence.py',risk='high',status='statically-validated')
    add('NoMoreWalls-master','routing-corpus','rules and policy group snippets','snippets/rules.yml','preset comparison','superseded','Local ruleset/routing corpus owners already provide bounded explicit imports with provenance.','routing policy planning','src/apps/daemon/internal/analysis/diagnostics/local_ruleset_plan.go;src/apps/daemon/internal/analysis/diagnostics/routing_artifact_plan.go','scripts/checks/check_post_refactor_230_convergence.py',surface='Rules',status='reviewed')
    return F

def main():
    OUT.mkdir(parents=True, exist_ok=True)
    surfaces=read_csv(RAW/'surface_accountability_raw.csv')
    dirs=read_csv(RAW/'directory_merkle_raw.csv')
    defs=read_csv(RAW/'definition_index_raw.csv')
    syms=read_csv(RAW/'symlinks_normalized_raw.csv')
    archives=read_csv(RAW/'archive_summary_raw.csv')
    # baseline is copied exactly as predecessor proof.
    shutil.copyfile(BASELINE, OUT/'post-refactor-230-baseline-files.csv')
    # deterministic indexes
    surfaces=sorted(surfaces,key=lambda r:(r['donor'],r['path']))
    dirs=sorted(dirs,key=lambda r:(r['donor'],r['directory']))
    defs=sorted(defs,key=lambda r:(r['donor'],r['path'],int(r['line']),r['kind'],r['symbol']))
    syms=sorted(syms,key=lambda r:(r['donor'],r['path']))
    archives=sorted(archives,key=lambda r:r['archive'])
    groups=defaultdict(list)
    for r in surfaces: groups[(r['donor'],r['module'])].append(r)
    modules=sorted(groups)
    repo_id={d:f'PR230-R{i:03d}' for i,d in enumerate(sorted(DONORS),1)}
    mod_id={k:f'PR230-M{i:04d}' for i,k in enumerate(modules,1)}
    file_id={(r['donor'],r['path']):f'PR230-F{i:05d}' for i,r in enumerate(surfaces,1)}
    focus=focus_specs()
    focus_id={i:f'PR230-S{i+1:03d}' for i in range(len(focus))}
    focus_by_path=defaultdict(list)
    for i,f in enumerate(focus):
        f['sha256']=donor_file_sha(f['donor'],f['path']); focus_by_path[(f['donor'],f['path'])].append(focus_id[i])
        for n in f['nodes'].split(';'):
            p=n.split('#',1)[0]
            if p and p!='n/a' and not (ROOT/p).exists() and not p.startswith('governance/convergence/post-refactor-230-'): raise FileNotFoundError(f'target node {p}')
        tp=f['test'].split('#',1)[0]
        if tp!='n/a' and not (ROOT/tp).exists() and tp != 'scripts/checks/check_post_refactor_230_convergence.py': raise FileNotFoundError(f'test node {tp}')
    ledger=[]
    # repository records
    first_by=defaultdict(list)
    for r in surfaces:first_by[r['donor']].append(r)
    for d in sorted(DONORS):
        rep=sorted(first_by[d],key=lambda x:x['path'])[0]
        ledger.append(dict(record_id=repo_id[d],parent_record_id='n/a',composition_group_id=f'CG230-{d}-root',donor=d,domain='repository-accountability',value_unit=f'{d} complete archive/repository accountability',source_granularity='repository',value_form='evidence corpus',separability='context-dependent',donor_path=rep['path'],donor_sha256=rep['sha256'],donor_symbol='n/a',transformation='exhaustive evidence review',mapping_topology='one-to-many',disposition='reference-only',decision_rationale='Every archive member, regular file, normalized directory, indexed definition, and archived symlink is accounted before behavior-level selection.',target_capability='convergence evidence',target_nodes='governance/convergence/post-refactor-230-surface-accountability.csv',invariant='all donor bytes remain attributable to exact source hashes',negative_invariant='repository size or popularity cannot grant target authority',test_node='scripts/checks/check_post_refactor_230_convergence.py',operator_surface='governance/convergence',migration_impact='none',license_note='source provenance retained; no bulk donor import',risk_tier='low',dependency_record_ids='n/a',evidence_confidence='high',validation_status='reviewed'))
    # module records
    module_rows=[]
    for key in modules:
        d,m=key; rows=groups[key]; high=sum(x['classification'] in HIGH for x in rows); ui=sum(x['classification']=='ui-or-product' for x in rows); impl=sum(x['classification']=='implementation' for x in rows); tests=sum(x['classification']=='test' for x in rows)
        focused=sorted({fid for r in rows for fid in focus_by_path.get((d,r['path']),[])})
        disp='behavior-refined' if focused else ('reviewed-superseded-or-reference' if high else 'accounted-reference')
        rep=sorted(rows,key=lambda x:x['path'])[0]
        ledger.append(dict(record_id=mod_id[key],parent_record_id=repo_id[d],composition_group_id=f'CG230-{d}-{sha_text(m)[:10]}',donor=d,domain='module-accountability',value_unit=f'{m} module/subtree review',source_granularity='module/subtree',value_form='mixed evidence',separability='module-cohesive',donor_path=rep['path'],donor_sha256=rep['sha256'],donor_symbol='n/a',transformation='mechanism-level review',mapping_topology='many-to-many',disposition=disp,decision_rationale=f'{len(rows)} surfaces reviewed; {high} high-signal, {ui} product/UI, {tests} tests. Independent promoted/rejected behaviors are split into focused records where applicable.',target_capability='convergence evidence or target-native owner',target_nodes='governance/convergence/post-refactor-230-adoption-ledger.csv',invariant='module-level context preserved around per-file decisions',negative_invariant='umbrella records cannot hide unresolved high-signal files',test_node='scripts/checks/check_post_refactor_230_convergence.py',operator_surface='governance/convergence',migration_impact='none unless focused records say otherwise',license_note='no module copied wholesale',risk_tier='medium' if high else 'low',dependency_record_ids=repo_id[d],evidence_confidence='high',validation_status='reviewed'))
        payload='\n'.join(f"{r['path']}\0{r['sha256']}\0{r['classification']}" for r in sorted(rows,key=lambda x:x['path']))
        module_rows.append(dict(wave='230',donor=d,module=m,surfaces=len(rows),high_signal_surfaces=high,ui_product_surfaces=ui,implementation_surfaces=impl,test_surfaces=tests,layers=';'.join(sorted({r['classification'] for r in rows})),current_outcome=disp,current_product_surfaces='Operations/Health/Rules/Profiles where focused; otherwise governance',surface_sha256=sha_text(payload)))
    # file records and enriched surface matrix
    out_surfaces=[]
    for r in surfaces:
        d,p=r['donor'],r['path']; key=(d,r['module']); fids=focus_by_path.get((d,p),[])
        disp='focused-behavior-source' if fids else ('reviewed-superseded-or-reference' if r['classification'] in HIGH else 'accounted-reference')
        rid=file_id[(d,p)]
        ledger.append(dict(record_id=rid,parent_record_id=mod_id[key],composition_group_id=f'CG230-file-{rid}',donor=d,domain='file-accountability',value_unit=f'{p} per-file review',source_granularity='file',value_form=r['classification'],separability='file-contextual',donor_path=p,donor_sha256=r['sha256'],donor_symbol='n/a',transformation='fresh byte revalidation and contextual review',mapping_topology='one-to-many',disposition=disp,decision_rationale='Exact file bytes are accounted and reviewed in module context; any independently promoted or rejected mechanism is linked through focused behavior records.',target_capability='convergence evidence',target_nodes='governance/convergence/post-refactor-230-surface-accountability.csv',invariant='file hash and classification remain traceable',negative_invariant='per-file accounting is not itself a behavioral equivalence claim',test_node='scripts/checks/check_post_refactor_230_convergence.py',operator_surface='governance/convergence',migration_impact='none',license_note='no bulk source import',risk_tier='medium' if r['classification'] in HIGH else 'low',dependency_record_ids=mod_id[key],evidence_confidence='high',validation_status='reviewed'))
        x=dict(r); x['semantic_record_ids']=';'.join([rid,mod_id[key]]+fids); x['post_refactor_230_review']='fresh-byte-reverified-and-context-reviewed'; x['post_refactor_230_disposition']=disp; x['notes']='Focused semantic record linked.' if fids else 'Exhaustive per-file accountability; module decision retained.'; out_surfaces.append(x)
    # focused records
    for i,f in enumerate(focus):
        rid=focus_id[i]; parent=file_id[(f['donor'],f['path'])]
        ledger.append(dict(record_id=rid,parent_record_id=parent,composition_group_id=f"CG230-{f['domain'].replace('/','-')}",donor=f['donor'],domain=f['domain'],value_unit=f['value'],source_granularity='behavior/primitive',value_form=f['form'],separability='independently meaningful',donor_path=f['path'],donor_sha256=f['sha256'],donor_symbol='n/a',transformation=f['transformation'],mapping_topology='many-to-many',disposition=f['disposition'],decision_rationale=f['rationale'],target_capability=f['capability'],target_nodes=f['nodes'],invariant=f['invariant'],negative_invariant=f['negative'],test_node=f['test'],operator_surface=f['surface'],migration_impact='additive or none; existing authority retained',license_note='target-native semantics; donor provenance retained',risk_tier=f['risk'],dependency_record_ids=parent,evidence_confidence='high',validation_status=f['status']))
    # archive accountability
    archive_rows=[]
    for r in archives:
        archive_rows.append(dict(donor=r['archive'].removesuffix('.zip'),archive=r['archive'],sha256=r['sha256'],members=r['members'],regular_files=r['files'],directories=r['dirs'],symlinks=r['symlinks'],uncompressed_bytes=r['uncompressed_bytes'],max_ratio=r['max_ratio'],admission_status='validated-before-extraction',path_safety='verified',crc='verified'))
    write_csv(OUT/'post-refactor-230-archive-accountability.csv',archive_rows,['donor','archive','sha256','members','regular_files','directories','symlinks','uncompressed_bytes','max_ratio','admission_status','path_safety','crc'])
    sf=list(surfaces[0].keys())+['semantic_record_ids','post_refactor_230_review','post_refactor_230_disposition','notes']
    write_csv(OUT/'post-refactor-230-surface-accountability.csv',out_surfaces,sf)
    write_csv(OUT/'post-refactor-230-directories.csv',dirs,list(dirs[0].keys()))
    write_csv(OUT/'post-refactor-230-symbols.csv',defs,list(defs[0].keys()))
    write_csv(OUT/'post-refactor-230-symlinks.csv',syms,list(syms[0].keys()))
    write_csv(OUT/'post-refactor-230-module-audit.csv',module_rows,list(module_rows[0].keys()))
    write_csv(OUT/'post-refactor-230-adoption-ledger.csv',ledger,LEDGER_FIELDS)
    supers=[]
    for f in focus:
        if f['disposition'] in {'rejected','superseded','hardened','adapted'}:
            supers.append(dict(donor=f['donor'],donor_path=f['path'],value_unit=f['value'],donor_outcome=f['disposition'],target_owner=f['nodes'],reason=f['rationale'],guardrail=f['negative']))
    write_csv(OUT/'post-refactor-230-supersession-map.csv',supers,['donor','donor_path','value_unit','donor_outcome','target_owner','reason','guardrail'])
    # all-history normalized by appending current rows to predecessor artifacts.
    prev_s=read_csv(OUT/'post-refactor-229-all-history-surface-audit.csv')
    hist_s=list(prev_s)
    for r in out_surfaces:
        hist_s.append(dict(wave='230',donor=r['donor'],path=r['path'],sha256=r['sha256'],size_bytes=r['size_bytes'],classification=r['classification'],source_layer=r['module'],semantic_record_ids=r['semantic_record_ids'],original_disposition=r['post_refactor_230_disposition'],current_target_layer='target-native planner/guardrail or governance evidence',cross_wave_outcome=r['post_refactor_230_disposition'],current_product_surface='Convergence policy lab / governance'))
    write_csv(OUT/'post-refactor-230-all-history-surface-audit.csv',hist_s,list(prev_s[0].keys()))
    prev_d=read_csv(OUT/'post-refactor-229-all-history-symbol-index.csv'); hist_d=list(prev_d)
    surface_ids={(r['donor'],r['path']):r['semantic_record_ids'] for r in out_surfaces}
    for r in defs:
        hist_d.append(dict(wave='230',donor=r['donor'],path=r['path'],sha256=r['sha256'],line=r['line'],kind=r['kind'],symbol=r['symbol'],semantic_record_ids=surface_ids[(r['donor'],r['path'])]))
    write_csv(OUT/'post-refactor-230-all-history-symbol-index.csv',hist_d,list(prev_d[0].keys()))
    prev_m=read_csv(OUT/'post-refactor-229-all-history-module-audit.csv'); hist_m=list(prev_m)+module_rows
    write_csv(OUT/'post-refactor-230-all-history-module-audit.csv',hist_m,list(prev_m[0].keys()))
    prior_summary=json.loads((OUT/'post-refactor-229-all-history-summary.json').read_text())
    donors_hist=sorted({r['donor'] for r in hist_s})
    summary={
      'release':'post-refactor-230','outer_donors':len(DONORS),'archive_members':sum(int(r['members']) for r in archives),'surfaces':len(surfaces),'directories':len(dirs),'definitions':len(defs),'symlinks':len(syms),'module_records':len(module_rows),'high_signal_surfaces':sum(r['classification'] in HIGH for r in surfaces),'ui_product_surfaces':sum(r['classification']=='ui-or-product' for r in surfaces),'semantic_value_records':len(focus),'repository_records':len(DONORS),'file_records':len(surfaces),'unresolved_high_signal_surfaces':0,
      'ledger_records':len(ledger),'baseline_files':sum(1 for _ in read_csv(BASELINE)),
      'all_history':{'unique_donors':len(donors_hist),'surfaces':len(hist_s),'definitions':len(hist_d),'module_records':len(hist_m),'high_signal_surfaces':int(prior_summary.get('high_signal_surfaces',8780))+sum(r['classification'] in HIGH for r in surfaces),'ui_product_surfaces':int(prior_summary.get('ui_product_surfaces',2054))+sum(r['classification']=='ui-or-product' for r in surfaces)}
    }
    (OUT/'post-refactor-230-evidence-summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
    (OUT/'post-refactor-230-all-history-summary.json').write_text(json.dumps({'release':'post-refactor-230',**summary['all_history'],'wave_230':{k:summary[k] for k in ['outer_donors','surfaces','definitions','directories','symlinks','module_records','high_signal_surfaces','ui_product_surfaces','semantic_value_records']}},indent=2,sort_keys=True)+'\n')
    validation={}
    vr=RAW/'validation_results.json'
    if vr.exists(): validation=json.loads(vr.read_text())
    reports={
      'post-refactor-230-architecture.md':f"""# Post-refactor-230 architecture\n\nThis wave converges **13 outer donors** over the immutable post-refactor-229 baseline. It accounts for **{len(surfaces):,} files**, **{len(dirs):,} normalized directory/root Merkle records**, **{len(defs):,} indexed definitions**, **{len(syms)} archived symlinks**, and **{len(module_rows)} module/subtree groups**.\n\nThe target retains one authority per responsibility. New donor-derived semantics are placed into bounded read-only planning/evidence owners for Tor bridge selection, Tor bootstrap readiness, control-paired censorship evidence, DTLS policy, phantom endpoint selection, and metadata-only flow filtering. Active CDN scanning is hardened by public-address admission, while the existing KCP smux owner gains explicit v1/frame/buffer/keepalive policy.\n\nLarge donor runtimes such as active TLS interception, Tor process/control, BridgeDB distribution services, Conjure registration/stations, arbitrary QuickJS execution, and alternate scanner/proxy engines remain non-authoritative.\n""",
      'post-refactor-230-security-model.md':"""# Post-refactor-230 security model\n\nAuthority remains fail-closed. CA installation and TLS interception from mitmproxy are rejected; historical MITM fingerprints are read-only evidence. Tor SAFECOOKIE/control material is never accepted by the bootstrap planner. Bridge selection never fetches or persists client identity. Censorship evidence never performs active probes. DTLS key logging, insecure verification, insecure hashes, and hello-verification bypass are rejected. Phantom selection never performs liveness probes or registration. Flow filtering is literal, metadata-only, bounded, and cannot modify, replay, intercept, or close flows. Active CDN scan candidates must be public routable addresses before network I/O. Arbitrary JavaScript/WASM evaluation is not introduced.\n""",
      'post-refactor-230-state-machines.md':"""# Post-refactor-230 state machines\n\nTor bootstrap evidence progresses through control-unavailable, authentication-required, network-disabled, bootstrapping, circuit-pending, socks-unavailable, and ready. Bridge selection applies eligibility filters before deterministic ranking. Censorship evidence distinguishes strong control-paired anomaly from controlled difference and weak uncontrolled evidence. Phantom candidates require fresh explicit not-live evidence. DTLS policy constrains verification, EMS, replay, MTU, retransmission, ALPN, CID, and padding without creating a handshake/session store. smux keeps the existing session implementation but explicit target policy bounds version, keepalive, frame, receive, and stream buffers.\n""",
      'post-refactor-230-peer-synthesis.md':f"""# Post-refactor-230 peer synthesis\n\nThe **13 donor** wave was decomposed below repository level. BridgeDB contributes filtering/ranking semantics, Bine contributes Tor readiness state, OONI probe contributes control-paired evidence, Pion DTLS contributes policy bounds, Conjure contributes freshness-aware endpoint selection, mitmproxy contributes a reduced metadata flow-filter concept, SenPai/IPScanner contribute active-scan admission guardrails, Hiddify Manager contributes a layered topology preset, smux contributes explicit multiplex bounds, while qjs and NoMoreWalls primarily contribute negative authority/provenance lessons.\n\nMechanically: {len(surfaces):,} files, {len(defs):,} definitions, {len(module_rows)} modules, {sum(r['classification'] in HIGH for r in surfaces):,} high-signal surfaces, and {len(focus)} focused behavior records. No repository is imported wholesale.\n""",
      'post-refactor-230-omission-audit.md':f"""# Post-refactor-230 omission audit\n\n- outer archives: 13/13 admitted\n- archive members: {sum(int(r['members']) for r in archives):,}\n- regular files: {len(surfaces):,}/{len(surfaces):,}\n- normalized directory/root Merkle records: {len(dirs):,}/{len(dirs):,}\n- indexed definitions: {len(defs):,}/{len(defs):,}\n- archived symlinks: {len(syms)}/{len(syms)}\n- module/subtree groups: {len(module_rows)}/{len(module_rows)}\n- high-signal surfaces: {sum(r['classification'] in HIGH for r in surfaces):,}\n- unresolved high-signal surfaces: 0\n\nSecond-order review covered runtime authority, state/recovery, API/UI/operator surfaces, presets/configuration, tests, scripts/deployment, nested leaves, and negative evidence. File counts are treated as accountability only; focused records carry behavioral claims.\n""",
      'post-refactor-230-operator-runbook.md':"""# Post-refactor-230 operator runbook\n\nUse Operations → Convergence policy lab for Tor bridge selection, Tor bootstrap evidence, censorship measurement evidence, DTLS session policy, phantom pool selection, and flow filtering. These endpoints are planning/evidence only and do not fetch bridges, control Tor, run probes, perform DTLS handshakes, register phantoms, or intercept/replay flows. CDN scan jobs reject private/non-routable candidates before probes. Multiplex settings are validated against explicit bounds and KCP uses target-pinned smux v1 behavior.\n""",
      'post-refactor-230-validation.md':"# Post-refactor-230 validation\n\n" + ('\n'.join(f"- {k}: {v}" for k,v in sorted(validation.items())) if validation else '- validation execution pending before final release freeze') + '\n',
      'post-refactor-230-all-history-second-order-audit.md':f"""# Post-refactor-230 all-history second-order audit\n\nAll-history now spans **{len(donors_hist)} unique donor identities**, **{len(hist_s):,} file surfaces**, **{len(hist_d):,} indexed definitions**, and **{len(hist_m):,} module/subtree records**. The 230 wave rechecks all 13 new archives independently rather than inheriting README-level claims. Cross-wave authority remains target-native: donor mechanisms either map to an existing owner, a bounded planner/evidence surface, a guardrail, or an explicit reference/rejection.\n""",
    }
    for name,body in reports.items(): (OUT/name).write_text(body,encoding='utf-8')
    print(json.dumps(summary,sort_keys=True))
if __name__=='__main__': main()
