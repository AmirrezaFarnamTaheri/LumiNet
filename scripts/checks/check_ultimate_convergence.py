#!/usr/bin/env python3
from __future__ import annotations
import csv, hashlib, os, re, sys
from pathlib import Path
from collections import Counter

ROOT=Path(__file__).resolve().parents[2]
G=ROOT/'governance/convergence'
EXPECTED={'donors':63,'members':9795,'nested_members':1,'directories':1594,'surfaces':8223,'modules':571,'symbols':18098,'records':662,'new_semantics':22,'supersession':24,'repairs':13,'high_level_planes':26,'baseline':2565,'symlinks':38}
HEX64=re.compile(r'^[0-9a-f]{64}$')
VALID_STATUS={'verified','statically-validated','reviewed','inferred','unverified','pending'}
VALID_DISPOSITIONS={'adopted','adapted','hardened','extracted','recomposed','synthesized','inspired-native','guardrail-derived','superseded','rejected-with-reason','reference-only'}
DELTA_REL='governance/convergence/ultimate-pass-target-delta.csv'
SUCCESSOR_BASELINE=G/'refactor-pass-baseline-files.csv'

def read_csv(name):
    p=G/name
    if not p.is_file(): raise AssertionError(f'missing {name}')
    with p.open(encoding='utf-8-sig',newline='') as f:return list(csv.DictReader(f))
def refs(v):return [x for x in (v or '').split(';') if x and x!='n/a']
def digest(p:Path):
    if p.is_symlink(): return ('symlink',hashlib.sha256(os.readlink(p).encode()).hexdigest(),os.readlink(p))
    return ('file',hashlib.sha256(p.read_bytes()).hexdigest(),'n/a')
def text(rel):return (ROOT/rel).read_text(encoding='utf-8',errors='replace')
LEGACY_ANCHOR_SUCCESSORS = {
    'src/apps/daemon/internal/adapters/api/config_mutation.go#commitConfigSnapshot': 'src/apps/daemon/internal/adapters/api/config_mutation.go#commitConfigMutation',
    'src/apps/daemon/internal/adapters/api/config_mutation.go#expectedConfigRevision': 'src/apps/daemon/internal/adapters/api/config_mutation.go#configMutationOptions',
}

def anchor_exists(node):
    node=(node or '').strip()
    node=LEGACY_ANCHOR_SUCCESSORS.get(node,node)
    if not node or node=='n/a':return True
    if '#' not in node:return (ROOT/node).is_file()
    rel,a=node.split('#',1); p=ROOT/rel
    if not p.is_file():return False
    raw=p.read_text(encoding='utf-8',errors='replace')
    cands={a,a.split('.')[-1],a.replace('-','_'),a.replace('-',' ')}
    return any(c and re.search(r'(?<![A-Za-z0-9_])'+re.escape(c)+r'(?![A-Za-z0-9_])',raw,re.I) for c in cands)
def scan_current():
    # Once a successor refactor pass exists, validate the frozen ultimate state
    # against that baseline. Later refactors must not rewrite ultimate history.
    if SUCCESSOR_BASELINE.is_file():
        out={}
        with SUCCESSOR_BASELINE.open(encoding='utf-8',newline='') as f:
            for row in csv.DictReader(f):
                rel=row['path'].strip()
                if rel==DELTA_REL:continue
                out[rel]=(row['file_type'].strip(),row['sha256'].strip(),row['link_target'])
        return out
    out={}
    for p in sorted(ROOT.rglob('*')):
        if not (p.is_file() or p.is_symlink()):continue
        rel=p.relative_to(ROOT).as_posix()
        if rel==DELTA_REL or rel.startswith('.git/') or '/__pycache__/' in '/'+rel or rel.endswith('.pyc'):continue
        out[rel]=digest(p)
    return out

def main():
    errors=[]
    try:
        donors=read_csv('ultimate-pass-donors.csv'); dirs=read_csv('ultimate-pass-directories.csv'); surfaces=read_csv('ultimate-pass-surfaces.csv'); modules=read_csv('ultimate-pass-modules.csv'); symbols=read_csv('ultimate-pass-symbols.csv'); ledger=read_csv('ultimate-pass-adoption-ledger.csv'); sups=read_csv('ultimate-pass-supersession-map.csv'); repairs=read_csv('ultimate-pass-target-repairs.csv'); planes=read_csv('ultimate-pass-high-level-plane-audit.csv'); baseline_rows=read_csv('ultimate-pass-baseline-files.csv'); delta_rows=read_csv('ultimate-pass-target-delta.csv'); licenses=read_csv('ultimate-pass-license-map.csv')
    except Exception as e:
        print('ultimate convergence:',e);return 1
    counts={'donors':len(donors),'directories':len(dirs),'surfaces':len(surfaces),'modules':len(modules),'symbols':len(symbols),'records':len(ledger),'supersession':len(sups),'repairs':len(repairs),'high_level_planes':len(planes),'baseline':len(baseline_rows)}
    for k,v in counts.items():
        if v!=EXPECTED[k]:errors.append(f'{k} count {v} != {EXPECTED[k]}')
    new_sem=[r for r in ledger if r['record_id'].startswith('U-S')]
    if len(new_sem)!=EXPECTED['new_semantics']:errors.append(f'new semantic count {len(new_sem)} != {EXPECTED["new_semantics"]}')
    if sum(int(r['member_count']) for r in donors)!=EXPECTED['members']:errors.append('outer archive member denominator mismatch')
    if sum(int(r.get('nested_members') or 0) for r in donors)!=EXPECTED['nested_members']:errors.append('nested archive member denominator mismatch')
    if sum(int(r['file_surfaces']) for r in donors)!=EXPECTED['surfaces']:errors.append('surface rollup mismatch')
    if sum(int(r['directories']) for r in donors)!=EXPECTED['directories']:errors.append('directory rollup mismatch')
    if sum(int(r['symbols']) for r in donors)!=EXPECTED['symbols']:errors.append('symbol rollup mismatch')
    if sum(int(r['symlinks']) for r in donors)!=EXPECTED['symlinks']:errors.append('symlink rollup mismatch')
    if len({r['donor'] for r in donors})!=EXPECTED['donors']:errors.append('duplicate donor identities')
    if len(licenses)!=EXPECTED['donors'] or {r['donor'] for r in licenses}!={r['donor'] for r in donors}:errors.append('license map donor mismatch')
    for d in donors:
        if not HEX64.fullmatch(d.get('archive_sha256','')):errors.append(f"{d.get('donor')}: invalid archive hash")
        if not d.get('archive_issues','').startswith('none'):errors.append(f"{d.get('donor')}: archive safety not closed")

    records={r['record_id']:r for r in ledger}
    if len(records)!=len(ledger) or '' in records:errors.append('duplicate/empty ledger ids')
    surface={(r['donor'],r['path']):r for r in surfaces}
    if len(surface)!=len(surfaces):errors.append('duplicate donor surface rows')
    module_by_id={m['module_id']:m for m in modules}
    if len(module_by_id)!=len(modules):errors.append('duplicate module ids')
    # Ledger source hash, anchors, evidence, dependencies.
    graph={}
    for r in ledger:
        rid=r['record_id']; graph[rid]=refs(r.get('dependency_record_ids'))
        if r.get('disposition') not in VALID_DISPOSITIONS:errors.append(f'{rid}: invalid disposition')
        if r.get('validation_status') not in VALID_STATUS:errors.append(f'{rid}: invalid validation status')
        if r.get('risk_tier') not in {'critical','high','medium','low'}:errors.append(f'{rid}: invalid risk')
        if not HEX64.fullmatch(r.get('donor_sha256','')):errors.append(f'{rid}: invalid donor hash')
        sr=surface.get((r.get('donor'),r.get('donor_path')))
        if not sr:errors.append(f"{rid}: missing donor surface {r.get('donor')}:{r.get('donor_path')}")
        elif sr['sha256']!=r['donor_sha256']:errors.append(f'{rid}: donor hash mismatch')
        for dep in graph[rid]:
            if dep not in records:errors.append(f'{rid}: unknown dependency {dep}')
        for node in refs(r.get('target_nodes')):
            if not anchor_exists(node):errors.append(f'{rid}: missing target anchor {node}')
        for node in refs(r.get('test_node')):
            if not anchor_exists(node):errors.append(f'{rid}: missing test anchor {node}')
        if rid.startswith('U-S') and r.get('disposition') not in {'reference-only','superseded'} and r.get('test_node')=='n/a':errors.append(f'{rid}: implemented/guardrail semantic lacks evidence')
    state={}
    def visit(n,stack):
        if state.get(n)==1:errors.append('ledger dependency cycle: '+' -> '.join(stack+[n]));return
        if state.get(n)==2:return
        state[n]=1
        for d in graph.get(n,[]):visit(d,stack+[n])
        state[n]=2
    for rid in graph:visit(rid,[])

    # Every surface has exactly one bounded module owner; every semantic link resolves.
    module_counts=Counter()
    for s in surfaces:
        if not HEX64.fullmatch(s.get('sha256','')):errors.append(f"surface {s['donor']}:{s['path']}: invalid hash")
        ids=refs(s.get('semantic_record_ids')); mids=[x for x in ids if x.startswith(('FP-M','U-M'))]
        if len(mids)!=1:errors.append(f"surface {s['donor']}:{s['path']}: expected one module link, got {mids}")
        else:module_counts[mids[0]]+=1
        for rid in ids:
            if rid not in records:errors.append(f"surface {s['donor']}:{s['path']}: unknown record {rid}")
    for mid,m in module_by_id.items():
        n=module_counts[mid]
        if n!=int(m['surface_count']):errors.append(f'{mid}: surface count {n} != {m["surface_count"]}')
        if n>100:errors.append(f'{mid}: umbrella module >100 surfaces')
        lr=records.get(mid)
        if not lr or lr['donor']!=m['donor'] or lr['donor_path']!=m['representative_path'] or lr['donor_sha256']!=m['representative_sha256']:errors.append(f'{mid}: module ledger mismatch')

    # Higher-level plane evidence and ownership.
    for hp in planes:
        eps=refs(hp.get('evidence_paths')); ehs=refs(hp.get('evidence_sha256'))
        if len(eps)!=len(ehs) or not eps:errors.append(f"plane {hp.get('plane')}: evidence cardinality mismatch");continue
        for ep,eh in zip(eps,ehs):
            if ':' not in ep:errors.append(f"plane {hp.get('plane')}: malformed evidence {ep}");continue
            donor,path=ep.split(':',1); sr=surface.get((donor,path))
            if not sr:errors.append(f"plane {hp.get('plane')}: missing donor evidence {ep}")
            elif sr['sha256']!=eh:errors.append(f"plane {hp.get('plane')}: hash mismatch {ep}")
        for owner in refs(hp.get('current_target_owner')):
            if not (ROOT/owner).exists():errors.append(f"plane {hp.get('plane')}: missing target owner {owner}")
        if hp.get('validation_status') not in VALID_STATUS:errors.append(f"plane {hp.get('plane')}: bad status")
        if not hp.get('decision_rationale') or not hp.get('invariant') or not hp.get('residual_gap'):errors.append(f"plane {hp.get('plane')}: incomplete decision")

    # All 63 donors must appear in the many-to-many synthesis/supersession map.
    sup_donors=set()
    for s in sups:sup_donors.update(refs(s.get('donors')))
    all_donors={r['donor'] for r in donors}
    if sup_donors!=all_donors:errors.append(f'supersession donor coverage mismatch missing={sorted(all_donors-sup_donors)} extra={sorted(sup_donors-all_donors)}')

    # Exact target delta against frozen all-43 baseline.
    baseline={r['path']:(r['file_type'],r['sha256'],r['link_target']) for r in baseline_rows}
    current=scan_current(); expected={}
    for p in sorted(set(baseline)|set(current)):
        a,b=baseline.get(p),current.get(p)
        if a==b:continue
        if a is None:expected[p]=('added','n/a',b[1])
        elif b is None:expected[p]=('deleted',a[1],'n/a')
        else:expected[p]=('modified',a[1],b[1])
    delta={}
    for r in delta_rows:
        p=r.get('path','').strip()
        if not p or p in delta:errors.append(f'duplicate/empty ultimate delta path {p!r}');continue
        delta[p]=r; exp=expected.get(p)
        if exp is None:errors.append(f'ultimate delta {p}: not changed');continue
        got=(r.get('change_type'),r.get('final_pass_sha256'),r.get('current_sha256'))
        if got!=exp:errors.append(f'ultimate delta {p}: mismatch got={got} expected={exp}')
        if not r.get('accountability_class','').strip() or not r.get('reason','').strip():errors.append(f'ultimate delta {p}: incomplete accountability')
    miss=sorted(set(expected)-set(delta));extra=sorted(set(delta)-set(expected))
    if miss:errors.append(f'ultimate target delta missing {len(miss)} paths: {miss[:50]}')
    if extra:errors.append(f'ultimate target delta extra {len(extra)} paths: {extra[:50]}')

    # Current-wave semantic invariants.
    watcher=text('src/apps/daemon/internal/platform/system/file_watcher.go'); runtime_watcher=text('src/apps/daemon/internal/runtime/proxy/config_watcher.go')
    for m in ['filepath.Dir','fsnotify.Create','fsnotify.Rename','fsnotify.Remove','timerMap','defaultConfigWatcherDebounce']:
        if m not in watcher:errors.append(f'watcher invariant missing {m}')
    if 'system.NewConfigWatcher' not in runtime_watcher:errors.append('runtime config watcher did not converge onto canonical system watcher')
    torcfg=text('src/apps/daemon/internal/platform/system/tor_config_builder.go'); mgr=text('src/apps/daemon/internal/runtime/runtimecore/manager.go'); adapters=text('src/apps/daemon/internal/runtime/runtimecore/adapters.go'); mt=text('src/apps/daemon/internal/runtime/runtimecore/manager_test.go')
    for m in ['BridgesWithTransports','maxTorTransportPlugins','formatTorToken','AvoidDiskWrites 1']:
        if m not in torcfg:errors.append(f'Tor config invariant missing {m}')
    for m in ['torTransportExecutableRegistry','torTransportArgumentRegistry','newManagerWithFactoryAndPreflight','m.preflight','normalizeTorTransportPluginRequest']:
        if m not in mgr:errors.append(f'Tor runtime authority invariant missing {m}')
    for m in ['productionPreflight','resolveTorTransportExecutable','Mode().IsRegular','runtime.GOOS']:
        if m not in adapters:errors.append(f'Tor executable preflight invariant missing {m}')
    for m in ['TestManagerPreflightFailureDoesNotStopCurrentEngine','TestManagerRejectsUnapprovedTorTransportArguments','TestManagerAllowsNarrowSnowflakeClientArgument']:
        if m not in mt:errors.append(f'Tor transport regression missing {m}')
    engine=text('src/apps/daemon/internal/runtime/runtimecore/tor_engine.go')
    if 'GeoIPFile' in engine or 'GeoIPv6File' in engine:errors.append('runtime Tor engine still points fresh temp DataDirectory at nonexistent GeoIP files')

    resolver=text('src/apps/daemon/internal/networking/dns/resolver.go'); dtest=text('src/apps/daemon/internal/networking/dns/resolver_dot_test.go')
    for m in ['DoTEndpoint','resolveDoT','LookupEncryptedA','configureDoHProxy','MinVersion:             tls.VersionTLS12','http.ErrUseLastResponse','DoT proxy must use socks5']:
        if m not in resolver:errors.append(f'encrypted DNS invariant missing {m}')
    for m in ['TestDoTDialRejectsNonSOCKSProxyBeforeNetwork','TestConfigureDoHProxyFailsClosed']:
        if m not in dtest:errors.append(f'encrypted DNS regression missing {m}')
    dnsel=text('src/apps/daemon/internal/analysis/diagnostics/tor_exit_check.go'); torops=text('src/apps/daemon/internal/adapters/api/handlers_tor_ops.go'); routes=text('src/apps/daemon/internal/adapters/api/routes_system.go')
    for m in ['TorExitUnknown','dnsel_nxdomain','dnsel_unavailable','dnsel_127_0_0_2']:
        if m not in dnsel:errors.append(f'DNSEL tri-state invariant missing {m}')
    if 'LookupEncryptedA' not in torops or 'via_tor' not in torops:errors.append('live Tor DNSEL handler is not encrypted-DNS/Tor-aware')
    if '/tor/exit-check' not in routes or 'CapProxyControl' not in routes:errors.append('Tor exit diagnostic route/capability missing')

    quality=text('src/apps/daemon/internal/runtime/proxy/node_latency_tester.go'); tlspeer=text('src/apps/daemon/internal/analysis/scanner/probe_pipeline_utils.go')
    for m in ['EndpointQualityResult','LossPercent','MedianLatency','BetterEndpointQuality','maxEndpointQualitySamples']:
        if m not in quality:errors.append(f'endpoint quality primitive missing {m}')
    for m in ['Issuer','ChainLength','ChainBytes','SignatureAlgorithm','PublicKeyAlgorithm']:
        if m not in tlspeer:errors.append(f'TLS evidence primitive missing {m}')

    # Historical/final invariants remain authoritative.
    remote=text('src/apps/daemon/internal/foundation/remoteaction/remoteaction.go')
    for m in ['RateLimitScope','MaxInFlight','ErrCoordinatorCapacity','ReconcileBeforeRetry','SingleAttempt']:
        if m not in remote:errors.append(f'automatic mutation retry invariant regressed: {m}')
    final_checker=text('scripts/checks/check_final_convergence.py'); make=text('Makefile')
    if "SUCCESSOR_BASELINE=G/'ultimate-pass-baseline-files.csv'" not in final_checker:errors.append('historical final checker lacks ultimate successor baseline')
    if 'check_ultimate_convergence.py' not in make:errors.append('verify-repo does not execute ultimate convergence gate')
    if 'export PYTHONDONTWRITEBYTECODE := 1' not in make:errors.append('verification may create Python bytecode residue')

    if errors:
        print(f'ultimate convergence: errors={len(errors)}')
        for e in errors[:400]:print('ERROR:',e)
        return 1
    print('ultimate convergence: donors={d} members={m}+nested:{nm} directories={dr} surfaces={s} symlinks={sl} modules={mo} symbols={sy} new_semantics={ns} records={r} supersession={su} repairs={rp} high_level_planes={hp} baseline={b} changes={c} errors=0'.format(d=len(donors),m=EXPECTED['members'],nm=EXPECTED['nested_members'],dr=len(dirs),s=len(surfaces),sl=EXPECTED['symlinks'],mo=len(modules),sy=len(symbols),ns=len(new_sem),r=len(ledger),su=len(sups),rp=len(repairs),hp=len(planes),b=len(baseline_rows),c=len(delta_rows)))
    return 0
if __name__=='__main__':sys.exit(main())
