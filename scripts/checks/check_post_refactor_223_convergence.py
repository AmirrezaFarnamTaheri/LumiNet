#!/usr/bin/env python3
from __future__ import annotations
import csv, hashlib, json, os, re, sys
from collections import Counter
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
G=ROOT/'governance/convergence'
P='post-refactor-223'
AE=Path('/mnt/data/luminet_223_rebuild/archive_evidence')
SUCCESSOR_BASELINE=G/'post-refactor-224-baseline-files.csv'
EXPECTED={'archives':13,'surfaces':10331,'symlinks':30,'fresh':10208,'symbols':51441,'records':56,'baseline':2895}
HEX64=re.compile(r'^[0-9a-f]{64}$')
FINAL={'verified','statically-validated','reviewed'}
IMPLEMENTED={'adopted','adapted','hardened','extracted','recomposed','synthesized','inspired-native','guardrail-derived'}
SUCCESSOR_ANCHORS={
    'src/apps/daemon/internal/analysis/scanner/adaptive_throttle.go#AdaptiveThrottle':'src/apps/daemon/internal/analysis/diagnostics/post_refactor_235_plans.go#BuildScanLoadPolicyPlan',
    'src/apps/daemon/internal/analysis/scanner/adaptive_throttle_alignment_test.go#TestAdaptiveThrottleAtomicFieldsAreEightByteAligned':'src/apps/daemon/internal/analysis/diagnostics/post_refactor_235_plans_test.go#TestPostRefactor235ScanLoadTimeoutsDoNotProveCongestion',
}

def rows(name):
    with (G/name).open(newline='',encoding='utf-8') as f: return list(csv.DictReader(f))
def digest(path:Path):
    if path.is_symlink():
        t=os.readlink(path); return 'symlink',hashlib.sha256(t.encode()).hexdigest(),t
    return 'file',hashlib.sha256(path.read_bytes()).hexdigest(),'n/a'
def anchor_exists(node:str)->bool:
    node=(node or '').strip()
    node=SUCCESSOR_ANCHORS.get(node,node)
    if not node or node=='n/a': return True
    if '#' not in node: return (ROOT/node).exists()
    rel,anchor=node.split('#',1); p=ROOT/rel
    return p.is_file() and anchor in p.read_text(encoding='utf-8',errors='replace')
def req(errors,cond,msg):
    if not cond: errors.append(msg)
def scan_current():
    # Historical post-223 evidence becomes immutable once post-224 exists.
    # Compare this wave to the successor's exact pre-224 snapshot rather than
    # interpreting intentional post-224 changes as post-223 regressions.
    if SUCCESSOR_BASELINE.is_file():
        out={}
        with SUCCESSOR_BASELINE.open(encoding='utf-8',newline='') as f:
            for row in csv.DictReader(f):
                rel=row['path'].strip()
                if rel==f'governance/convergence/{P}-target-delta.csv': continue
                out[rel]=(row['file_type'].strip(),row['sha256'].strip(),row.get('link_target','n/a') or 'n/a')
        return out
    out={}
    for p in sorted(ROOT.rglob('*')):
        if not (p.is_file() or p.is_symlink()): continue
        rel=p.relative_to(ROOT).as_posix()
        if rel==f'governance/convergence/{P}-target-delta.csv': continue
        if rel.startswith('.git/') or '/__pycache__/' in '/'+rel or rel.endswith('.pyc') or '/node_modules/' in '/'+rel or '/.gradle/' in '/'+rel: continue
        out[rel]=digest(p)
    return out

def main():
    errors=[]
    try:
        ledger=rows(f'{P}-adoption-ledger.csv'); surfaces=rows(f'{P}-surface-accountability.csv'); symbols=rows(f'{P}-symbols.csv'); delta=rows(f'{P}-target-delta.csv'); baseline=rows(f'{P}-baseline-files.csv'); archives=rows(f'{P}-archive-accountability.csv'); summary=json.loads((G/f'{P}-summary.json').read_text())
    except Exception as e:
        print(f'{P} convergence: load failure: {e}'); return 1
    ids={r['record_id'] for r in ledger}
    req(errors,len(ledger)==EXPECTED['records'],f'ledger count {len(ledger)} != {EXPECTED["records"]}')
    req(errors,len(ids)==len(ledger),'duplicate ledger IDs')
    surface_map={}
    backlinks=Counter()
    req(errors,len(surfaces)==EXPECTED['surfaces'],f'surface count {len(surfaces)} != {EXPECTED["surfaces"]}')
    req(errors,sum(r['file_type']=='symlink' for r in surfaces)==EXPECTED['symlinks'],'symlink count drift')
    for s in surfaces:
        k=(s['donor'],s['path']); req(errors,k not in surface_map,f'duplicate surface {k}'); surface_map[k]=s
        req(errors,HEX64.fullmatch(s['sha256'] or '') is not None,f'invalid surface hash {k}')
        linked=[x for x in s['semantic_record_ids'].split(';') if x]
        req(errors,bool(linked),f'unlinked surface {k}')
        for rid in linked:
            req(errors,rid in ids,f'unknown record {rid} on {k}'); backlinks[rid]+=1
    for r in ledger:
        rid=r['record_id']
        req(errors,r['validation_status'] in FINAL,f'{rid}: non-final validation status')
        req(errors,r['risk_tier'] in {'critical','high','medium','low'},f'{rid}: invalid risk')
        req(errors,HEX64.fullmatch(r['donor_sha256'] or '') is not None,f'{rid}: invalid donor hash')
        src=surface_map.get((r['donor'],r['donor_path']))
        req(errors,src is not None,f'{rid}: evidence surface missing {r["donor"]}:{r["donor_path"]}')
        if src:
            req(errors,src['sha256']==r['donor_sha256'],f'{rid}: evidence hash mismatch')
            req(errors,rid in src['semantic_record_ids'].split(';'),f'{rid}: evidence surface missing backlink')
        req(errors,backlinks[rid]>0,f'{rid}: no surface backlinks')
        if r['disposition'] in IMPLEMENTED:
            req(errors,r['target_nodes']!='n/a',f'{rid}: implemented missing target')
            req(errors,r['test_node']!='n/a',f'{rid}: implemented missing test')
        if r['risk_tier'] in {'critical','high'} and r['disposition']=='rejected-with-reason': req(errors,r['test_node']!='n/a',f'{rid}: high-risk rejection missing guard test')
        for n in r['target_nodes'].split(';'): req(errors,anchor_exists(n),f'{rid}: unresolved target {n}')
        for n in r['test_node'].split(';'): req(errors,anchor_exists(n),f'{rid}: unresolved test {n}')
    req(errors,len(symbols)==EXPECTED['symbols'],f'symbol count {len(symbols)} != {EXPECTED["symbols"]}')
    for s in symbols:
        src=surface_map.get((s['donor'],s['path']))
        req(errors,src is not None,f'symbol source missing {s["donor"]}:{s["path"]}:{s["symbol"]}')
        if src:
            req(errors,src['sha256']==s['sha256'],f'symbol hash mismatch {s["donor"]}:{s["path"]}:{s["symbol"]}')
            req(errors,src['semantic_record_ids']==s['semantic_record_ids'],f'symbol semantic links drift {s["donor"]}:{s["path"]}:{s["symbol"]}')
    req(errors,len(archives)==EXPECTED['archives'],f'archive count {len(archives)} != {EXPECTED["archives"]}')
    req(errors,sum(int(a['surface_members']) for a in archives)==EXPECTED['surfaces'],'archive surface rollup drift')
    req(errors,sum(int(a['symlinks']) for a in archives)==EXPECTED['symlinks'],'archive symlink rollup drift')
    dup=sum(int(a['surface_members']) for a in archives if a['duplicate_of']!='n/a')
    req(errors,dup==123,'historical duplicate surface count drift')
    for a in archives:
        req(errors,HEX64.fullmatch(a['sha256'] or '') is not None,f'archive invalid hash {a["archive"]}')
        if not SUCCESSOR_BASELINE.is_file():
            p=Path('/mnt/data')/a['archive']
            req(errors,p.is_file(),f'uploaded archive unavailable {a["archive"]}')
            if p.is_file(): req(errors,hashlib.sha256(p.read_bytes()).hexdigest()==a['sha256'],f'archive hash mismatch {a["archive"]}')
    req(errors,len(baseline)==EXPECTED['baseline'],'baseline count drift')
    b={r['path']:(r['file_type'],r['sha256'],r.get('link_target','n/a') or 'n/a') for r in baseline}
    current=scan_current(); exp={}
    for path in sorted(set(b)|set(current)):
        before=b.get(path); after=current.get(path)
        if before==after: continue
        if before is None: exp[path]=('added','n/a',after[1])
        elif after is None: exp[path]=('deleted',before[1],'n/a')
        else: exp[path]=('modified',before[1],after[1])
    d={}
    for r in delta:
        path=r['path']; req(errors,path and path not in d,f'duplicate delta path {path!r}'); d[path]=r
        e=exp.get(path); req(errors,e is not None,f'unexpected/unchanged delta {path}')
        if e: req(errors,(r['change_type'],r['baseline_sha256'],r['current_sha256'])==e,f'delta mismatch {path}')
        req(errors,bool(r.get('reason','').strip()),f'delta reason missing {path}')
    missing=sorted(set(exp)-set(d)); extra=sorted(set(d)-set(exp))
    if missing: errors.append(f'delta missing {len(missing)} paths: {missing[:80]}')
    if extra: errors.append(f'delta extra {len(extra)} paths: {extra[:80]}')
    req(errors,int(summary['supplied_surfaces'])==EXPECTED['surfaces'],'summary surface drift')
    req(errors,int(summary['fresh_or_changed_surfaces'])==EXPECTED['fresh'],'summary fresh drift')
    req(errors,int(summary['symbol_records'])==EXPECTED['symbols'],'summary symbols drift')
    req(errors,int(summary['semantic_records'])==EXPECTED['records'],'summary records drift')
    # Cross-wave and live verification requirements.
    make=(ROOT/'Makefile').read_text(errors='replace')
    req(errors,'check_post_refactor_223_convergence.py' in make,'canonical Makefile missing post-223 convergence verifier')
    old=(ROOT/'scripts/checks/check_post_refactor_222_convergence.py').read_text(errors='replace')
    req(errors,'post-refactor-223-baseline-files.csv' in old and 'SUCCESSOR_BASELINE' in old,'post-222 checker not frozen to successor baseline')
    # High-risk product truth guards.
    android=(ROOT/'src/apps/android/app/src/main/AndroidManifest.xml').read_text(errors='replace')
    req(errors,android.count('android.permission.BIND_VPN_SERVICE')==1,'Android gained multiple VPN authorities')
    sub=(ROOT/'src/apps/daemon/internal/integrations/sub/node_catalogue.go').read_text(errors='replace')
    req(errors,'Password' not in (ROOT/'src/apps/daemon/internal/adapters/api/handlers_subscription_nodes.go').read_text(errors='replace'),'subscription node API appears to expose credential field')
    req(errors,'at least one subscription node must remain visible' in sub,'hide-all guard missing')
    bridge=(ROOT/'src/apps/daemon/internal/runtime/proxy/evasion_tunnel.go').read_text(errors='replace')
    req(errors,'ReleaseHostNetworkRoute' in bridge and 'systemProxyBridge.Close' in bridge and bridge.find('ReleaseHostNetworkRoute') < bridge.find('systemProxyBridge.Close'),'host route is not restored before bridge teardown')
    reality=(ROOT/'src/apps/daemon/internal/analysis/scanner/reality_scanner.go').read_text(errors='replace')
    req(errors,'InsecureSkipVerify' not in reality,'REALITY scanner reintroduced insecure TLS verification')
    relay=(ROOT/'src/apps/daemon/internal/adapters/api').read_text(errors='replace') if False else ''
    if errors:
        print(f'{P} convergence: FAIL ({len(errors)} errors)')
        for e in errors[:500]: print('ERROR:',e)
        return 1
    dc=Counter(r['change_type'] for r in delta)
    print(f"{P} convergence: PASS archives={len(archives)} surfaces={len(surfaces)} fresh={EXPECTED['fresh']} symlinks={EXPECTED['symlinks']} symbols={len(symbols)} semantic={len(ledger)} delta={len(delta)} added={dc['added']} modified={dc['modified']} deleted={dc['deleted']}")
    return 0
if __name__=='__main__': raise SystemExit(main())
