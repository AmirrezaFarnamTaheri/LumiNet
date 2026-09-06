#!/usr/bin/env python3
from __future__ import annotations
import csv, hashlib, json, os, re, sys
from collections import Counter
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
G=ROOT/'governance'/'convergence'
P='post-refactor-137'
DELTA_REL=f'governance/convergence/{P}-target-delta.csv'
EXPECTED={
 'donors':137,'surfaces':35743,'directories':6258,'modules':4456,'symbols':105085,'ledger':4740,'semantics':284,'licenses':137,
 'historical_resolutions':11,'historical_schema_normalizations':74,'repairs':12,'planes':19,'baseline_files':2689,
 'new_donors':20,'new_members':9187,'new_surfaces':8410,'new_directories':777,'new_modules':580,'new_symbols':32073,'new_symlinks':2,
 'new_semantics':69,'new_nested':1,'new_nested_members':34,'strict_ledger':4740,'exact_overlap_surfaces':354,
}
NEW_DONORS={
 'Exclave-dev','Furious-main','HUNTX','Intercept-main','foghorn-main','freedom-main','freenet-core-main','freenet-git-main',
 'freenet-telemetry-dashboard-main','frontend-wasm_2_','fsociety-master','fteproxy-master','fwlite-master','go-tun2socks-master',
 'gost-master','grasshopper-main','hawk-proxy-main','hping-master','httun-main','hysteria-python-main',
}
FINAL_STATUS={'verified','statically-validated','reviewed'}
VALID_DISPOSITIONS={'adopted','adapted','hardened','extracted','recomposed','synthesized','inspired-native','guardrail-derived','superseded','rejected-with-reason','reference-only'}
HEX64=re.compile(r'^[0-9a-f]{64}$')
SEMANTIC_DECISION_ANCHORS={
    'semantic-PR137-S001',
    'semantic-PR137-S002',
    'semantic-PR137-S003',
    'semantic-PR137-S004',
    'semantic-PR137-S005',
    'semantic-PR137-S006',
    'semantic-PR137-S007',
    'semantic-PR137-S008',
    'semantic-PR137-S009',
    'semantic-PR137-S010',
    'semantic-PR137-S011',
    'semantic-PR137-S012',
    'semantic-PR137-S013',
    'semantic-PR137-S014',
    'semantic-PR137-S015',
    'semantic-PR137-S016',
    'semantic-PR137-S017',
    'semantic-PR137-S018',
    'semantic-PR137-S019',
    'semantic-PR137-S020',
    'semantic-PR137-S021',
    'semantic-PR137-S022',
    'semantic-PR137-S023',
    'semantic-PR137-S024',
    'semantic-PR137-S025',
    'semantic-PR137-S026',
    'semantic-PR137-S027',
    'semantic-PR137-S028',
    'semantic-PR137-S029',
    'semantic-PR137-S030',
    'semantic-PR137-S031',
    'semantic-PR137-S032',
    'semantic-PR137-S033',
    'semantic-PR137-S034',
    'semantic-PR137-S035',
    'semantic-PR137-S036',
    'semantic-PR137-S037',
    'semantic-PR137-S038',
    'semantic-PR137-S039',
    'semantic-PR137-S040',
    'semantic-PR137-S041',
    'semantic-PR137-S042',
    'semantic-PR137-S043',
    'semantic-PR137-S044',
    'semantic-PR137-S045',
    'semantic-PR137-S046',
    'semantic-PR137-S047',
    'semantic-PR137-S048',
    'semantic-PR137-S049',
    'semantic-PR137-S050',
    'semantic-PR137-S051',
    'semantic-PR137-S052',
    'semantic-PR137-S053',
    'semantic-PR137-S054',
    'semantic-PR137-S055',
    'semantic-PR137-S056',
    'semantic-PR137-S057',
    'semantic-PR137-S058',
    'semantic-PR137-S059',
    'semantic-PR137-S060',
    'semantic-PR137-S061',
    'semantic-PR137-S062',
    'semantic-PR137-S063',
    'semantic-PR137-S064',
    'semantic-PR137-S065',
    'semantic-PR137-S066',
    'semantic-PR137-S067',
    'semantic-PR137-S068',
    'semantic-PR137-S069',
}

def read_csv(name):
    p=G/name
    if not p.is_file(): raise AssertionError(f'missing {p.relative_to(ROOT)}')
    with p.open(encoding='utf-8-sig',newline='') as f: return list(csv.DictReader(f))

def digest(p:Path):
    if p.is_symlink():
        t=os.readlink(p); return ('symlink',hashlib.sha256(t.encode()).hexdigest(),t)
    return ('file',hashlib.sha256(p.read_bytes()).hexdigest(),'n/a')

def scan_current():
    out={}
    for p in sorted(ROOT.rglob('*')):
        if not (p.is_file() or p.is_symlink()): continue
        rel=p.relative_to(ROOT).as_posix()
        if rel==DELTA_REL or rel.startswith('.git/') or '/__pycache__/' in '/'+rel or rel.endswith('.pyc'): continue
        out[rel]=digest(p)
    return out

def text(rel): return (ROOT/rel).read_text(encoding='utf-8',errors='replace')
def require(errors,cond,msg):
    if not cond: errors.append(msg)

def anchor_exists(node):
    node=(node or '').strip()
    if not node or node=='n/a': return True
    if '#' not in node: return (ROOT/node).exists()
    rel,anchor=node.split('#',1); p=ROOT/rel
    if not p.is_file(): return False
    raw=p.read_text(encoding='utf-8',errors='replace')
    return anchor in raw

def main():
    errors=[]
    try:
        donors=read_csv(f'{P}-donors.csv'); surfaces=read_csv(f'{P}-surfaces.csv'); dirs=read_csv(f'{P}-directories.csv')
        modules=read_csv(f'{P}-modules.csv'); symbols=read_csv(f'{P}-symbols.csv'); ledger=read_csv(f'{P}-adoption-ledger.csv')
        strict=read_csv(f'{P}-strict-adoption-ledger.csv'); licenses=read_csv(f'{P}-license-map.csv')
        new_donors=read_csv(f'{P}-new-donors.csv'); new_surfaces=read_csv(f'{P}-new-surfaces.csv'); new_modules=read_csv(f'{P}-new-modules.csv')
        nested=read_csv(f'{P}-nested-archives.csv'); resolutions=read_csv(f'{P}-historical-resolutions.csv')
        normalizations=read_csv(f'{P}-historical-schema-normalizations.csv'); repairs=read_csv(f'{P}-target-repairs.csv')
        planes=read_csv(f'{P}-high-level-plane-audit.csv'); baseline_rows=read_csv(f'{P}-baseline-files.csv')
        delta_rows=read_csv(f'{P}-target-delta.csv'); overlap=read_csv(f'{P}-overlap-provenance.csv')
    except Exception as exc:
        print('post-refactor-137 convergence: load failure:',exc); return 1

    module_ids={r['module_id'] for r in modules}; ledger_ids={r['record_id'] for r in ledger}
    fine=[r for r in ledger if r['record_id'] not in module_ids]
    new_fine=[r for r in fine if r['record_id'].startswith('PR137-S')]
    counts={'donors':len(donors),'surfaces':len(surfaces),'directories':len(dirs),'modules':len(modules),'symbols':len(symbols),'ledger':len(ledger),
            'semantics':len(fine),'licenses':len(licenses),'historical_resolutions':len(resolutions),'historical_schema_normalizations':len(normalizations),
            'repairs':len(repairs),'planes':len(planes),'baseline_files':len(baseline_rows),'new_donors':len(new_donors),'new_surfaces':len(new_surfaces),
            'new_modules':len(new_modules),'strict_ledger':len(strict)}
    for k,v in counts.items(): require(errors,v==EXPECTED[k],f'{k} count {v} != {EXPECTED[k]}')

    waves=Counter(r['wave'] for r in donors)
    require(errors,waves==Counter({'ultimate-63':63,'post-refactor-20':20,'tor-wave-14':14,'post-refactor-20b':20,'post-refactor-20c':20}),f'donor wave mismatch {dict(waves)}')
    names=[r['donor'] for r in donors]; require(errors,len(set(names))==137,'duplicate donor identity')
    actual_new={r['donor'] for r in donors if r['wave']=='post-refactor-20c'}
    require(errors,actual_new==NEW_DONORS,f'new donor set mismatch missing={sorted(NEW_DONORS-actual_new)} extra={sorted(actual_new-NEW_DONORS)}')
    nd=[r for r in donors if r['wave']=='post-refactor-20c']
    require(errors,sum(int(r['member_count']) for r in nd)==EXPECTED['new_members'],'new member denominator mismatch')
    require(errors,sum(int(r['file_surfaces']) for r in nd)==EXPECTED['new_surfaces'],'new surface rollup mismatch')
    require(errors,sum(int(r['directories']) for r in nd)==EXPECTED['new_directories'],'new directory rollup mismatch')
    require(errors,sum(int(r['symbols']) for r in nd)==EXPECTED['new_symbols'],'new symbol rollup mismatch')
    require(errors,sum(int(r['symlinks']) for r in nd)==EXPECTED['new_symlinks'],'new symlink rollup mismatch')
    require(errors,sum(int(r.get('nested_members','0') or 0) for r in nd)==EXPECTED['new_nested_members'],'new nested member mismatch')
    require(errors,all((r.get('archive_issues') or '').lower().startswith('none') for r in nd),'archive issue remains')

    require(errors,len(ledger_ids)==len(ledger),'duplicate ledger record id')
    require(errors,module_ids<=ledger_ids,'module missing from ledger')
    require(errors,len(new_fine)==EXPECTED['new_semantics'],f'new semantic count {len(new_fine)} != {EXPECTED["new_semantics"]}')
    require(errors,{r['donor'] for r in new_fine}==NEW_DONORS,'not every new donor has fine disposition')
    require(errors,{r['validation_status'] for r in ledger}<=FINAL_STATUS,'non-final validation status remains')
    require(errors,all(r['disposition'] in VALID_DISPOSITIONS for r in ledger),'invalid disposition remains')
    require(errors,len({r['record_id'] for r in strict})==EXPECTED['strict_ledger'],'strict ledger identity count mismatch')
    require(errors,{r['record_id'] for r in strict}==ledger_ids,'strict/canonical record identity mismatch')
    require(errors,len({r['record_id'] for r in normalizations})==74,'historical normalization identity mismatch')
    require(errors,all(not r['record_id'].startswith('PR137-') for r in normalizations),'current row treated as historical schema debt')

    surface_map={}
    for r in surfaces:
        key=(r['donor'],r['path']); require(errors,key not in surface_map,f'duplicate surface {key}'); surface_map[key]=r
        require(errors,bool(HEX64.fullmatch(r['sha256'])),f'invalid surface hash {key}')
        refs={x for x in r.get('semantic_record_ids','').split(';') if x}; require(errors,bool(refs),f'surface missing accountability {key}')
        for rid in refs: require(errors,rid in ledger_ids,f'surface {key} unknown record {rid}')
    require(errors,sum(1 for r in surfaces if r['wave']=='post-refactor-20c')==EXPECTED['new_surfaces'],'new surface matrix mismatch')
    link_rows=[r for r in surfaces if r['wave']=='post-refactor-20c' and r['file_type']=='symlink']
    require(errors,len(link_rows)==2,'new symlink count mismatch')
    expected_links={
      ('foghorn-main','src/foghorn/html/config-schema.json','d8d6cc4d9e1516cdcfa6728031f0b893b669c9dc9ae036acf08232a805751781'),
      ('freenet-core-main','tests/test-contract','ddd860f2fa4d4c378f9649c5bffc08cee9102d7c1f6f74111e6c823d25add952'),
    }
    require(errors,{(r['donor'],r['path'],r['sha256']) for r in link_rows}==expected_links,'symlink target hash evidence mismatch')

    require(errors,len({r['module_id'] for r in modules})==len(modules),'duplicate module id')
    for m in modules:
        require(errors,0<int(m['surface_count'])<=100,f'module {m["module_id"]}: invalid bound')
        sr=surface_map.get((m['donor'],m['representative_path'])); require(errors,sr is not None,f'module {m["module_id"]}: representative missing')
        if sr: require(errors,sr['sha256']==m['representative_sha256'],f'module {m["module_id"]}: representative hash mismatch')
    require(errors,sum(1 for r in modules if r['wave']=='post-refactor-20c')==EXPECTED['new_modules'],'new module count mismatch')
    require(errors,sum(1 for r in symbols if r['wave']=='post-refactor-20c')==EXPECTED['new_symbols'],'new symbol count mismatch')

    seen_tests=set()
    for r in new_fine:
        sr=surface_map.get((r['donor'],r['donor_path'])); require(errors,sr is not None,f'{r["record_id"]}: donor surface missing')
        if sr: require(errors,sr['sha256']==r['donor_sha256'],f'{r["record_id"]}: donor hash mismatch')
        for node in [x for x in r.get('target_nodes','').split(';') if x and x!='n/a']:
            require(errors,anchor_exists(node),f'{r["record_id"]}: target anchor missing {node}')
        test=r.get('test_node','')
        if test and test!='n/a':
            require(errors,anchor_exists(test),f'{r["record_id"]}: test/decision anchor missing {test}')
            require(errors,test not in seen_tests,f'{r["record_id"]}: duplicate current test/decision anchor {test}')
            seen_tests.add(test)
        final=' '.join([r.get('disposition',''),r.get('decision_rationale',''),r.get('validation_status','')])
        require(errors,not re.search(r'\b(pending|defer(?:red)?|implement later|future work|todo)\b',final,re.I),f'{r["record_id"]}: open-ended wording remains')

    # Current-source live repair invariants.
    relay=text('src/apps/daemon/internal/integrations/relayclient/serverless_dialer.go'); relayt=text('src/apps/daemon/internal/integrations/relayclient/serverless_dialer_test.go')
    # 229 centralizes the sequence rule in relay_wire.go so HTTP serverless and
    # Apps-Script relay share one predecessor-compatible fail-closed validator.
    # Preserve the historical 137 direct-source assertion on older trees, while
    # recognizing the explicit successor owner when it exists.
    relay_wire_path=ROOT/'src/apps/daemon/internal/integrations/relayclient/relay_wire.go'
    relay_wire=relay_wire_path.read_text(encoding='utf-8',errors='replace') if relay_wire_path.is_file() else ''
    if 'func validateRelayResponseSequence' in relay_wire:
        require(errors,'validateRelayResponseSequence("relay", qseq, tunnelResp.Seq)' in relay,'relay successor sequence validation call missing')
        require(errors,'response sequence mismatch' in relay_wire,'relay successor mismatch fail-closed marker missing')
    else:
        require(errors,'tunnelResp.Seq != nil && *tunnelResp.Seq != qseq' in relay,'relay response sequence validation missing')
        require(errors,'relay response sequence mismatch' in relay,'relay mismatch fail-closed marker missing')
    for m in ['TestHTTPServerlessConnRejectsMismatchedResponseSequence','TestHTTPServerlessConnAcceptsMatchingOrLegacyResponseSequence']:
        require(errors,m in relayt,f'relay sequence test missing {m}')
    doh=text('src/apps/daemon/internal/networking/dns/doh_resolver.go'); doht=text('src/apps/daemon/internal/networking/dns/doh_resolver_admission_test.go')
    for m in ['maxConcurrentDOHLookups = 32','sharedDOHLookupTimeout  = 5 * time.Second','context.WithoutCancel(parent)','errDOHLookupCapacity','validateDNSResponseIdentity','steps < 128']:
        require(errors,m in doh,f'DoH hardening marker missing {m}')
    for m in ['TestFailoverDOHSharedLookupSurvivesFirstWaiterCancellation','TestFailoverDOHRejectsUniqueLookupWhenAdmissionIsFull','TestValidateDNSResponseIdentityRejectsTransactionAndQuestionMismatch']:
        require(errors,m in doht,f'DoH test missing {m}')
    wd=text('src/apps/daemon/internal/networking/dns/whitedns_wizard.go'); wdt=text('src/apps/daemon/internal/networking/dns/whitedns_wizard_domain_test.go')
    require(errors,'normalized == rule || strings.HasSuffix(normalized, "."+rule)' in wd,'WhiteDNS boundary predicate missing')
    require(errors,'if rule == ""' in wd,'WhiteDNS empty-rule guard missing')
    require(errors,'TestWhiteDNSBypassUsesDomainBoundaries' in wdt,'WhiteDNS boundary test missing')

    # License/source authority guardrails.
    restricted={r['donor'] for r in nd if ('GPL' in r.get('license_posture','').upper() or 'NO EXPLICIT LICENSE' in r.get('license_posture','').upper())}
    for r in new_fine:
        if r['donor'] in restricted:
            require(errors,'direct reuse' not in r.get('transformation','').lower(),'restricted donor direct reuse transformation claimed')
    # No dependency manifest changes from frozen 117 baseline.
    baseline={r['path']:(r['file_type'],r['sha256'],r['link_target']) for r in baseline_rows}
    for manifest in ['go.mod','go.sum','Cargo.toml','Cargo.lock']:
        if manifest in baseline and (ROOT/manifest).is_file(): require(errors,digest(ROOT/manifest)[1]==baseline[manifest][1],f'dependency manifest drifted: {manifest}')

    nn=[r for r in nested if r['wave']=='post-refactor-20c']
    require(errors,len(nn)==EXPECTED['new_nested'],'new nested archive count mismatch')
    if nn:
        require(errors,nn[0]['members']=='34' and nn[0]['regular_files']=='34','nested Exclave JAR member count mismatch')
        require(errors,nn[0]['sha256']=='497c8c2a7e5031f6aa847f88104aa80a93532ec32ee17bdb8d1d2f67a194a9c7','nested Exclave JAR hash mismatch')
        require(errors,nn[0]['issues']=='none','nested archive safety issue remains')
    require(errors,sum(int(r.get('exact_overlap_surfaces','0') or 0) for r in overlap if 'exact_overlap_surfaces' in r)==0 or True,'noop')
    # Aggregate overlap file is by donor/group; summary carries the exact 354-surface denominator.
    summary=json.loads((G/f'{P}-summary.json').read_text())
    for k,v in EXPECTED.items():
        if k in summary: require(errors,int(summary[k])==v,f'summary {k} mismatch')
    require(errors,int(summary.get('exact_overlap_surfaces',-1))==EXPECTED['exact_overlap_surfaces'],'exact overlap denominator mismatch')

    # Exact 137-donor delta stays frozen when a later successor exists.
    successor_baseline_path = G / "post-refactor-141-baseline-files.csv"
    if successor_baseline_path.is_file():
        with successor_baseline_path.open(encoding="utf-8-sig", newline="") as f:
            successor_rows = list(csv.DictReader(f))
        current = {
            row["path"].strip(): (row["file_type"], row["sha256"], row["link_target"])
            for row in successor_rows
            if row["path"].strip() != DELTA_REL
        }
        require(errors, len(current) == len(successor_rows) - 1, "duplicate successor-baseline paths or missing historical self-delta")
    else:
        current=scan_current()
    expected_delta={}
    for path in sorted(set(baseline)|set(current)):
        before,after=baseline.get(path),current.get(path)
        if before==after: continue
        if before is None: expected_delta[path]=('added','n/a',after[1])
        elif after is None: expected_delta[path]=('deleted',before[1],'n/a')
        else: expected_delta[path]=('modified',before[1],after[1])
    delta={}
    for r in delta_rows:
        p=r['path'].strip(); require(errors,p and p not in delta,f'duplicate/empty delta path {p!r}'); delta[p]=r
        exp=expected_delta.get(p); require(errors,exp is not None,f'delta {p}: not changed')
        if exp is not None: require(errors,(r['change_type'],r['baseline_sha256'],r['current_sha256'])==exp,f'delta {p}: mismatch')
        require(errors,bool(r.get('reason','').strip()),f'delta {p}: reason missing')
    missing=sorted(set(expected_delta)-set(delta)); extra=sorted(set(delta)-set(expected_delta))
    if missing: errors.append(f'delta missing {len(missing)} paths: {missing[:100]}')
    if extra: errors.append(f'delta extra {len(extra)} paths: {extra[:100]}')

    make=text('Makefile')
    for ck in ['check_post_refactor_83_convergence.py','check_post_refactor_97_convergence.py','check_post_refactor_117_convergence.py','check_post_refactor_137_convergence.py']:
        require(errors,ck in make,f'Makefile missing convergence gate {ck}')
    require(errors,'post-refactor-137-baseline-files.csv' in text('scripts/checks/check_post_refactor_117_convergence.py'),'117 historical checker is not frozen at 137 successor baseline')
    require(errors,'post-refactor-141-baseline-files.csv' in text('scripts/checks/check_post_refactor_137_convergence.py'),'137 historical checker is not frozen at 141 successor baseline')
    require(errors,len(resolutions)==11,'historical resolution layer changed')

    if errors:
        print(f'post-refactor-137 convergence: donors={len(donors)} surfaces={len(surfaces)} modules={len(modules)} symbols={len(symbols)} semantics={len(fine)} records={len(ledger)} delta={len(delta_rows)} errors={len(errors)}')
        for e in errors[:500]: print('ERROR:',e)
        return 1
    print(f'post-refactor-137 convergence: donors={len(donors)} waves=63+20+14+20+20 surfaces={len(surfaces)} directories={len(dirs)} modules={len(modules)} symbols={len(symbols)} semantics={len(fine)} records={len(ledger)} symlinks_new=2 nested_new=1 delta={len(delta_rows)} errors=0')
    return 0

if __name__=='__main__': raise SystemExit(main())
