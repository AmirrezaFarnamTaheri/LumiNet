#!/usr/bin/env python3
from __future__ import annotations
import csv, hashlib, json, os, re, sys
from collections import Counter
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
G=ROOT/'governance'/'convergence'
P='post-refactor-117'
BASELINE_REL=f'governance/convergence/{P}-baseline-files.csv'
DELTA_REL=f'governance/convergence/{P}-target-delta.csv'
EXPECTED={
 'donors':117,'surfaces':27333,'directories':5481,'modules':3876,'symbols':73012,'ledger':4091,'semantics':215,'licenses':117,'nested':12,
 'historical_resolutions':11,'repairs':8,'planes':15,'baseline_files':2652,'new_donors':20,'new_members':8097,'new_surfaces':6748,'new_directories':1349,
 'new_modules':1175,'new_symbols':33593,'new_symlinks':6,'new_semantics':60,'new_nested':1,'new_nested_members':33,'overlap':3,
 'strict_ledger':4091,'historical_schema_normalizations':74,
}
NEW_DONORS={
 'serenity-dev','shadow-main','shadowsocks-libev-master','simple-obfs-android-master','sing-box-dashboard-main','sing-box-dev-next','sing-box-extended-extended',
 'sing-box-for-android-dev','sing-cloudflared-main','tun2proxy-master','tun2socks-main','tun2socks-python-main','uquic-master','vanguards-master','water-master','water-rs-main',
 'website-master','websocket-main','wgsocks-main','wsnet-master',
}
HEX64=re.compile(r'^[0-9a-f]{64}$')
VALID_DISPOSITIONS={'adopted','adapted','hardened','extracted','recomposed','synthesized','inspired-native','guardrail-derived','superseded','rejected-with-reason','reference-only'}
FINAL_STATUS={'verified','statically-validated','reviewed'}
# These markers make non-executable semantic decisions independently addressable without pretending they are runtime tests.
SEMANTIC_DECISION_ANCHORS={
    "semantic-PR117-S001",
    "semantic-PR117-S002",
    "semantic-PR117-S003",
    "semantic-PR117-S004",
    "semantic-PR117-S005",
    "semantic-PR117-S006",
    "semantic-PR117-S007",
    "semantic-PR117-S008",
    "semantic-PR117-S009",
    "semantic-PR117-S010",
    "semantic-PR117-S011",
    "semantic-PR117-S012",
    "semantic-PR117-S013",
    "semantic-PR117-S014",
    "semantic-PR117-S015",
    "semantic-PR117-S016",
    "semantic-PR117-S017",
    "semantic-PR117-S018",
    "semantic-PR117-S019",
    "semantic-PR117-S020",
    "semantic-PR117-S021",
    "semantic-PR117-S022",
    "semantic-PR117-S023",
    "semantic-PR117-S024",
    "semantic-PR117-S025",
    "semantic-PR117-S026",
    "semantic-PR117-S027",
    "semantic-PR117-S028",
    "semantic-PR117-S029",
    "semantic-PR117-S030",
    "semantic-PR117-S031",
    "semantic-PR117-S032",
    "semantic-PR117-S033",
    "semantic-PR117-S034",
    "semantic-PR117-S035",
    "semantic-PR117-S036",
    "semantic-PR117-S037",
    "semantic-PR117-S038",
    "semantic-PR117-S039",
    "semantic-PR117-S040",
    "semantic-PR117-S041",
    "semantic-PR117-S042",
    "semantic-PR117-S043",
    "semantic-PR117-S044",
    "semantic-PR117-S045",
    "semantic-PR117-S046",
    "semantic-PR117-S047",
    "semantic-PR117-S048",
    "semantic-PR117-S049",
    "semantic-PR117-S050",
    "semantic-PR117-S051",
    "semantic-PR117-S052",
    "semantic-PR117-S053",
    "semantic-PR117-S054",
    "semantic-PR117-S055",
    "semantic-PR117-S056",
    "semantic-PR117-S057",
    "semantic-PR117-S058",
    "semantic-PR117-S059",
    "semantic-PR117-S060",
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
    candidates={anchor,anchor.split('.')[-1],anchor.replace('-','_'),anchor.replace('-',' ')}
    return any(c and re.search(r'(?<![A-Za-z0-9_])'+re.escape(c)+r'(?![A-Za-z0-9_])',raw,re.I) for c in candidates)

def main():
    errors=[]
    try:
        donors=read_csv(f'{P}-donors.csv'); surfaces=read_csv(f'{P}-surfaces.csv'); dirs=read_csv(f'{P}-directories.csv'); modules=read_csv(f'{P}-modules.csv'); symbols=read_csv(f'{P}-symbols.csv')
        ledger=read_csv(f'{P}-adoption-ledger.csv'); licenses=read_csv(f'{P}-license-map.csv'); nested=read_csv(f'{P}-nested-archives.csv'); resolutions=read_csv(f'{P}-historical-resolutions.csv')
        repairs=read_csv(f'{P}-target-repairs.csv'); planes=read_csv(f'{P}-high-level-plane-audit.csv'); baseline_rows=read_csv(f'{P}-baseline-files.csv'); delta_rows=read_csv(f'{P}-target-delta.csv')
        overlap=read_csv(f'{P}-overlap-provenance.csv'); new_donors=read_csv(f'{P}-new-donors.csv'); new_surfaces=read_csv(f'{P}-new-surfaces.csv'); new_modules=read_csv(f'{P}-new-modules.csv')
        strict_ledger=read_csv(f'{P}-strict-adoption-ledger.csv'); historical_normalizations=read_csv(f'{P}-historical-schema-normalizations.csv')
    except Exception as exc:
        print('post-refactor-117 convergence:',exc); return 1
    counts={'donors':len(donors),'surfaces':len(surfaces),'directories':len(dirs),'modules':len(modules),'symbols':len(symbols),'ledger':len(ledger),'licenses':len(licenses),'nested':len(nested),'historical_resolutions':len(resolutions),'repairs':len(repairs),'planes':len(planes),'baseline_files':len(baseline_rows),'new_donors':len(new_donors),'new_surfaces':len(new_surfaces),'new_modules':len(new_modules),'overlap':len(overlap),'strict_ledger':len(strict_ledger),'historical_schema_normalizations':len(historical_normalizations)}
    for k,v in counts.items(): require(errors,v==EXPECTED[k],f'{k} count {v} != {EXPECTED[k]}')

    waves=Counter(r['wave'] for r in donors)
    require(errors,waves==Counter({'ultimate-63':63,'post-refactor-20':20,'tor-wave-14':14,'post-refactor-20b':20}),f'donor wave mismatch {dict(waves)}')
    names=[r['donor'] for r in donors]; require(errors,len(set(names))==117,'duplicate donor identity in combined inventory')
    actual_new={r['donor'] for r in donors if r['wave']=='post-refactor-20b'}
    require(errors,actual_new==NEW_DONORS,f'new donor set mismatch missing={sorted(NEW_DONORS-actual_new)} extra={sorted(actual_new-NEW_DONORS)}')
    nd=[r for r in donors if r['wave']=='post-refactor-20b']
    require(errors,sum(int(r['member_count']) for r in nd)==EXPECTED['new_members'],'new member denominator mismatch')
    require(errors,sum(int(r['file_surfaces']) for r in nd)==EXPECTED['new_surfaces'],'new surface rollup mismatch')
    require(errors,sum(int(r['directories']) for r in nd)==EXPECTED['new_directories'],'new directory rollup mismatch')
    require(errors,sum(int(r['symbols']) for r in nd)==EXPECTED['new_symbols'],'new symbol rollup mismatch')
    require(errors,sum(int(r['symlinks']) for r in nd)==EXPECTED['new_symlinks'],'new symlink rollup mismatch')
    require(errors,sum(int(r.get('nested_members','0') or 0) for r in nd)==EXPECTED['new_nested_members'],'new nested-member rollup mismatch')
    require(errors,all((r.get('archive_issues') or '').lower().startswith('none') for r in nd),'new archive safety issue remains')

    ledger_ids={r['record_id'] for r in ledger}; module_ids={r['module_id'] for r in modules}
    require(errors,len(ledger_ids)==len(ledger),'duplicate adoption/accountability record IDs')
    require(errors,len(module_ids)==len(modules),'duplicate module IDs')
    require(errors,module_ids<=ledger_ids,'module record missing from ledger')
    fine=[r for r in ledger if r['record_id'] not in module_ids]
    require(errors,len(fine)==EXPECTED['semantics'],f'fine semantic count {len(fine)} != {EXPECTED["semantics"]}')
    new_fine=[r for r in fine if r['record_id'].startswith('PR117-S')]
    require(errors,len(new_fine)==EXPECTED['new_semantics'],f'new semantic count {len(new_fine)} != {EXPECTED["new_semantics"]}')
    require(errors,{r['validation_status'] for r in ledger}<=FINAL_STATUS,'non-final validation status remains')
    require(errors,all(r['disposition'] in VALID_DISPOSITIONS for r in ledger),'invalid disposition exists')

    # Historical schema debt is normalized in a successor overlay, never by mutating frozen 97 evidence.
    strict_by_id={r['record_id']:r for r in strict_ledger}
    require(errors,len(strict_by_id)==EXPECTED['strict_ledger'],'strict ledger duplicate/missing record IDs')
    require(errors,set(strict_by_id)==ledger_ids,'strict ledger record identity differs from canonical ledger')
    norm_by_id={r['record_id']:r for r in historical_normalizations}
    require(errors,len(norm_by_id)==EXPECTED['historical_schema_normalizations'],'historical normalization IDs are not unique')
    require(errors,set(norm_by_id)<=ledger_ids,'historical normalization references unknown record')
    require(errors,all(not rid.startswith('PR117-S') for rid in norm_by_id),'current-wave row was incorrectly treated as historical schema debt')
    require(errors,(G/f'{P}-historical-evidence-anchors.md').is_file(),'historical evidence anchor file missing')
    for rid,norm in norm_by_id.items():
        strict=strict_by_id.get(rid,{})
        require(errors,strict.get('target_nodes')==norm.get('normalized_target_nodes'),f'{rid}: strict target_nodes does not match normalization overlay')
        require(errors,strict.get('test_node')==norm.get('normalized_test_node'),f'{rid}: strict test_node does not match normalization overlay')

    surface_map={}
    for r in surfaces:
        key=(r['donor'],r['path']); require(errors,key not in surface_map,f'duplicate surface {key}'); surface_map[key]=r
        require(errors,bool(HEX64.fullmatch(r.get('sha256',''))),f'surface invalid hash {key}')
        refs=[x for x in r.get('semantic_record_ids','').split(';') if x]; require(errors,bool(refs),f'surface has no accountability {key}')
        for rid in refs: require(errors,rid in ledger_ids,f'surface {key}: unknown record {rid}')
    require(errors,sum(1 for r in surfaces if r['wave']=='post-refactor-20b')==EXPECTED['new_surfaces'],'new combined surface count mismatch')
    require(errors,sum(1 for r in surfaces if r['wave']=='post-refactor-20b' and r['file_type']=='symlink')==EXPECTED['new_symlinks'],'new symlink matrix count mismatch')

    for m in modules:
        require(errors,0<int(m['surface_count'])<=100,f'module {m["module_id"]}: invalid bound')
        sr=surface_map.get((m['donor'],m['representative_path'])); require(errors,sr is not None,f'module {m["module_id"]}: representative missing')
        if sr: require(errors,sr['sha256']==m['representative_sha256'],f'module {m["module_id"]}: representative hash mismatch')
    require(errors,sum(1 for r in modules if r['wave']=='post-refactor-20b')==EXPECTED['new_modules'],'new module denominator mismatch')
    require(errors,sum(1 for r in symbols if r['wave']=='post-refactor-20b')==EXPECTED['new_symbols'],'new symbol denominator mismatch')

    # New fine decisions must point to exact donor surface bytes and live/addressable target evidence.
    seen_tests=set()
    for r in new_fine:
        sr=surface_map.get((r['donor'],r['donor_path'])); require(errors,sr is not None,f'{r["record_id"]}: donor surface missing')
        if sr: require(errors,sr['sha256']==r['donor_sha256'],f'{r["record_id"]}: donor hash mismatch')
        for node in [x for x in r.get('target_nodes','').split(';') if x and x!='n/a']:
            require(errors,anchor_exists(node),f'{r["record_id"]}: target anchor missing {node}')
        test=r.get('test_node','')
        if test and test!='n/a':
            require(errors,anchor_exists(test),f'{r["record_id"]}: test/decision anchor missing {test}')
            require(errors,test not in seen_tests,f'{r["record_id"]}: duplicate fine test/decision anchor {test}')
            seen_tests.add(test)
        final=' '.join([r.get('disposition',''),r.get('decision_rationale',''),r.get('validation_status','')])
        require(errors,not re.search(r'\b(pending|defer(?:red)?|implement later|future work|todo)\b',final,re.I),f'{r["record_id"]}: open-ended wording remains')
    require(errors,{r['donor'] for r in new_fine}==NEW_DONORS,'not every new donor has fine semantic disposition')

    # License/source reuse vetoes.
    gpl={r['donor'] for r in nd if 'GPL' in r.get('license_posture','').upper()}
    for r in new_fine:
        if r['donor'] in gpl:
            require(errors,'direct reuse' not in r['transformation'].lower() and 'direct reuse' not in r['decision_rationale'].lower(),f'{r["record_id"]}: GPL direct source reuse claimed')
    # No dependency manifests changed from 97 baseline as a side effect of donor convergence.
    baseline={r['path']:(r['file_type'],r['sha256'],r['link_target']) for r in baseline_rows}
    for manifest in ['go.mod','go.sum','Cargo.toml','Cargo.lock']:
        if manifest in baseline and (ROOT/manifest).is_file():
            require(errors,digest(ROOT/manifest)[1]==baseline[manifest][1],f'dependency manifest drifted: {manifest}')

    # Duplicate/shared-base evidence is explicit and semantically de-duplicated.
    ov={r['relationship_id']:r for r in overlap}
    require(errors,'115 embedded tun2socks-go files' in ov.get('PR117-DUP-001',{}).get('evidence',''),'tun2socks embedded-copy count missing')
    require(errors,'635 identical' in ov.get('PR117-DUP-002',{}).get('evidence',''),'sing-box shared-base overlap evidence missing')
    require(errors,'github.com/metacubex/websocket' in ov.get('PR117-PROV-003',{}).get('evidence',''),'websocket fork provenance missing')
    dup=next((r for r in new_fine if r['donor']=='tun2socks-python-main' and r['donor_path']=='tun2socks-go/transport/socks5/socks5.go'),None)
    require(errors,dup is not None and dup['disposition']=='superseded','embedded tun2socks semantic duplicate not superseded')
    if dup:
        standalone=surface_map.get(('tun2socks-main','transport/socks5/socks5.go'))
        require(errors,standalone is not None and standalone['sha256']==dup['donor_sha256']=='15828ef8f3fa840ba87f1badcfa2b80733921717a8fec4ea1f14647f0e31f190','embedded/standalone tun2socks exact hash proof failed')

    # Nested archive closure.
    nn=[r for r in nested if r['wave']=='post-refactor-20b']
    require(errors,len(nn)==1 and nn[0]['members']=='33','new nested Gradle JAR count mismatch')
    if nn:
        require(errors,nn[0]['sha256']=='d3b261c2820e9e3d8d639ed084900f11f4a86050a8f83342ade7b6bc9b0d2bdd','nested Gradle JAR hash mismatch')
        require(errors,nn[0]['issues']=='none','nested archive safety issue remains')

    # Live TUN/SOCKS invariants and explicit IPv4 NAT truth.
    tun=text('src/apps/daemon/internal/platform/mobilehost/tun2socks_adapter.go'); tunt=text('src/apps/daemon/internal/platform/mobilehost/tun2socks_test.go'); nat=text('src/apps/daemon/internal/platform/system/nat/nat.go')
    for marker in ['socksAssociationHandshakeTimeout','DialContext(a.ctx','SetDeadline(socksHandshakeDeadline(a.ctx))','writeFull','readSocks5UDPRelay','case 0x04','installUDPAssoc','newAssoc.close()']:
        require(errors,marker in tun,f'TUN/SOCKS repair marker missing: {marker}')
    for marker in ['TestReadSocks5UDPRelayIPv6','TestInstallUDPAssocHasSingleWinner','TestWriteFullHandlesShortWrites','TestCreateUDPAssocHonorsContextDeadline']:
        require(errors,marker in tunt,f'TUN/SOCKS regression test missing: {marker}')
    require(errors,'only ipv4 supported' in nat.lower(),'authoritative IPv4-only NAT truth changed; capability claims must be revisited')

    # Live WebSocket/VLESS invariants.
    helper=text('src/apps/daemon/internal/runtime/proxy/websocket_conn_helpers.go'); vless=text('src/apps/daemon/internal/runtime/proxy/vless_dialer.go'); edge=text('src/apps/daemon/internal/runtime/proxy/edge_dialer.go'); pt=text('src/apps/daemon/internal/runtime/proxy/websocket_conn_helpers_test.go')
    relay=text('src/apps/daemon/internal/integrations/relayclient/websocket_conn.go'); relayt=text('src/apps/daemon/internal/integrations/relayclient/websocket_conn_test.go'); sd=text('src/apps/daemon/internal/integrations/relayclient/serverless_dialer.go'); wst=text('src/apps/daemon/internal/runtime/proxy/wstunnel.go')
    for marker in ['proxyWebSocketReadLimit int64 = 1 << 20','SetReadLimit','NetConn().LocalAddr','NetConn().RemoteAddr','SetReadDeadline','SetWriteDeadline','type vlessWSResponseState']:
        require(errors,marker in helper,f'proxy WebSocket repair marker missing: {marker}')
    require(errors,'configureProxyWebSocket(wsConn)' in vless and 'configureProxyWebSocket(wsConn)' in edge,'proxy WebSocket read-limit configuration missing')
    require(errors,'return c.Read(b)' not in vless,'recursive VLESS WebSocket read returned')
    for marker in ['TestVLESSWSResponseStateHeaderIsConsumedExactlyOnce','TestVLESSWSResponseStateAcceptsSplitHeaderWithoutRecursion','TestVLESSWSResponseStateRejectsWrongVersion']:
        require(errors,marker in pt,f'VLESS state test missing: {marker}')
    for marker in ['SetReadLimit(relayWebSocketReadLimit)','NetConn().LocalAddr','NetConn().RemoteAddr','SetReadDeadline','SetWriteDeadline']:
        require(errors,marker in relay,f'relay WebSocket marker missing: {marker}')
    for marker in ['TestWebSocketConnNetConnContract','TestWebSocketConnEnforcesReadLimit']:
        require(errors,marker in relayt,f'relay WebSocket test missing: {marker}')
    require(errors,'SetReadDeadline' in sd and '5 * time.Second' in sd,'relay confirmation deadline missing')
    require(errors,'relayclient.NewWebSocketConn(wsConn)' in wst,'wstunnel does not use canonical relay WebSocket wrapper')

    # Exact 117-donor delta from the frozen 97 source baseline. When a later successor exists,
    # freeze this historical checker at the exact 137 baseline rather than widening old evidence.
    successor_baseline_path = G / "post-refactor-137-baseline-files.csv"
    if successor_baseline_path.is_file():
        with successor_baseline_path.open(encoding="utf-8-sig", newline="") as f:
            successor_baseline_rows = list(csv.DictReader(f))
        current = {
            row["path"].strip(): (row["file_type"], row["sha256"], row["link_target"])
            for row in successor_baseline_rows
            if row["path"].strip() != DELTA_REL
        }
        require(errors, len(current) == len(successor_baseline_rows) - 1, "duplicate successor-baseline paths or missing historical self-delta")
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
        exp=expected_delta.get(p)
        require(errors,exp is not None,f'delta {p}: not changed')
        if exp is not None:
            require(errors,(r['change_type'],r['baseline_sha256'],r['current_sha256'])==exp,f'delta {p}: mismatch')
        require(errors,bool(r.get('reason','').strip()),f'delta {p}: reason missing')
    missing=sorted(set(expected_delta)-set(delta)); extra=sorted(set(delta)-set(expected_delta))
    if missing: errors.append(f'delta missing {len(missing)} paths: {missing[:100]}')
    if extra: errors.append(f'delta extra {len(extra)} paths: {extra[:100]}')

    # Historical gates remain executable at their frozen successor boundaries.
    make=text('Makefile')
    for ck in ['check_post_refactor_83_convergence.py','check_post_refactor_97_convergence.py','check_post_refactor_117_convergence.py']:
        require(errors,ck in make,f'Makefile missing convergence gate {ck}')
    require(errors,'post-refactor-117-baseline-files.csv' in text('scripts/checks/check_post_refactor_97_convergence.py'),'97-donor historical gate not frozen at successor baseline')
    require(errors,'post-refactor-137-baseline-files.csv' in text('scripts/checks/check_post_refactor_117_convergence.py'),'117-donor historical gate not frozen at successor baseline')
    require(errors,len(resolutions)==11,'historical resolution layer count changed')

    # Summary cross-check.
    try:
        summary=json.loads((G/f'{P}-summary.json').read_text())
        mapping={'ledger_records':'ledger','semantic_records':'semantics','nested_archives':'nested','new_semantic_records':'new_semantics','new_nested_archives':'new_nested'}
        for key,val in summary.items():
            ek=mapping.get(key,key)
            if ek in EXPECTED: require(errors,int(val)==EXPECTED[ek],f'summary {key} mismatch')
    except Exception as exc: errors.append(f'invalid summary: {exc}')

    if errors:
        print(f'post-refactor-117 convergence: donors={len(donors)} surfaces={len(surfaces)} modules={len(modules)} symbols={len(symbols)} semantics={len(fine)} records={len(ledger)} delta={len(delta_rows)} errors={len(errors)}')
        for e in errors[:500]: print('ERROR:',e)
        return 1
    print(f'post-refactor-117 convergence: donors={len(donors)} waves=63+20+14+20 surfaces={len(surfaces)} directories={len(dirs)} modules={len(modules)} symbols={len(symbols)} semantics={len(fine)} records={len(ledger)} symlinks_new={EXPECTED["new_symlinks"]} nested_new={EXPECTED["new_nested"]} delta={len(delta_rows)} errors=0')
    return 0

if __name__=='__main__': sys.exit(main())
