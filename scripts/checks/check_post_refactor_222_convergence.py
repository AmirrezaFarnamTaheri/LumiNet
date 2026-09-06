#!/usr/bin/env python3
from __future__ import annotations

import csv
import hashlib
import json
import os
import re
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
G = ROOT / 'governance' / 'convergence'
P = 'post-refactor-222'
DELTA_REL = f'governance/convergence/{P}-target-delta.csv'
SUCCESSOR_BASELINE = G / 'post-refactor-223-baseline-files.csv'
HEX64 = re.compile(r'^[0-9a-f]{64}$')

EXPECTED = {
    'unique_donors': 23,
    'surfaces': 6253,
    'symbols': 13006,
    'symlinks': 20,
    'ledger': 81,
    'baseline_files': 2857,
    'uploaded_archives': 28,
    'uploaded_donor_archive_files': 25,
}
FINAL_STATUS = {'verified', 'statically-validated', 'reviewed'}
VALID_DISPOSITIONS = {
    'adopted','adapted','hardened','extracted','recomposed','synthesized',
    'inspired-native','guardrail-derived','superseded','rejected-with-reason','reference-only',
}
IMPLEMENTED = {'adopted','adapted','hardened','extracted','recomposed','synthesized','inspired-native','guardrail-derived'}


def rows(name: str) -> list[dict[str,str]]:
    path=G/name
    if not path.is_file():
        raise AssertionError(f'missing {path.relative_to(ROOT)}')
    with path.open(encoding='utf-8-sig',newline='') as f:
        return list(csv.DictReader(f))


def text(rel: str) -> str:
    return (ROOT/rel).read_text(encoding='utf-8',errors='replace')


def digest(path: Path) -> tuple[str,str,str]:
    if path.is_symlink():
        target=os.readlink(path)
        return 'symlink',hashlib.sha256(target.encode()).hexdigest(),target
    return 'file',hashlib.sha256(path.read_bytes()).hexdigest(),'n/a'


def scan_current() -> dict[str,tuple[str,str,str]]:
    # Historical post-222 evidence is immutable. Once post-223 exists, compare
    # this wave against the successor's frozen pre-change snapshot rather than
    # today's descendant source tree.
    if SUCCESSOR_BASELINE.is_file():
        current={}
        with SUCCESSOR_BASELINE.open(encoding='utf-8',newline='') as f:
            for row in csv.DictReader(f):
                rel=row['path'].strip()
                if rel==DELTA_REL: continue
                current[rel]=(row['file_type'].strip(),row['sha256'].strip(),row.get('link_target','n/a') or 'n/a')
        return current
    current={}
    for path in sorted(ROOT.rglob('*')):
        if not (path.is_file() or path.is_symlink()): continue
        rel=path.relative_to(ROOT).as_posix()
        if rel==DELTA_REL: continue
        if rel.startswith('.git/') or '/__pycache__/' in '/'+rel or rel.endswith('.pyc'): continue
        if '/node_modules/' in '/'+rel or '/.gradle/' in '/'+rel: continue
        current[rel]=digest(path)
    return current


def anchor_exists(node: str) -> bool:
    node=(node or '').strip()
    if not node or node=='n/a': return True
    if '#' not in node: return (ROOT/node).exists()
    rel,anchor=node.split('#',1)
    path=ROOT/rel
    return path.is_file() and anchor in path.read_text(encoding='utf-8',errors='replace')


def require(errors:list[str], condition:bool, message:str)->None:
    if not condition: errors.append(message)


def main()->int:
    errors=[]
    try:
        ledger=rows(f'{P}-adoption-ledger.csv')
        surfaces=rows(f'{P}-surface-accountability.csv')
        symbols=rows(f'{P}-symbols.csv')
        baseline_rows=rows(f'{P}-baseline-files.csv')
        delta_rows=rows(f'{P}-target-delta.csv')
        accountability=rows(f'{P}-cross-wave-accountability.csv')
        archives=rows(f'{P}-archive-accountability.csv')
        summary=json.loads((G/f'{P}-summary.json').read_text())
    except Exception as exc:
        print(f'{P} convergence: load failure: {exc}')
        return 1

    ids={r['record_id'] for r in ledger}
    require(errors,len(ledger)==EXPECTED['ledger'],f"ledger {len(ledger)} != {EXPECTED['ledger']}")
    require(errors,len(ids)==len(ledger),'duplicate ledger record ID')
    require(errors,ids=={f'PR222-S{i:03d}' for i in range(1,EXPECTED['ledger']+1)},'ledger identity sequence drift')
    test_nodes=[r['test_node'] for r in ledger if r['test_node']!='n/a']
    require(errors,len(test_nodes)==len(set(test_nodes)),'non-n/a ledger test_node values must be unique')

    for r in ledger:
        rid=r['record_id']
        require(errors,r['disposition'] in VALID_DISPOSITIONS,f'{rid}: invalid disposition {r["disposition"]}')
        require(errors,r['validation_status'] in FINAL_STATUS,f'{rid}: non-final status {r["validation_status"]}')
        require(errors,r['risk_tier'] in {'critical','high','medium','low'},f'{rid}: invalid risk')
        require(errors,HEX64.fullmatch(r['donor_sha256']) is not None,f'{rid}: invalid evidence hash')
        require(errors,bool(r['decision_rationale'].strip()),f'{rid}: missing rationale')
        require(errors,bool(r['invariant'].strip()) and bool(r['negative_invariant'].strip()),f'{rid}: missing invariants')
        if r['disposition'] in IMPLEMENTED:
            require(errors,r['target_nodes']!='n/a',f'{rid}: implemented record missing target owner')
            require(errors,r['test_node']!='n/a',f'{rid}: implemented record missing acceptance evidence')
        if r['risk_tier'] in {'critical','high'} and r['disposition']=='rejected-with-reason':
            require(errors,r['test_node']!='n/a',f'{rid}: high-risk rejection missing guardrail evidence')
        for node in r['target_nodes'].split(';'):
            require(errors,anchor_exists(node),f'{rid}: unresolved target node {node}')
        for node in r['test_node'].split(';'):
            require(errors,anchor_exists(node),f'{rid}: unresolved test node {node}')

    require(errors,len(surfaces)==EXPECTED['surfaces'],f"surface count {len(surfaces)} != {EXPECTED['surfaces']}")
    require(errors,sum(r['file_type']=='symlink' for r in surfaces)==EXPECTED['symlinks'],'symlink denominator drift')
    surface_by_key={}
    record_surface_refs=Counter()
    for r in surfaces:
        key=(r['donor'],r['path'])
        require(errors,key not in surface_by_key,f'duplicate surface {key}')
        surface_by_key[key]=r
        require(errors,HEX64.fullmatch(r['sha256']) is not None,f'{key}: invalid surface hash')
        linked=[x for x in r['semantic_record_ids'].split(';') if x]
        require(errors,bool(linked),f'{key}: unlinked surface')
        for rid in linked:
            require(errors,rid in ids,f'{key}: unknown semantic record {rid}')
            record_surface_refs[rid]+=1
        if r['classification'] in {'implementation','configuration','script','deployment','ui-or-product'}:
            require(errors,bool(linked),f'{key}: strict authoritative/product surface lacks disposition')

    require(errors,len(symbols)==EXPECTED['symbols'],f"symbol count {len(symbols)} != {EXPECTED['symbols']}")
    for r in symbols:
        key=(r['donor'],r['path'])
        source=surface_by_key.get(key)
        require(errors,source is not None,f'symbol source missing {key}')
        if source:
            require(errors,source['sha256']==r['sha256'],f'symbol hash mismatch {key}:{r["symbol"]}')
            require(errors,r['semantic_record_ids']==source['semantic_record_ids'],f'symbol semantic links drift {key}:{r["symbol"]}')

    # Donor evidence hashes and bidirectional links.
    baseline={r['path']:(r['file_type'],r['sha256'],r.get('link_target','n/a') or 'n/a') for r in baseline_rows}
    require(errors,len(baseline)==EXPECTED['baseline_files'],'post-222 baseline denominator drift')
    require(errors,len(baseline)==len(baseline_rows),'duplicate post-222 baseline path')
    for r in ledger:
        rid=r['record_id']
        if r['donor']=='LumiNet/baseline-221':
            source=baseline.get(r['donor_path'])
            require(errors,source is not None,f'{rid}: predecessor target evidence missing')
            if source: require(errors,source[1]==r['donor_sha256'],f'{rid}: predecessor target hash mismatch')
        elif r['donor']=='LumiNet/current':
            if SUCCESSOR_BASELINE.is_file():
                successor=scan_current().get(r['donor_path'])
                require(errors,successor is not None,f'{rid}: successor-baseline target evidence missing')
                if successor: require(errors,successor[1]==r['donor_sha256'],f'{rid}: successor-baseline target evidence hash mismatch')
            else:
                p=ROOT/r['donor_path']
                require(errors,p.is_file(),f'{rid}: current target evidence missing')
                if p.is_file(): require(errors,hashlib.sha256(p.read_bytes()).hexdigest()==r['donor_sha256'],f'{rid}: current target evidence hash mismatch')
        else:
            source=surface_by_key.get((r['donor'],r['donor_path']))
            require(errors,source is not None,f'{rid}: donor evidence surface missing {r["donor"]}:{r["donor_path"]}')
            if source:
                require(errors,source['sha256']==r['donor_sha256'],f'{rid}: donor evidence hash mismatch')
                require(errors,rid in source['semantic_record_ids'].split(';'),f'{rid}: evidence surface does not backlink record')
    for r in ledger:
        if r['donor'] not in {'LumiNet/baseline-221','LumiNet/current'}:
            require(errors,record_surface_refs[r['record_id']]>0,f'{r["record_id"]}: no donor surface links back to record')

    donor_rows=[r for r in accountability if r['role']=='donor']
    target_rows=[r for r in accountability if r['role']=='target']
    require(errors,len(donor_rows)==EXPECTED['unique_donors'],f'donor accountability {len(donor_rows)} != 23')
    require(errors,len(target_rows)==1 and target_rows[0]['project']=='LumiNet','exactly one target accountability row required')
    require(errors,sum(int(r['surface_count']) for r in donor_rows)==EXPECTED['surfaces'],'donor accountability surface rollup drift')
    require(errors,sum(int(r['reopened_surfaces']) for r in donor_rows)==summary['reopened_surfaces'],'reopened surface rollup drift')
    require(errors,sum(int(r['exact_historical_matches']) for r in donor_rows)==summary['historically_exact_surfaces'],'historical exact-match rollup drift')

    require(errors,len(archives)==EXPECTED['uploaded_archives'],f'archive accountability {len(archives)} != 28')
    donor_archive_rows=[r for r in archives if r['role']=='donor']
    require(errors,len(donor_archive_rows)==EXPECTED['uploaded_donor_archive_files'],'uploaded donor archive-file count drift')
    unique_donor_hashes={r['sha256'] for r in donor_archive_rows}
    require(errors,len(unique_donor_hashes)==EXPECTED['unique_donors'],'unique donor archive hash count drift')
    duplicate_rows=[r for r in donor_archive_rows if r['duplicate_of']!='n/a']
    require(errors,len(duplicate_rows)==2,'expected exactly two duplicate donor uploads (Kloak and stealthspanner)')
    require(errors,{r['archive'] for r in duplicate_rows}=={'Kloak_platform-master.zip','stealthspanner-master.zip'},'duplicate donor alias set drift')

    require(errors,int(summary['unique_current_donors'])==EXPECTED['unique_donors'],'summary donor count drift')
    require(errors,int(summary['current_donor_surfaces'])==EXPECTED['surfaces'],'summary surface count drift')
    require(errors,int(summary['current_donor_symbols'])==EXPECTED['symbols'],'summary symbol count drift')
    require(errors,int(summary['semantic_records'])==EXPECTED['ledger'],'summary ledger count drift')
    require(errors,int(summary['baseline_files'])==EXPECTED['baseline_files'],'summary baseline count drift')
    require(errors,summary['target_baseline_sha256']=='24db4253756f32c8a96cdb6783d498dd38bf076ac6bc5ff2a98536f152c96df2','baseline archive identity drift')

    # Core promoted behavior: peer identity/admission, local blocklist, NAT evidence, no active discovery authority.
    peer=text('src/apps/daemon/internal/analysis/peerdiscovery/planner.go')
    bep=text('src/apps/daemon/internal/analysis/peerdiscovery/bep42.go')
    require(errors,'MaxCandidates   = 1000' in peer and 'MaxResults      = 64' in peer and 'MaxBlockedCIDRs = 128' in peer,'peer planner bounds drift')
    require(errors,'netpolicy.IsPublicAddress' in peer and 'blocked-address' in peer and 'parseBlockedCIDRs' in peer,'peer public/local-deny admission missing')
    require(errors,'SharedAddressObserved' in peer and 'SharedAddressCount' in peer,'shared-address evidence missing')
    require(errors,'accepted[i].Distance < accepted[j].Distance' in peer and 'xorDistance' in peer,'exact XOR ordering missing')
    require(errors,'crc32.Castagnoli' in bep and '0x030f3fff' in bep,'BEP42 CRC32C/IP binding drift')
    require(errors,'no DNSBL lookups, sockets, peer dialing, persistence, route mutation, or trust-based identity bypass' in peer,'peer non-authority boundary drift')
    # PR222-GUARD-TORRENT-ACTIVE
    require(errors,all(token not in peer for token in ['bittorrent-dht','tracker.Client','net.Dial','http.Get','exec.Command']),'peer planner gained active peer discovery/probing authority')
    # PR222-GUARD-NO-TORRENT-RUNTIME
    peer_files={p.name for p in (ROOT/'src/apps/daemon/internal/analysis/peerdiscovery').iterdir() if p.is_file()}
    require(errors,peer_files <= {'.context','bep42.go','bep42_test.go','planner.go','planner_test.go'},f'unexpected peer content runtime surface: {sorted(peer_files)}')

    # Endpoint continuity/diversity evidence remains bounded and quality-preserving.
    endpoint=text('src/apps/daemon/internal/analysis/diagnostics/endpoint_pool_plan.go')
    require(errors,all(x in endpoint for x in ['JitterMs','PacketLossPct','PreviousSuccessful','stableScopeHash','endpointDiversityBand = 5.0']),'endpoint evidence/failover primitives missing')
    require(errors,'bestScore-previousScore > endpointDiversityBand' in endpoint,'last-known-good quality bound missing')
    # PR222-GUARD-NO-COUNTRY-TRUST
    require(errors,'Country' not in endpoint and 'country' not in endpoint,'endpoint ranker gained country-based trust scoring')

    # Product planes remain local/read-only and diagnostics stay structurally redacted.
    health=text('src/packages/control-ui/src/pages/Health.tsx')
    palette=text('src/packages/control-ui/src/CommandPalette.tsx')
    appearance=text('src/packages/control-ui/src/lib/appearance.ts')
    operations=text('src/packages/control-ui/src/pages/Operations.tsx')
    require(errors,"schema: 'luminet.redacted-diagnostics.v1'" in health and 'last_error_present: Boolean(network.lastError)' in health,'redacted diagnostic schema drift')
    require(errors,'message: check.message' not in health and 'last_error: network.lastError' not in health,'free-form diagnostic leakage returned')
    require(errors,"source_errors: snapshot.sourceErrors.map((item) => item.split(':', 1)[0])" in health,'source errors are no longer reduced to source identity')
    require(errors,'MAX_RECENTS = 5' in palette and 'role="dialog"' in palette and 'aria-modal="true"' in palette,'command palette bound/accessibility drift')
    require(errors,"value === 'system' || value === 'dark' || value === 'light'" in appearance,'appearance preference vocabulary drift')
    require(errors,'Local blocked IPv4 CIDRs' in operations and 'shared address ×' in operations,'peer deny/shared-address product evidence missing')
    # PR222-GUARD-CDIN-AUTHORITY
    require(errors,all(x not in palette for x in ['child_process','exec(','spawn(','readFile(','writeFile(']),'command palette gained shell/filesystem authority')
    # PR222-GUARD-NO-TIMER-AUTHORITY
    require(errors,'expires_soon' in text('src/packages/control-ui/src/pages/Profiles.tsx') and 'EvaluateProfileEntitlement' in text('src/apps/daemon/internal/integrations/sub/profile_entitlement.go'),'profile expiry lost authoritative target owner')

    # Subscription deep-link admission stays proposal-only and reuses canonical profile source policy.
    deeplink=text('src/apps/daemon/internal/integrations/sub/deeplink.go')
    subhandlers=text('src/apps/daemon/internal/adapters/api/handlers_subscription.go')
    subroutes=text('src/apps/daemon/internal/adapters/api/routes_misc.go')
    profiles=text('src/packages/control-ui/src/pages/Profiles.tsx')
    require(errors,'luminet://import' in deeplink and 'maxDeepLinkLength     = 4096' in deeplink and 'ValidateProfileSourceURL(source)' in deeplink,'subscription deep-link bounded/canonical admission drift')
    require(errors,'subscription URL must not embed credentials' in deeplink and 'unsupported deep-link parameter' in deeplink and 'must appear exactly once' in deeplink,'subscription deep-link input hardening drift')
    require(errors,'subs.POST("/deeplink/inspect", s.InspectSubscriptionDeepLink)' in subroutes and '"requires_confirmation": true' in subhandlers and '"side_effects":          []string{}' in subhandlers,'subscription deep-link inspect-only API contract drift')
    require(errors,'never fetches, saves, refreshes, or activates' in profiles and 'Inspect & prefill' in profiles,'subscription deep-link explicit-confirmation product contract drift')
    require(errors,all(token not in deeplink for token in ['http.Get','http.NewRequest','os.WriteFile','exec.Command']),'subscription deep-link parser gained network/filesystem/process side effects')

    # Update durability and mutation retry ownership.
    stage=text('src/apps/daemon/internal/foundation/updateadmission/stage.go')
    unix_replace=text('src/apps/daemon/internal/foundation/updateadmission/replace_stage_file_unix.go')
    win_replace=text('src/apps/daemon/internal/foundation/updateadmission/replace_stage_file_windows.go')
    unix_sync=text('src/apps/daemon/internal/foundation/updateadmission/sync_stage_dir_unix.go')
    require(errors,'replacePublishedStagedFile(source, target)' in stage and 'syncStageDirectory(filepath.Dir(target))' in stage,'staged publication durability path missing')
    require(errors,'return os.Rename(source, target)' in unix_replace and 'os.Remove(target)' not in unix_replace,'Unix publication is no longer atomic rename-overwrite')
    require(errors,'os.Remove(target)' in win_replace and 'os.Rename(source, target)' in win_replace,'Windows replacement fallback drift')
    require(errors,'dir.Sync()' in unix_sync,'Unix parent directory sync missing')
    cfg=text('src/apps/daemon/internal/foundation/config/config.go')
    require(errors,'DefaultMutationAttempts = 3' in cfg and 'MaxMutationAttempts     = 8' in cfg,'automatic configuration retry bounds drift')
    require(errors,'options.ExpectedRevision != nil' in cfg and 'maxAttempts = 1' in cfg and 'errors.Is(err, ErrRevisionConflict)' in cfg,'configuration retry authority semantics drift')
    require(errors,not (ROOT/'src/packages/lumicore/src/integration/mutation_retry.rs').exists(),'superseded generic Rust mutation retry returned')

    # High-risk negative guardrails.
    middleware=text('src/apps/daemon/internal/adapters/api/middleware.go')
    # PR222-GUARD-CAPTCHA
    require(errors,'captcha' not in middleware.lower() and 'subtle.ConstantTimeCompare' in middleware,'authentication acquired challenge-solver authority or lost constant-time key comparison')
    # PR222-GUARD-TOR-CORRELATION
    security=text('governance/convergence/post-refactor-222-security-model.md')
    require(errors,'## Correlation and anonymity limits' in security and 'must not be described as proof of anonymity' in security,'correlation/anonymity claim guard missing')
    # PR222-GUARD-HDS-RISK
    require(errors,'## Access-risk heuristics' in security and 'never authenticate a caller' in security,'access-risk observation/identity boundary missing')
    # PR222-GUARD-MARZBAN-INSECURE
    require(errors,'## Service identity and certificates' in security and 'fail closed' in security,'service identity fail-closed guard missing')
    # PR222-GUARD-RELEASE-KEYS
    require(errors,'## Release trust' in security and 'Donor signing keys' in security,'release-key authority guard missing')
    # PR222-GUARD-NO-FLASH
    update_files='\n'.join(p.as_posix() for p in (ROOT/'src/apps/daemon/internal/foundation/updateadmission').rglob('*') if p.is_file())
    require(errors,all(x not in stage for x in ['fastboot','adb ','install-su','signature spoof']),'signed update staging gained device-flashing authority')
    # PR222-GUARD-BUNDLED-BINARIES
    require(errors,not any(p.suffix.lower() in {'.jar','.exe','.dll'} for p in ROOT.rglob('*') if p.is_file() and p.relative_to(ROOT).as_posix() in {r['path'] for r in delta_rows}),'post-222 delta introduced opaque executable helper binary')
    # PR222-GUARD-STEALTH-KILLSWITCH
    require(errors,'ufw' not in cfg.lower() and 'killswitch' not in cfg.lower(),'configuration authority absorbed donor firewall reset helper')
    # PR222-SUPERSEDE-ED-RUNTIME
    require(errors,not any('edtunnel' in p.name.lower() for p in (ROOT/'src').rglob('*')),'donor-shaped EDtunnel runtime copied into source tree')
    # PR222-GUARD-ED-URL-AUTHORITY
    require(errors,'c.Query("api_key")' not in middleware and 'Query("key")' not in middleware,'query-string credentials became API authority')
    # PR222-SUPERSEDE-IOS-RUNTIME
    require(errors,not (ROOT/'VpnTunnelExtension').exists() and not (ROOT/'src/VpnTunnelExtension').exists(),'iOS donor packet-tunnel runtime copied into target root')

    # Older convergence waves freeze to this exact predecessor baseline instead of descendant source.
    old220=text('scripts/checks/check_post_refactor_220_convergence.py')
    require(errors,'post-refactor-222-baseline-files.csv' in old220 and 'SUCCESSOR_BASELINE' in old220,'post-220 checker is not frozen to post-222 baseline')
    require(errors,SUCCESSOR_BASELINE.is_file(),'post-222 historical checker is not frozen to the post-223 successor baseline')
    make=text('Makefile')
    require(errors,'check_post_refactor_222_convergence.py' in make,'Makefile missing post-222 gate')

    # Target delta is exact against immutable post-221 baseline. The delta file excludes itself.
    current=scan_current()
    expected_delta={}
    for path in sorted(set(baseline)|set(current)):
        before=baseline.get(path); after=current.get(path)
        if before==after: continue
        if before is None: expected_delta[path]=('added','n/a',after[1])
        elif after is None: expected_delta[path]=('deleted',before[1],'n/a')
        else: expected_delta[path]=('modified',before[1],after[1])
    delta={}
    for r in delta_rows:
        path=r['path'].strip()
        require(errors,path and path not in delta,f'duplicate/empty delta path {path!r}')
        delta[path]=r
        expected=expected_delta.get(path)
        require(errors,expected is not None,f'delta contains unchanged/unexpected path {path}')
        if expected:
            require(errors,(r['change_type'],r['baseline_sha256'],r['current_sha256'])==expected,f'delta mismatch {path}')
        require(errors,bool(r.get('reason','').strip()),f'delta reason missing {path}')
    missing=sorted(set(expected_delta)-set(delta)); extra=sorted(set(delta)-set(expected_delta))
    if missing: errors.append(f'delta missing {len(missing)} paths: {missing[:100]}')
    if extra: errors.append(f'delta has {len(extra)} extra paths: {extra[:100]}')

    if errors:
        print(f'{P} convergence: FAIL ({len(errors)} errors)')
        for error in errors[:500]: print('ERROR:',error)
        return 1
    dc=Counter(r['change_type'] for r in delta_rows)
    print(f"{P} convergence: PASS donors={len(donor_rows)} surfaces={len(surfaces)} symbols={len(symbols)} ledger={len(ledger)} baseline={len(baseline)} delta={len(delta_rows)} added={dc['added']} modified={dc['modified']} deleted={dc['deleted']}")
    return 0

if __name__=='__main__':
    raise SystemExit(main())
