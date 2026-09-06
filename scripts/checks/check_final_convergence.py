#!/usr/bin/env python3
from __future__ import annotations
import csv, hashlib, os, re
from pathlib import Path
from collections import Counter, defaultdict

ROOT = Path(__file__).resolve().parents[2]
G = ROOT/'governance/convergence'
EXPECTED = {
    'donors':43, 'members':9556, 'directories':1516, 'surfaces':8040,
    'modules':523, 'symbols':17724, 'historical_semantics':60,
    'records':592, 'new_semantics':9, 'supersession':13, 'repairs':15, 'high_level_planes':18,
    'baseline':2546, 'symlinks':37,
}
HEX64 = re.compile(r'^[0-9a-f]{64}$')
VALID_STATUS = {'verified','statically-validated','reviewed','inferred','unverified','pending'}
VALID_DISPOSITIONS = {'adopted','adapted','hardened','extracted','recomposed','synthesized','inspired-native','guardrail-derived','superseded','rejected-with-reason','reference-only'}
DELTA_REL='governance/convergence/final-pass-target-delta.csv'
SUCCESSOR_BASELINE=G/'ultimate-pass-baseline-files.csv'


def read_csv(name):
    p=G/name
    if not p.is_file(): raise AssertionError(f'missing {name}')
    with p.open(encoding='utf-8-sig',newline='') as f: return list(csv.DictReader(f))

def refs(v): return [x for x in (v or '').split(';') if x and x!='n/a']

def digest_path(p:Path):
    if p.is_symlink():
        t=os.readlink(p); return ('symlink', hashlib.sha256(t.encode()).hexdigest(), t)
    return ('file', hashlib.sha256(p.read_bytes()).hexdigest(), 'n/a')

def scan_current():
    # Once the ultimate +20 wave exists, validate the frozen all-43 final state
    # against its successor baseline so later convergence cannot rewrite the
    # historical final-pass delta.
    if SUCCESSOR_BASELINE.is_file():
        out={}
        with SUCCESSOR_BASELINE.open(encoding='utf-8',newline='') as f:
            for row in csv.DictReader(f):
                rel=row['path'].strip()
                if rel==DELTA_REL: continue
                out[rel]=(row['file_type'].strip(),row['sha256'].strip(),row['link_target'])
        return out
    out={}
    for p in sorted(ROOT.rglob('*')):
        if not (p.is_file() or p.is_symlink()): continue
        rel=p.relative_to(ROOT).as_posix()
        if rel==DELTA_REL or rel.startswith('.git/') or '/__pycache__/' in '/'+rel or rel.endswith('.pyc'): continue
        out[rel]=digest_path(p)
    return out

LEGACY_ANCHOR_SUCCESSORS = {
    'src/apps/daemon/internal/adapters/api/config_mutation.go#commitConfigSnapshot': 'src/apps/daemon/internal/adapters/api/config_mutation.go#commitConfigMutation',
    'src/apps/daemon/internal/adapters/api/config_mutation.go#expectedConfigRevision': 'src/apps/daemon/internal/adapters/api/config_mutation.go#configMutationOptions',
}

def anchor_exists(node):
    node=(node or '').strip()
    node=LEGACY_ANCHOR_SUCCESSORS.get(node,node)
    if not node or node=='n/a': return True
    if '#' not in node:
        return (ROOT/node).is_file()
    rel,a=node.split('#',1); p=ROOT/rel
    if not p.is_file(): return False
    raw=p.read_text(encoding='utf-8',errors='replace')
    cands={a,a.split('.')[-1],a.replace('-',' '),a.replace('-','_')}
    return any(c and re.search(r'(?<![A-Za-z0-9_])'+re.escape(c)+r'(?![A-Za-z0-9_])',raw,re.I) for c in cands)

def text(rel): return (ROOT/rel).read_text(encoding='utf-8',errors='replace')

def main():
    errors=[]
    try:
        donors=read_csv('final-pass-donors.csv')
        dirs=read_csv('final-pass-directories.csv')
        surfaces=read_csv('final-pass-surfaces.csv')
        modules=read_csv('final-pass-modules.csv')
        symbols=read_csv('final-pass-symbols.csv')
        ledger=read_csv('final-pass-adoption-ledger.csv')
        reval=read_csv('final-pass-semantic-revalidation.csv')
        sups=read_csv('final-pass-supersession-map.csv')
        repairs=read_csv('final-pass-target-repairs.csv')
        baseline_rows=read_csv('final-pass-baseline-files.csv')
        delta_rows=read_csv('final-pass-target-delta.csv')
        licenses=read_csv('final-pass-license-map.csv')
        high_planes=read_csv('final-pass-high-level-plane-audit.csv')
    except Exception as e:
        print('final convergence:',e); return 1

    counts={'donors':len(donors),'directories':len(dirs),'surfaces':len(surfaces),'modules':len(modules),'symbols':len(symbols),'historical_semantics':len(reval),'records':len(ledger),'supersession':len(sups),'repairs':len(repairs),'baseline':len(baseline_rows),'high_level_planes':len(high_planes)}
    for k,v in counts.items():
        if v != EXPECTED[k]: errors.append(f'{k} count {v} != {EXPECTED[k]}')
    if len([r for r in ledger if r['record_id'].startswith('FP-S')]) != EXPECTED['new_semantics']: errors.append('new semantic record denominator mismatch')
    if sum(int(r['member_count']) for r in donors) != EXPECTED['members']: errors.append('archive member denominator mismatch')
    if sum(int(r['file_surfaces']) for r in donors) != EXPECTED['surfaces']: errors.append('surface rollup mismatch')
    if sum(int(r['directories']) for r in donors) != EXPECTED['directories']: errors.append('directory rollup mismatch')
    if sum(int(r['symbols']) for r in donors) != EXPECTED['symbols']: errors.append('symbol rollup mismatch')
    if sum(int(r['symlinks']) for r in donors) != EXPECTED['symlinks']: errors.append('symlink rollup mismatch')
    if len(licenses)!=EXPECTED['donors'] or {r['donor'] for r in licenses}!={r['donor'] for r in donors}: errors.append('license map donor mismatch')
    if len({r['donor'] for r in donors})!=EXPECTED['donors']: errors.append('duplicate donor identities')
    for d in donors:
        if not HEX64.fullmatch(d.get('archive_sha256','')): errors.append(f"{d.get('donor')}: invalid archive hash")
        if not d.get('archive_issues','').startswith('none'): errors.append(f"{d.get('donor')}: archive safety not closed")

    records={r.get('record_id',''):r for r in ledger}
    if len(records)!=len(ledger) or '' in records: errors.append('duplicate/empty ledger ids')
    surface={(r['donor'],r['path']):r for r in surfaces}
    if len(surface)!=len(surfaces): errors.append('duplicate donor surface rows')
    module_by_id={m['module_id']:m for m in modules}
    if len(module_by_id)!=len(modules): errors.append('duplicate module ids')

    # Higher-level plane audit: exact donor evidence and current target ownership must remain truthful.
    for hp in high_planes:
        eps=refs(hp.get('evidence_paths'))
        ehs=refs(hp.get('evidence_sha256'))
        if len(eps)!=len(ehs) or not eps:
            errors.append(f"high-level plane {hp.get('plane')}: evidence path/hash cardinality mismatch")
            continue
        for ep,eh in zip(eps,ehs):
            if ':' not in ep:
                errors.append(f"high-level plane {hp.get('plane')}: malformed evidence path {ep}"); continue
            donor,path=ep.split(':',1)
            sr=surface.get((donor,path))
            if not sr:
                errors.append(f"high-level plane {hp.get('plane')}: missing donor evidence {ep}")
            elif sr['sha256']!=eh:
                errors.append(f"high-level plane {hp.get('plane')}: donor hash mismatch {ep}")
        for owner in refs(hp.get('current_target_owner')):
            if not (ROOT/owner).exists():
                errors.append(f"high-level plane {hp.get('plane')}: missing target owner {owner}")
        if hp.get('validation_status') not in VALID_STATUS:
            errors.append(f"high-level plane {hp.get('plane')}: invalid validation status")
        if not hp.get('decision_rationale') or not hp.get('invariant') or not hp.get('residual_gap'):
            errors.append(f"high-level plane {hp.get('plane')}: incomplete decision/invariant/residual gap")

    # Ledger evidence, target anchors, dependency graph and discriminating evidence.
    for r in ledger:
        rid=r['record_id']
        if r.get('disposition') not in VALID_DISPOSITIONS: errors.append(f'{rid}: invalid disposition')
        if r.get('validation_status') not in VALID_STATUS: errors.append(f'{rid}: invalid validation status')
        if r.get('risk_tier') not in {'critical','high','medium','low'}: errors.append(f'{rid}: invalid risk')
        if not HEX64.fullmatch(r.get('donor_sha256','')): errors.append(f'{rid}: invalid donor hash')
        sr=surface.get((r.get('donor'),r.get('donor_path')))
        if not sr: errors.append(f"{rid}: donor surface missing {r.get('donor')}:{r.get('donor_path')}")
        elif sr['sha256']!=r['donor_sha256']: errors.append(f'{rid}: donor hash mismatch')
        for dep in refs(r.get('dependency_record_ids')):
            if dep not in records: errors.append(f'{rid}: unknown dependency {dep}')
        for node in refs(r.get('target_nodes')):
            if not anchor_exists(node): errors.append(f'{rid}: missing target anchor {node}')
        for node in refs(r.get('test_node')):
            if not anchor_exists(node): errors.append(f'{rid}: missing test anchor {node}')
        if r['record_id'].startswith('FP-S') and r.get('disposition') not in {'reference-only','superseded'} and r.get('test_node')=='n/a': errors.append(f'{rid}: final semantic decision lacks evidence')
    # Detect dependency cycles.
    graph={rid:refs(r.get('dependency_record_ids')) for rid,r in records.items()}
    state={}
    def visit(n,stack):
        s=state.get(n,0)
        if s==1: errors.append('ledger dependency cycle: '+' -> '.join(stack+[n])); return
        if s==2: return
        state[n]=1
        for d in graph.get(n,[]): visit(d,stack+[n])
        state[n]=2
    for rid in graph: visit(rid,[])

    # Every surface belongs to exactly one bounded recursive module; fine rows add evidence links.
    module_counts=Counter()
    for s in surfaces:
        if not HEX64.fullmatch(s.get('sha256','')): errors.append(f"surface {s['donor']}:{s['path']}: invalid hash")
        ids=refs(s.get('semantic_record_ids'))
        mids=[x for x in ids if x.startswith('FP-M')]
        if len(mids)!=1: errors.append(f"surface {s['donor']}:{s['path']}: expected exactly one module link, got {mids}")
        else:
            if mids[0] not in module_by_id: errors.append(f"surface {s['donor']}:{s['path']}: unknown module {mids[0]}")
            module_counts[mids[0]]+=1
        for rid in ids:
            if rid not in records: errors.append(f"surface {s['donor']}:{s['path']}: unknown record {rid}")
    for mid,m in module_by_id.items():
        n=module_counts[mid]
        if n!=int(m['surface_count']): errors.append(f'{mid}: surface count {n} != {m["surface_count"]}')
        if n>100: errors.append(f'{mid}: umbrella module contains {n} surfaces >100')
        lr=records.get(mid)
        if not lr or lr['donor']!=m['donor'] or lr['donor_path']!=m['representative_path'] or lr['donor_sha256']!=m['representative_sha256']: errors.append(f'{mid}: module ledger mismatch')

    # Directory accountability. The source analyzer distinguished directory symlinks
    # from file symlinks using the extracted donor filesystem; that distinction is not
    # reconstructible from the packaged surface CSV alone. Validate uniqueness, donor
    # coverage, non-negative direct counts, roots, and parent coverage without inventing
    # symlink kind after the donor trees are no longer present.
    dirkeys=set()
    roots=set()
    valid_donors={r['donor'] for r in donors}
    for d in dirs:
        key=(d['donor'],d['directory'])
        if key in dirkeys: errors.append(f'duplicate directory row {key}')
        dirkeys.add(key)
        if d['donor'] not in valid_donors: errors.append(f'unknown directory donor {d["donor"]}')
        try:
            if int(d['direct_files'])<0 or int(d['direct_dirs'])<0: errors.append(f'negative directory count {key}')
        except ValueError: errors.append(f'invalid directory count {key}')
        if d['directory']=='.': roots.add(d['donor'])
    if roots!=valid_donors: errors.append(f'directory root coverage mismatch missing={sorted(valid_donors-roots)}')
    for s in surfaces:
        parent=Path(s['path']).parent.as_posix()
        if parent=='.': parent='.'
        if (s['donor'],parent) not in dirkeys:
            # A surface below a directory symlink has no real child traversal in the
            # safe extraction, so only actual surface parents are required.
            errors.append(f'surface parent absent from directory inventory {s["donor"]}:{s["path"]}')
    # All parsed symbols resolve to exact inventoried source paths.
    for s in symbols:
        if (s['donor'],s['path']) not in surface: errors.append(f"symbol path absent {s['donor']}:{s['path']}#{s['symbol']}")

    # Revalidation must prove all 60 fine historical decisions still resolve.
    oldids={r['record_id'] for r in reval}
    if len(oldids)!=EXPECTED['historical_semantics']: errors.append('historical semantic ids duplicate')
    for r in reval:
        if r['final_status']!='verified-current' or r['donor_hash_matches']!='true' or r['target_nodes_current']!='true' or r['test_nodes_current']!='true': errors.append(f"{r['record_id']}: stale historical semantic evidence")
        if r['record_id'] not in records: errors.append(f"{r['record_id']}: historical record missing from final ledger")

    # Fine record -> evidence surface must link back to the record.
    for r in ledger:
        rid=r['record_id']
        if rid.startswith('FP-M'): continue
        sr=surface.get((r['donor'],r['donor_path']))
        if sr and rid not in refs(sr['semantic_record_ids']): errors.append(f'{rid}: donor surface lacks bidirectional fine link')

    # Exact ninth-order baseline -> final-pass source delta. final-pass-target-delta.csv does not self-account.
    baseline={}
    for r in baseline_rows:
        p=r['path'].strip()
        if not p or p in baseline: errors.append(f'duplicate/empty final baseline path {p!r}'); continue
        if r['file_type'] not in {'file','symlink'} or not HEX64.fullmatch(r['sha256']): errors.append(f'final baseline {p}: invalid row')
        baseline[p]=(r['file_type'],r['sha256'],r['link_target'])
    current=scan_current(); expected={}
    for p in sorted(set(baseline)|set(current)):
        a,b=baseline.get(p),current.get(p)
        if a==b: continue
        if a is None: expected[p]=('added','n/a',b[1])
        elif b is None: expected[p]=('deleted',a[1],'n/a')
        else: expected[p]=('modified',a[1],b[1])
    delta={}
    for r in delta_rows:
        p=r.get('path','').strip()
        if not p or p in delta: errors.append(f'duplicate/empty final delta path {p!r}'); continue
        delta[p]=r; exp=expected.get(p)
        if exp is None: errors.append(f'final delta {p}: not changed'); continue
        got=(r.get('change_type'),r.get('ninth_order_sha256'),r.get('current_sha256'))
        if got!=exp: errors.append(f'final delta {p}: hash/change mismatch got={got} expected={exp}')
        if not r.get('accountability_class','').strip() or not r.get('reason','').strip(): errors.append(f'final delta {p}: incomplete accountability')
    missing=sorted(set(expected)-set(delta)); extra=sorted(set(delta)-set(expected))
    if missing: errors.append(f'final target delta missing {len(missing)} paths: {missing[:40]}')
    if extra: errors.append(f'final target delta extra {len(extra)} paths: {extra[:40]}')

    # ----- New automatic mutation-coordination invariants -----
    remote=text('src/apps/daemon/internal/foundation/remoteaction/remoteaction.go')
    rtest=text('src/apps/daemon/internal/foundation/remoteaction/remoteaction_test.go')
    for m in ['RateLimitScope','MaxInFlight','ErrCoordinatorCapacity','waitForCooldownAndAcquire','equalJitter','CapacityStops','InFlightWaits','ReconcileBeforeRetry','SingleAttempt']:
        if m not in remote: errors.append(f'remote mutation final invariant missing {m}')
    for m in ['TestExecutorSharesCooldownAcrossActionsInSameProviderScope','TestExecutorProviderScopesRemainIsolated','TestExecutorBoundsConcurrentMutationsPerScope','TestExecutorFailsClosedWhenActiveScopeCapacityIsExhausted','TestExecutorJittersOnlyLocalBackoff','TestRetryAfterRemainsProviderAuthoritativeWithoutJitter','TestSingleAttemptNeverReplays']:
        if m not in rtest: errors.append(f'remote mutation final test missing {m}')
    for rel,scope in [
        ('src/apps/daemon/internal/integrations/provision/cloudflare.go','provider.cloudflare'),
        ('src/apps/daemon/internal/analysis/scanner/cloudflare_deployer.go','provider.cloudflare'),
        ('src/apps/daemon/internal/runtime/proxy/google_drive_actions.go','provider.google-drive'),
        ('src/apps/daemon/internal/runtime/warp/warp.go','provider.cloudflare-warp')]:
        if scope not in text(rel): errors.append(f'{rel}: provider retry scope {scope} missing')
    ddns=text('src/apps/daemon/internal/networking/dns/ddns_updater.go')
    for scope in ['provider.cloudflare','provider.duckdns','provider.noip','provider.dynu','provider.ddns']:
        if scope not in ddns: errors.append(f'DDNS retry scope missing {scope}')

    # ----- Live configuration authority -----
    cfg=text('src/apps/daemon/internal/foundation/config/config.go')
    ctest=text('src/apps/daemon/internal/foundation/config/revision_test.go')
    for m in ['ConfigRevision','ErrRevisionConflict','SaveIfRevision','GetWithRevision','persistSecretCopyOnWrite','retireSupersededSecretRefs','deleteSecretRefsBestEffort','deepCopy','fileHashSet','samePersistedBytes']:
        if m not in cfg: errors.append(f'live config invariant missing {m}')
    # Upgen encrypted seed intentionally remains inline; it must not trigger migration churn.
    has_inline=cfg[cfg.find('func (c *Config) hasInlineSecrets()'):cfg.find('func (m *Manager) persistSecrets',cfg.find('func (c *Config) hasInlineSecrets()'))]
    if 'UpgenObfuscation' in has_inline or 'SeedHex' in has_inline: errors.append('inline-secret detector still treats Upgen seed as migration trigger')
    for m in ['TestSaveIfRevisionRejectsStaleWriterWithoutLosingNewerState','TestFailedSaveDoesNotAdvanceRevision','TestSavePublishesOwnedSnapshotWithGeneratedSecretRefs','TestUnchangedSecretKeepsCommittedReference','TestChangedSecretUsesCopyOnWriteReference','TestFailedConfigCommitRollsBackStagedSecretWithoutMutatingOldRef','TestRevisionPersistsAcrossRestart','TestLegacyConfigWithoutRevisionIsMigratedAtomically','TestExternalReloadWithReusedRevisionAdvancesGeneration','TestReloadOfCurrentCommittedBytesDoesNotAdvanceRevision']:
        if m not in ctest: errors.append(f'live config regression missing {m}')
    api=text('src/apps/daemon/internal/adapters/api/config_mutation.go'); apit=text('src/apps/daemon/internal/adapters/api/config_mutation_test.go')
    for m in ['configRevisionETag','parseConfigRevisionETag','configMutationOptions','commitConfigMutation','If-Match','current_revision']:
        if m not in api: errors.append(f'HTTP config CAS invariant missing {m}')
    if 'TestParseConfigRevisionETag' not in apit: errors.append('HTTP config ETag parser test missing')
    if 'TestConfigRevisionConflictStatus' not in apit: errors.append('HTTP If-Match precondition-status test missing')
    if 'StatusPreconditionFailed' not in api: errors.append('HTTP If-Match conflict does not use 412 Precondition Failed')
    for rel in ['src/apps/daemon/internal/adapters/api/handlers_system_startup.go','src/apps/daemon/internal/adapters/api/handlers_system_ddns.go','src/apps/daemon/internal/adapters/api/handlers_proxy_directory.go']:
        raw=text(rel)
        for m in ['GetWithRevision','commitConfigMutation']:
            if m not in raw: errors.append(f'{rel}: shared live config CAS path missing {m}')
    startup=text('src/apps/daemon/internal/adapters/api/handlers_system_startup.go')
    if startup.find('commitConfigMutation') > startup.find('SetHostsOverride'): errors.append('HostsOverride side effect still occurs before durable config commit')

    # Dormant unsafe parallel authorities must stay gone; canonical owners remain.
    for rel in ['src/apps/daemon/internal/platform/system/reverse_tls.go','src/apps/daemon/internal/platform/system/api_key_reverse_proxy.go','src/apps/daemon/internal/platform/system/traffic_shaper.go']:
        if (ROOT/rel).exists(): errors.append(f'unsafe/dormant parallel authority survived: {rel}')
    for rel in ['src/apps/daemon/internal/platform/system/host_network.go','src/apps/daemon/internal/foundation/config/config.go','src/apps/daemon/internal/foundation/remoteaction/remoteaction.go']:
        if not (ROOT/rel).is_file(): errors.append(f'canonical target owner missing: {rel}')

    # Ninth-order Caddy compatibility owner may remain for reference/tests, but must not regain production authority.
    caddy=text('src/apps/daemon/internal/platform/system/caddy.go')
    if 'HotReloadIfHash' not in caddy: errors.append('dormant Caddy reference owner unexpectedly lost conditional-mutation evidence')
    production_hits=[]
    for p in (ROOT/'src/apps/daemon').rglob('*.go'):
        rel=p.relative_to(ROOT).as_posix()
        if rel.endswith('caddy.go') or rel.endswith('caddy_test.go'): continue
        raw=p.read_text(encoding='utf-8',errors='replace')
        if 'NewConfigManager(' in raw or 'ConfigManager{' in raw: production_hits.append(rel)
    if production_hits: errors.append(f'dormant Caddy ConfigManager regained parallel production authority: {production_hits[:10]}')

    # Historical checker layering: final edits cannot mutate ninth-order historical truth.
    ninth=text('scripts/checks/check_ninth_order_convergence.py'); make=text('Makefile')
    if "SUCCESSOR_BASELINE=G/'final-pass-baseline-files.csv'" not in ninth: errors.append('ninth-order checker lacks final-pass successor baseline layering')
    if 'check_final_convergence.py' not in make: errors.append('canonical verify-repo does not execute final convergence gate')
    if 'export PYTHONDONTWRITEBYTECODE := 1' not in make: errors.append('canonical verification can create Python bytecode residue')

    # Safety-veto peers remain evidence only, not production capability names/surfaces.
    for forbidden in ['DNS-Persist','ftpscan','InterceptSuite']:
        for p in (ROOT/'src').rglob('*'):
            if not p.is_file(): continue
            if forbidden.lower() in p.name.lower(): errors.append(f'safety-veto donor leaked into production filename: {p.relative_to(ROOT)}')
    xui=text('deploy/server-bootstrap/x-ui-pro.sh')
    if 'placeholder' not in xui.lower(): errors.append('x-ui-pro deployment surface no longer truthfully identifies placeholder status')

    # Supersession groups must cover all donors at least once across the final many-to-many synthesis map.
    sup_donors=set()
    for s in sups:
        sup_donors.update(refs(s.get('donors')))
    all_donors={r['donor'] for r in donors}
    if sup_donors != all_donors:
        errors.append(f'supersession donor coverage mismatch missing={sorted(all_donors-sup_donors)} extra={sorted(sup_donors-all_donors)}')

    if errors:
        print(f'final convergence: errors={len(errors)}')
        for e in errors[:300]: print('ERROR:',e)
        return 1
    print('final convergence: donors={donors} members={members} directories={directories} surfaces={surfaces} symlinks={symlinks} modules={modules} symbols={symbols} historical_semantics={historical} new_semantics={new} records={records} supersession={supersession} repairs={repairs} high_level_planes={high_level_planes} baseline={baseline} changes={changes} errors=0'.format(
        donors=len(donors),members=EXPECTED['members'],directories=len(dirs),surfaces=len(surfaces),symlinks=EXPECTED['symlinks'],modules=len(modules),symbols=len(symbols),historical=len(reval),new=len([r for r in ledger if r['record_id'].startswith('FP-S')]),records=len(ledger),supersession=len(sups),repairs=len(repairs),high_level_planes=len(high_planes),baseline=len(baseline_rows),changes=len(delta_rows)))
    return 0

if __name__=='__main__': raise SystemExit(main())
