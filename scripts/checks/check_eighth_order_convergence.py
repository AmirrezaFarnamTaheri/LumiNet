#!/usr/bin/env python3
from __future__ import annotations
import csv, hashlib, os, re, sys
from pathlib import Path
from collections import defaultdict

ROOT=Path(__file__).resolve().parents[2]
G=ROOT/'governance/convergence'
EXPECTED={'donors':23,'members':7177,'directories':1091,'surfaces':6057,'modules':395,'symbols':9072,'records':424,'supersession':8,'baseline':2502}
HEX64=re.compile(r'^[0-9a-f]{64}$')
VALID_STATUS={'verified','statically-validated','reviewed','inferred','unverified','pending'}
VALID_DISPOSITIONS={'adopted','adapted','hardened','extracted','recomposed','synthesized','inspired-native','guardrail-derived','superseded','rejected-with-reason','reference-only'}
DELTA_REL='governance/convergence/eighth-order-target-delta.csv'
SUCCESSOR_BASELINE=G/'ninth-order-baseline-files.csv'

def read_csv(name):
 p=G/name
 if not p.is_file():raise AssertionError(f'missing {name}')
 with p.open(encoding='utf-8-sig',newline='') as f:return list(csv.DictReader(f))

def refs(value):return [x for x in (value or '').split(';') if x and x!='n/a']
def digest_path(p):
 if p.is_symlink():
  t=os.readlink(p);return ('symlink',hashlib.sha256(t.encode()).hexdigest(),t)
 return ('file',hashlib.sha256(p.read_bytes()).hexdigest(),'n/a')
def scan_current():
 # Once ninth-order exists, validate delivered eighth-order state against its
 # frozen successor baseline so later convergence cannot rewrite history.
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
  if rel==DELTA_REL or rel.startswith('.git/'):continue
  out[rel]=digest_path(p)
 return out

def anchor_exists(node):
 node=(node or '').strip()
 if not node or node=='n/a':return True
 if '#' not in node:return False
 rel,anchor=node.split('#',1);p=ROOT/rel
 if not p.is_file():return False
 raw=p.read_text(encoding='utf-8',errors='replace')
 cands={anchor,anchor.split('.')[-1],anchor.replace('-',' '),anchor.replace('-','_')}
 return any(c and re.search(r'(?<![A-Za-z0-9_])'+re.escape(c)+r'(?![A-Za-z0-9_])',raw,re.I) for c in cands)

def main():
 errors=[]
 try:
  donors=read_csv('eighth-order-donors.csv');dirs=read_csv('eighth-order-directories.csv');surfaces=read_csv('eighth-order-surfaces.csv');modules=read_csv('eighth-order-modules.csv');symbols=read_csv('eighth-order-symbols.csv');ledger=read_csv('eighth-order-adoption-ledger.csv');sups=read_csv('eighth-order-supersession-map.csv');baseline_rows=read_csv('eighth-order-baseline-files.csv');delta_rows=read_csv('eighth-order-target-delta.csv')
 except Exception as e:
  print('eighth-order convergence:',e);return 1
 counts={'donors':len(donors),'directories':len(dirs),'surfaces':len(surfaces),'modules':len(modules),'symbols':len(symbols),'records':len(ledger),'supersession':len(sups),'baseline':len(baseline_rows)}
 for k,v in counts.items():
  if v!=EXPECTED[k]:errors.append(f'{k} count {v} != {EXPECTED[k]}')
 if sum(int(r['member_count']) for r in donors)!=EXPECTED['members']:errors.append('archive member denominator mismatch')
 if sum(int(r['file_surfaces']) for r in donors)!=EXPECTED['surfaces']:errors.append('surface rollup mismatch')
 if sum(int(r['directories']) for r in donors)!=EXPECTED['directories']:errors.append('directory rollup mismatch')
 if sum(int(r['symbols']) for r in donors)!=EXPECTED['symbols']:errors.append('symbol rollup mismatch')
 if len({r['donor'] for r in donors})!=EXPECTED['donors']:errors.append('duplicate donor identities')
 records={r.get('record_id',''):r for r in ledger}
 if len(records)!=len(ledger) or '' in records:errors.append('duplicate/empty ledger record ids')
 surface={(r['donor'],r['path']):r for r in surfaces}
 if len(surface)!=len(surfaces):errors.append('duplicate donor surface rows')
 for d in donors:
  if not HEX64.fullmatch(d.get('archive_sha256','')):errors.append(f"{d.get('donor')}: invalid archive hash")
  if not d.get('archive_issues','').startswith('none'):errors.append(f"{d.get('donor')}: archive issues not closed")
  for rid in refs(d.get('semantic_record_ids')):
   if rid not in records:errors.append(f"{d.get('donor')}: unknown record {rid}")
 for r in ledger:
  rid=r['record_id']
  if r.get('disposition') not in VALID_DISPOSITIONS:errors.append(f'{rid}: invalid disposition')
  if r.get('validation_status') not in VALID_STATUS:errors.append(f'{rid}: invalid validation status')
  if r.get('risk_tier') not in {'critical','high','medium','low'}:errors.append(f'{rid}: invalid risk')
  if not HEX64.fullmatch(r.get('donor_sha256','')):errors.append(f'{rid}: invalid donor hash')
  sr=surface.get((r.get('donor'),r.get('donor_path')))
  if not sr:errors.append(f"{rid}: donor surface missing {r.get('donor')}:{r.get('donor_path')}")
  elif sr['sha256']!=r['donor_sha256']:errors.append(f'{rid}: donor hash mismatch')
  for dep in refs(r.get('dependency_record_ids')):
   if dep not in records:errors.append(f'{rid}: unknown dependency {dep}')
  for node in refs(r.get('target_nodes')):
   if not anchor_exists(node):errors.append(f'{rid}: missing target anchor {node}')
  test=r.get('test_node','n/a')
  if test!='n/a' and not anchor_exists(test):errors.append(f'{rid}: missing test anchor {test}')
  if r.get('disposition')!='reference-only' and test=='n/a':errors.append(f'{rid}: non-reference disposition lacks discriminating evidence')
 for s in surfaces:
  if not HEX64.fullmatch(s.get('sha256','')):errors.append(f"surface {s.get('donor')}:{s.get('path')}: invalid hash")
  ids=refs(s.get('semantic_record_ids'))
  if not ids:errors.append(f"surface {s.get('donor')}:{s.get('path')}: unresolved")
  for rid in ids:
   if rid not in records:errors.append(f"surface {s.get('donor')}:{s.get('path')}: unknown {rid}")
 # Directory counts and links are derived from exact surface paths, root included.
 by_donor=defaultdict(list)
 for s in surfaces:by_donor[s['donor']].append(s)
 for d in dirs:
  if d['path']=='.':
   desc=by_donor[d['donor']];direct=[s for s in desc if '/' not in s['path']]
  else:
   prefix=d['path'].rstrip('/')+'/'
   desc=[s for s in by_donor[d['donor']] if s['path'].startswith(prefix)]
   direct=[s for s in desc if '/' not in s['path'][len(prefix):]]
  if len(desc)!=int(d['recursive_surface_count']):errors.append(f"dir {d['donor']}:{d['path']}: recursive mismatch")
  if len(direct)!=int(d['direct_surface_count']):errors.append(f"dir {d['donor']}:{d['path']}: direct mismatch")
  for rid in refs(d.get('semantic_record_ids')):
   if rid not in records:errors.append(f"dir {d['donor']}:{d['path']}: unknown {rid}")
 for m in modules:
  ids=refs(m.get('semantic_record_ids'))
  if not m.get('module_id') or not ids:errors.append(f"module {m.get('donor')}:{m.get('path')}: unresolved")
  for rid in ids:
   if rid not in records:errors.append(f"module {m.get('donor')}:{m.get('path')}: unknown {rid}")
 # The recursive split is a deliberate anti-umbrella gate: only root-files or
 # unsplittable path chains may exceed 100 surfaces, and none do in this corpus.
 module_sizes={}
 for m in modules:
  rid=refs(m.get('semantic_record_ids'))[0] if refs(m.get('semantic_record_ids')) else ''
  module_sizes[rid]=0
 for s in surfaces:
  for rid in refs(s.get('semantic_record_ids')):
   if rid in module_sizes:module_sizes[rid]+=1
 over=[(rid,n) for rid,n in module_sizes.items() if n>100]
 if over:errors.append(f'recursive module grouping still hides >100 surfaces: {over[:10]}')
 for s in symbols:
  if (s['donor'],s['path']) not in surface:errors.append(f"symbol path absent {s['donor']}:{s['path']}#{s['symbol']}")
  ids=refs(s.get('semantic_record_ids'))
  if not ids:errors.append(f"symbol unresolved {s['donor']}:{s['path']}#{s['symbol']}")
  for rid in ids:
   if rid not in records:errors.append(f"symbol {s['symbol']}: unknown {rid}")
 for sup in sups:
  if not sup.get('supersession_id') or not sup.get('target_winner') or not sup.get('reason'):errors.append('incomplete supersession row')
  for rid in refs(sup.get('eighth_order_record_ids')):
   if rid not in records:errors.append(f"{sup.get('supersession_id')}: unknown {rid}")

 # Frozen seventh-order delivered baseline -> exact current delta.
 baseline={}
 for r in baseline_rows:
  p=r['path'].strip()
  if not p or p in baseline:errors.append(f'duplicate/empty eighth baseline path {p!r}');continue
  if r['file_type'] not in {'file','symlink'} or not HEX64.fullmatch(r['sha256']):errors.append(f'eighth baseline {p}: invalid row')
  baseline[p]=(r['file_type'],r['sha256'],r['link_target'])
 current=scan_current();expected={}
 for p in sorted(set(baseline)|set(current)):
  before,after=baseline.get(p),current.get(p)
  if before==after:continue
  if before is None:expected[p]=('added','n/a',after[1])
  elif after is None:expected[p]=('deleted',before[1],'n/a')
  else:expected[p]=('modified',before[1],after[1])
 delta={}
 for row in delta_rows:
  p=row.get('path','').strip()
  if not p or p in delta:errors.append(f'duplicate/empty eighth delta path {p!r}');continue
  delta[p]=row;exp=expected.get(p)
  if exp is None:errors.append(f'eighth delta {p}: not changed from baseline');continue
  got=(row.get('change_type'),row.get('seventh_order_sha256'),row.get('current_sha256'))
  if got!=exp:errors.append(f'eighth delta {p}: change/hash mismatch got={got} expected={exp}')
  for rid in refs(row.get('eighth_order_record_ids')):
   if rid not in records:errors.append(f'eighth delta {p}: unknown accountability id {rid}')
  if not row.get('accountability_class','').strip() or not row.get('reason','').strip() or not row.get('verification_node','').strip():errors.append(f'eighth delta {p}: incomplete accountability')
  if row.get('verification_node')!='n/a' and not anchor_exists(row.get('verification_node')):errors.append(f"eighth delta {p}: missing verification anchor {row.get('verification_node')}")
 missing=sorted(set(expected)-set(delta));extra=sorted(set(delta)-set(expected))
 if missing:errors.append(f'eighth target delta missing {len(missing)} paths: {missing[:20]}')
 if extra:errors.append(f'eighth target delta has {len(extra)} extra paths: {extra[:20]}')

 def text(rel):return (ROOT/rel).read_text(encoding='utf-8',errors='replace')
 # Automatic mutation retry: second-order, action-scoped, bounded, observable.
 remote=text('src/apps/daemon/internal/foundation/remoteaction/remoteaction.go')
 rtest=text('src/apps/daemon/internal/foundation/remoteaction/remoteaction_test.go')
 status=text('src/apps/daemon/internal/adapters/api/handlers_system_status.go')
 for marker in ['type Executor struct','defaultCooldownKeys','waitForCooldown','rememberCooldown','CooldownKeys','RateLimits','SingleAttempt','ReconcileBeforeRetry']:
  if marker not in remote:errors.append(f'remote mutation retry invariant missing {marker!r}')
 for marker in ['TestExecutorSharesRateLimitCooldownPerAction','TestExecutorCooldownStateIsBounded','TestExecutorCooldownWaitHonorsCancellationBeforeRequest']:
  if marker not in rtest:errors.append(f'remote mutation retry test missing {marker!r}')
 if not re.search(r'RemoteMutationRetry\s*:\s*remoteaction\.DefaultExecutorStats\(\)', status):errors.append('remote mutation retry telemetry is not exposed in system status')
 # DNS resilience composition.
 bounded=text('src/apps/daemon/internal/networking/dns/bounded_cache.go')
 cache=text('src/apps/daemon/internal/networking/dns/dohcache.go')
 proxy=text('src/apps/daemon/internal/networking/dns/doh_proxy.go')
 resolver=text('src/apps/daemon/internal/networking/dns/doh_resolver.go')
 for marker in ['type boundedTTLCache','maxEntries','staleUntil','EvictExpired']:
  if marker not in bounded:errors.append(f'bounded DNS cache invariant missing {marker!r}')
 for marker in ['DoHCachePolicy','cacheStale','fetchCoalesced','StartEviction(ctx context.Context','StatusBadGateway']:
  if marker not in cache:errors.append(f'DoH cache resilience invariant missing {marker!r}')
 if 'map[string]*cacheEntry' in proxy or 'sync.Map' in cache:errors.append('legacy unbounded DNS cache survived convergence')
 for marker in ['boundedTTLCache[[]byte]','rngMu','ErrNoProviders']:
  if marker not in proxy:errors.append(f'DoH proxy hardening missing {marker!r}')
 for marker in ['boundedTTLCache[[]string]','providerSnapshot','no providers configured','HTTP client is unavailable']:
  if marker not in resolver:errors.append(f'DoH resolver hardening missing {marker!r}')
 if 'map[string]*dnsCacheEntry' in resolver:errors.append('legacy unbounded resolver cache survived convergence')
 # Supervisor recovery semantics.
 sup=text('src/apps/daemon/internal/platform/system/process_supervisor.go')
 stest=text('src/apps/daemon/internal/platform/system/process_supervisor_test.go')
 for marker in ['stableReadyRun','stableReadyPeriod','recordFailureAfterRun','pruneFailureTimesLocked']:
  if marker not in sup:errors.append(f'process supervisor convergence missing {marker!r}')
 for marker in ['TestProcessSupervisorStableReadinessResetsOnlyBackoffDebt','TestProcessSupervisorFailureWindowPrunesDuringLongStableRun']:
  if marker not in stest:errors.append(f'process supervisor regression evidence missing {marker!r}')
 # Historical layering and canonical verify-repo entrypoint.
 seventh=text('scripts/checks/check_seventh_order_convergence.py')
 make=text('Makefile')
 if "SUCCESSOR_BASELINE=G/'eighth-order-baseline-files.csv'" not in seventh:errors.append('seventh-order historical checker lacks eighth-order successor baseline layering')
 if 'check_eighth_order_convergence.py' not in make:errors.append('canonical verify-repo does not execute eighth-order gate')
 # Safety veto: donor offensive repo names must not appear in production source.
 live='\n'.join(p.read_text(encoding='utf-8',errors='ignore') for p in (ROOT/'src').rglob('*') if p.is_file() and p.suffix in {'.go','.rs','.ts','.tsx','.js','.mjs','.kt','.java','.c','.cpp','.h'})
 for forbidden in ['DNS-Persist-master','ftpscan-master','InterceptSuite-main']:
  if forbidden in live:errors.append(f'safety-veto donor leaked into production source: {forbidden}')

 if errors:
  print(f'eighth-order convergence: errors={len(errors)}')
  for e in errors:print('ERROR:',e)
  return 1
 print(f'eighth-order convergence: donors={len(donors)} members={EXPECTED["members"]} directories={len(dirs)} surfaces={len(surfaces)} modules={len(modules)} symbols={len(symbols)} records={len(ledger)} supersession={len(sups)} baseline={len(baseline_rows)} changes={len(delta_rows)} errors=0')
 return 0
if __name__=='__main__':raise SystemExit(main())
