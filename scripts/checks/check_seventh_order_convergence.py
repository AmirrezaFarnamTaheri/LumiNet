#!/usr/bin/env python3
from __future__ import annotations
import csv, hashlib, os, re, sys
from pathlib import Path
from collections import defaultdict

ROOT=Path(__file__).resolve().parents[2]
G=ROOT/'governance/convergence'
EXPECTED={'donors':10,'members':17400,'directories':5605,'surfaces':11785,'modules':126,'symbols':31264,'records':55,'supersession':14,'baseline':2478}
HEX64=re.compile(r'^[0-9a-f]{64}$')
VALID_STATUS={'verified','statically-validated','reviewed','inferred','unverified','pending'}
VALID_DISPOSITIONS={'adopted','adapted','hardened','extracted','recomposed','synthesized','inspired-native','guardrail-derived','superseded','rejected-with-reason','reference-only'}
DELTA_REL='governance/convergence/seventh-order-target-delta.csv'
SUCCESSOR_BASELINE=G/'eighth-order-baseline-files.csv'

def read_csv(name):
 p=G/name
 if not p.is_file(): raise AssertionError(f'missing {name}')
 with p.open(encoding='utf-8-sig',newline='') as f:return list(csv.DictReader(f))

def refs(value): return [x for x in (value or '').split(';') if x and x!='n/a']
def digest_path(p):
 if p.is_symlink():
  t=os.readlink(p); return ('symlink',hashlib.sha256(t.encode()).hexdigest(),t)
 return ('file',hashlib.sha256(p.read_bytes()).hexdigest(),'n/a')
def scan_current():
 # Once eighth-order exists, validate the delivered seventh-order state against
 # its frozen successor baseline so later convergence cannot rewrite history.
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
 rel,anchor=node.split('#',1); p=ROOT/rel
 if not p.is_file():return False
 raw=p.read_text(encoding='utf-8',errors='replace')
 cands={anchor,anchor.split('.')[-1],anchor.replace('-',' '),anchor.replace('-','_')}
 return any(c and re.search(r'(?<![A-Za-z0-9_])'+re.escape(c)+r'(?![A-Za-z0-9_])',raw,re.I) for c in cands)

def main():
 errors=[]
 try:
  donors=read_csv('seventh-order-donors.csv'); dirs=read_csv('seventh-order-directories.csv'); surfaces=read_csv('seventh-order-surfaces.csv'); modules=read_csv('seventh-order-modules.csv'); symbols=read_csv('seventh-order-symbols.csv'); ledger=read_csv('seventh-order-adoption-ledger.csv'); sups=read_csv('seventh-order-supersession-map.csv'); baseline_rows=read_csv('seventh-order-baseline-files.csv'); delta_rows=read_csv('seventh-order-target-delta.csv')
 except Exception as e:
  print('seventh-order convergence:',e); return 1
 counts={'donors':len(donors),'directories':len(dirs),'surfaces':len(surfaces),'modules':len(modules),'symbols':len(symbols),'records':len(ledger),'supersession':len(sups),'baseline':len(baseline_rows)}
 for k,v in counts.items():
  if v!=EXPECTED[k]:errors.append(f'{k} count {v} != {EXPECTED[k]}')
 if sum(int(r['member_count']) for r in donors)!=EXPECTED['members']:errors.append('ZIP member denominator mismatch')
 if sum(int(r['file_surfaces']) for r in donors)!=EXPECTED['surfaces']:errors.append('surface rollup mismatch')
 if sum(int(r['directories']) for r in donors)!=EXPECTED['directories']:errors.append('directory rollup mismatch')
 if sum(int(r['symbols']) for r in donors)!=EXPECTED['symbols']:errors.append('symbol rollup mismatch')
 records={r['record_id']:r for r in ledger}
 if len(records)!=len(ledger):errors.append('duplicate ledger record ids')
 surface={(r['donor'],r['path']):r for r in surfaces}
 if len(surface)!=len(surfaces):errors.append('duplicate donor surface rows')
 for d in donors:
  if not HEX64.fullmatch(d.get('archive_sha256','')):errors.append(f"{d.get('donor')}: invalid archive hash")
  if d.get('archive_issues')!='none':errors.append(f"{d.get('donor')}: archive issues not closed: {d.get('archive_issues')}")
  for rid in refs(d.get('semantic_record_ids')):
   if rid not in records:errors.append(f"{d.get('donor')}: unknown record {rid}")
 for r in ledger:
  rid=r['record_id']
  if r.get('disposition') not in VALID_DISPOSITIONS:errors.append(f'{rid}: invalid disposition')
  if r.get('validation_status') not in VALID_STATUS:errors.append(f'{rid}: invalid validation status')
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
  if r.get('disposition') in {'inspired-native','recomposed','extracted','superseded','rejected-with-reason','hardened','adapted','adopted','guardrail-derived','synthesized'} and test=='n/a':errors.append(f'{rid}: non-reference disposition lacks discriminating evidence')
 for s in surfaces:
  if not HEX64.fullmatch(s.get('sha256','')):errors.append(f"surface {s.get('donor')}:{s.get('path')}: invalid hash")
  ids=refs(s.get('semantic_record_ids'))
  if not ids:errors.append(f"surface {s.get('donor')}:{s.get('path')}: unresolved")
  for rid in ids:
   if rid not in records:errors.append(f"surface {s.get('donor')}:{s.get('path')}: unknown {rid}")
 by_donor=defaultdict(list)
 for s in surfaces:by_donor[s['donor']].append(s)
 for d in dirs:
  prefix=d['path'].rstrip('/')+'/'
  desc=[s for s in by_donor[d['donor']] if s['path'].startswith(prefix)]
  direct=[s for s in desc if '/' not in s['path'][len(prefix):]]
  if len(desc)!=int(d['recursive_surface_count']):errors.append(f"dir {d['donor']}:{d['path']}: recursive count mismatch")
  if len(direct)!=int(d['direct_surface_count']):errors.append(f"dir {d['donor']}:{d['path']}: direct count mismatch")
  for rid in refs(d.get('semantic_record_ids')):
   if rid not in records:errors.append(f"dir {d['donor']}:{d['path']}: unknown {rid}")
 for m in modules:
  if not m.get('module_id') or not refs(m.get('semantic_record_ids')):errors.append(f"module {m.get('donor')}:{m.get('path')}: unresolved")
  for rid in refs(m.get('semantic_record_ids')):
   if rid not in records:errors.append(f"module {m.get('path')}: unknown {rid}")
 for s in symbols:
  if (s['donor'],s['path']) not in surface:errors.append(f"symbol path absent {s['donor']}:{s['path']}#{s['symbol']}")
  ids=refs(s.get('semantic_record_ids'))
  if not ids:errors.append(f"symbol unresolved {s['donor']}:{s['path']}#{s['symbol']}")
  for rid in ids:
   if rid not in records:errors.append(f"symbol {s['symbol']}: unknown {rid}")
 for sup in sups:
  if not sup.get('supersession_id') or not sup.get('target_winner') or not sup.get('reason'):errors.append('incomplete supersession row')
  for rid in refs(sup.get('seventh_order_record_ids')):
   if rid not in records:errors.append(f"{sup.get('supersession_id')}: unknown {rid}")

 # Exact sixth-order baseline -> current delta.
 baseline={}
 for r in baseline_rows:
  p=r['path'].strip()
  if not p or p in baseline:errors.append(f'duplicate/empty seventh baseline path {p!r}');continue
  if r['file_type'] not in {'file','symlink'} or not HEX64.fullmatch(r['sha256']):errors.append(f'seventh baseline {p}: invalid row')
  baseline[p]=(r['file_type'],r['sha256'],r['link_target'])
 current=scan_current(); expected={}
 for p in sorted(set(baseline)|set(current)):
  a,b=baseline.get(p),current.get(p)
  if a==b:continue
  if a is None:expected[p]=('added','n/a',b[1])
  elif b is None:expected[p]=('deleted',a[1],'n/a')
  else:expected[p]=('modified',a[1],b[1])
 delta={}
 for r in delta_rows:
  p=r['path'].strip()
  if not p or p in delta:errors.append(f'duplicate/empty seventh delta {p!r}');continue
  delta[p]=r; exp=expected.get(p)
  if exp is None:errors.append(f'seventh delta {p}: path not changed');continue
  got=(r.get('change_type'),r.get('sixth_order_sha256'),r.get('current_sha256'))
  if got!=exp:errors.append(f'seventh delta {p}: hash/change mismatch got={got} expected={exp}')
  for rid in refs(r.get('seventh_order_record_ids')):
   if rid not in records:errors.append(f'seventh delta {p}: unknown accountability {rid}')
  if not r.get('reason','').strip() or not r.get('accountability_class','').strip() or not r.get('verification_node','').strip():errors.append(f'seventh delta {p}: incomplete accountability')
  if r.get('verification_node')!='n/a' and not anchor_exists(r.get('verification_node')):errors.append(f"seventh delta {p}: missing verification anchor {r.get('verification_node')}")
 missing=sorted(set(expected)-set(delta)); extra=sorted(set(delta)-set(expected))
 if missing:errors.append(f'seventh target delta missing {len(missing)} paths: {missing[:20]}')
 if extra:errors.append(f'seventh target delta extra {len(extra)} paths: {extra[:20]}')

 # Live seventh-order feature invariants.
 def text(rel):return (ROOT/rel).read_text(encoding='utf-8',errors='replace')
 manager=text('src/apps/daemon/internal/runtime/runtimecore/manager.go'); ike=text('src/apps/daemon/internal/runtime/runtimecore/ikev2_engine.go'); routes=text('src/apps/daemon/internal/adapters/api/routes_system.go'); ops=text('src/packages/control-ui/src/pages/Operations.tsx'); pkg=text('src/packages/control-ui/package.json'); sixth=text('scripts/checks/check_sixth_order_convergence.py')
 for token in ['EngineIKEv2','normalizeIKEv2Request']:
  if token not in manager and token not in ike:errors.append(f'IKEv2 invariant missing {token}')
 for token in ['charon-cmd','ikev2-pub','--cert','--priv']:
  if token not in ike:errors.append(f'IKEv2 engine missing {token}')
 for route in ['/mesh-route-plan','/endpoint-pool-plan','/dns-tunnel-plan']:
  if route not in routes:errors.append(f'seventh planner route missing {route}')
 for marker in ['IKEv2 / strongSwan public-key profile','Network planning lab','Mesh route planner','Endpoint pool planner','DNS tunnel capacity']:
  if marker not in ops:errors.append(f'Operations missing {marker!r}')
 if 'test:seventh' not in pkg or 'test-seventh-order-promotions.mjs' not in pkg:errors.append('seventh UI characterization not wired')
 if 'seventh-order-baseline-files.csv' not in sixth or 'SUCCESSOR_BASELINE' not in sixth:errors.append('sixth-order checker lacks seventh successor baseline layering')
 if errors:
  print(f'seventh-order convergence: errors={len(errors)}')
  for e in errors[:220]:print('ERROR:',e)
  return 1
 print(f'seventh-order convergence: donors={len(donors)} members={EXPECTED["members"]} directories={len(dirs)} surfaces={len(surfaces)} modules={len(modules)} symbols={len(symbols)} records={len(ledger)} supersession={len(sups)} baseline={len(baseline_rows)} changes={len(delta_rows)} errors=0')
 return 0
if __name__=='__main__':raise SystemExit(main())
