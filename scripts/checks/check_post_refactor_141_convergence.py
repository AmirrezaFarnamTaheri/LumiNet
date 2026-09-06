#!/usr/bin/env python3
from __future__ import annotations
import csv, hashlib, json, os, re
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
G=ROOT/'governance'/'convergence'; P='post-refactor-141'; DELTA_REL=f'governance/convergence/{P}-target-delta.csv'; SUCCESSOR_BASELINE=G/'post-refactor-160-baseline-files.csv'
EXPECTED={'donors':141,'surfaces':42277,'directories':7210,'modules':4789,'symbols':143859,'ledger':5126,'semantics':337,'licenses':141,'historical_resolutions':11,'historical_schema_normalizations':74,'repairs':13,'planes':23,'baseline_files':2724,'new_donors':4,'new_members':7491,'new_surfaces':6534,'new_directories':952,'new_modules':333,'new_symbols':38774,'new_symlinks':0,'new_semantics':53,'new_nested':92,'new_nested_members':10145,'strict_ledger':5126,'exact_overlap_surfaces':66}
NEW_DONORS={'geospoof-main','ZedSecure-main','i2p.i2p-master','metapi-main'}
FINAL_STATUS={'verified','statically-validated','reviewed'}
VALID_DISPOSITIONS={'adopted','adapted','hardened','extracted','recomposed','synthesized','inspired-native','guardrail-derived','superseded','rejected-with-reason','reference-only'}
HEX64=re.compile(r'^[0-9a-f]{64}$')
def read_csv(name):
 p=G/name
 if not p.is_file(): raise AssertionError(f'missing {p.relative_to(ROOT)}')
 with p.open(encoding='utf-8-sig',newline='') as f: return list(csv.DictReader(f))
def text(rel): return (ROOT/rel).read_text(encoding='utf-8',errors='replace')
def require(errs,cond,msg):
 if not cond: errs.append(msg)
def dig(p:Path):
 if p.is_symlink():
  t=os.readlink(p); return ('symlink',hashlib.sha256(t.encode()).hexdigest(),t)
 return ('file',hashlib.sha256(p.read_bytes()).hexdigest(),'n/a')
def scan_current():
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
  out[rel]=dig(p)
 return out
def anchor_exists(node):
 node=(node or '').strip()
 if not node or node=='n/a': return True
 if '#' not in node: return (ROOT/node).exists()
 rel,anchor=node.split('#',1); p=ROOT/rel
 if not p.is_file(): return False
 return anchor in p.read_text(encoding='utf-8',errors='replace')
def main():
 errors=[]
 try:
  donors=read_csv(f'{P}-donors.csv'); surfaces=read_csv(f'{P}-surfaces.csv'); dirs=read_csv(f'{P}-directories.csv'); modules=read_csv(f'{P}-modules.csv'); symbols=read_csv(f'{P}-symbols.csv'); ledger=read_csv(f'{P}-adoption-ledger.csv'); strict=read_csv(f'{P}-strict-adoption-ledger.csv'); licenses=read_csv(f'{P}-license-map.csv'); new_donors=read_csv(f'{P}-new-donors.csv'); new_surfaces=read_csv(f'{P}-new-surfaces.csv'); new_modules=read_csv(f'{P}-new-modules.csv'); nested=read_csv(f'{P}-nested-archives.csv'); resolutions=read_csv(f'{P}-historical-resolutions.csv'); normalizations=read_csv(f'{P}-historical-schema-normalizations.csv'); repairs=read_csv(f'{P}-target-repairs.csv'); planes=read_csv(f'{P}-high-level-plane-audit.csv'); baseline_rows=read_csv(f'{P}-baseline-files.csv'); delta_rows=read_csv(f'{P}-target-delta.csv'); overlap=read_csv(f'{P}-overlap-provenance.csv')
 except Exception as exc:
  print('post-refactor-141 convergence: load failure:',exc); return 1
 module_ids={r['module_id'] for r in modules}; ledger_ids={r['record_id'] for r in ledger}; fine=[r for r in ledger if r['record_id'] not in module_ids]; new_fine=[r for r in fine if r['record_id'].startswith('PR141-S')]
 counts={'donors':len(donors),'surfaces':len(surfaces),'directories':len(dirs),'modules':len(modules),'symbols':len(symbols),'ledger':len(ledger),'semantics':len(fine),'licenses':len(licenses),'historical_resolutions':len(resolutions),'historical_schema_normalizations':len(normalizations),'repairs':len(repairs),'planes':len(planes),'baseline_files':len(baseline_rows),'new_donors':len(new_donors),'new_surfaces':len(new_surfaces),'new_modules':len(new_modules),'strict_ledger':len(strict)}
 for k,v in counts.items(): require(errors,v==EXPECTED[k],f'{k} count {v} != {EXPECTED[k]}')
 waves=Counter(r['wave'] for r in donors)
 require(errors,waves==Counter({'ultimate-63':63,'post-refactor-20':20,'tor-wave-14':14,'post-refactor-20b':20,'post-refactor-20c':20,'post-refactor-4d':4}),f'donor wave mismatch {dict(waves)}')
 names=[r['donor'] for r in donors]; require(errors,len(set(names))==141,'duplicate donor identity')
 nd=[r for r in donors if r['wave']=='post-refactor-4d']; require(errors,{r['donor'] for r in nd}==NEW_DONORS,'new donor set mismatch')
 require(errors,sum(int(r['member_count']) for r in nd)==EXPECTED['new_members'],'new archive member denominator mismatch')
 require(errors,sum(int(r['file_surfaces']) for r in nd)==EXPECTED['new_surfaces'],'new surface rollup mismatch')
 require(errors,sum(int(r['directories']) for r in nd)==EXPECTED['new_directories'],'new directory rollup mismatch')
 require(errors,sum(int(r['symbols']) for r in nd)==EXPECTED['new_symbols'],'new symbol rollup mismatch')
 require(errors,sum(int(r['symlinks']) for r in nd)==EXPECTED['new_symlinks'],'new symlink rollup mismatch')
 require(errors,len(ledger_ids)==len(ledger),'duplicate ledger record id'); require(errors,module_ids<=ledger_ids,'module missing from ledger')
 require(errors,len(new_fine)==EXPECTED['new_semantics'],f'new semantic count {len(new_fine)} != {EXPECTED["new_semantics"]}')
 require(errors,{r['donor'] for r in new_fine}==NEW_DONORS,'not every new donor has fine disposition')
 require(errors,{r['validation_status'] for r in ledger}<=FINAL_STATUS,'non-final validation status remains')
 require(errors,all(r['disposition'] in VALID_DISPOSITIONS for r in ledger),'invalid disposition remains')
 require(errors,{r['record_id'] for r in strict}==ledger_ids and len(strict)==EXPECTED['strict_ledger'],'strict/canonical identity mismatch')
 require(errors,len({r['record_id'] for r in normalizations})==74,'historical normalization identity mismatch')
 sm={}
 for r in surfaces:
  key=(r['donor'],r['path']); require(errors,key not in sm,f'duplicate surface {key}'); sm[key]=r
  require(errors,bool(HEX64.fullmatch(r['sha256'])),f'invalid surface hash {key}')
  refs={x for x in r.get('semantic_record_ids','').split(';') if x}; require(errors,bool(refs),f'surface missing accountability {key}')
  for rid in refs: require(errors,rid in ledger_ids,f'surface {key} unknown record {rid}')
 require(errors,sum(1 for r in surfaces if r['wave']=='post-refactor-4d')==EXPECTED['new_surfaces'],'new combined surface mismatch')
 require(errors,sum(1 for r in surfaces if r['wave']=='post-refactor-4d' and r['file_type']=='symlink')==0,'unexpected outer symlink')
 for m in modules:
  require(errors,0<int(m['surface_count'])<=100,f'module {m["module_id"]}: invalid bound')
  sr=sm.get((m['donor'],m['representative_path'])); require(errors,sr is not None,f'module {m["module_id"]}: representative missing')
  if sr: require(errors,sr['sha256']==m['representative_sha256'],f'module {m["module_id"]}: hash mismatch')
 require(errors,sum(1 for r in modules if r['wave']=='post-refactor-4d')==EXPECTED['new_modules'],'new module count mismatch')
 require(errors,sum(1 for r in symbols if r['wave']=='post-refactor-4d')==EXPECTED['new_symbols'],'new symbol count mismatch')
 seen=set()
 for r in new_fine:
  sr=sm.get((r['donor'],r['donor_path'])); require(errors,sr is not None,f'{r["record_id"]}: donor surface missing')
  if sr: require(errors,sr['sha256']==r['donor_sha256'],f'{r["record_id"]}: donor hash mismatch')
  for node in [x for x in r.get('target_nodes','').split(';') if x and x!='n/a']: require(errors,anchor_exists(node),f'{r["record_id"]}: target anchor missing {node}')
  test=r.get('test_node','')
  if test and test!='n/a':
   require(errors,anchor_exists(test),f'{r["record_id"]}: test/decision anchor missing {test}')
   require(errors,test not in seen,f'{r["record_id"]}: duplicate current test anchor {test}'); seen.add(test)
  final=' '.join([r.get('disposition',''),r.get('decision_rationale',''),r.get('validation_status','')]); require(errors,not re.search(r'\b(pending|defer(?:red)?|implement later|future work|todo)\b',final,re.I),f'{r["record_id"]}: open-ended wording remains')
 # Live source invariant: direct peer IP is the default authority.
 router=text('src/apps/daemon/internal/adapters/api/router.go'); checker=text('scripts/checks/check_api_direct_client_ip.py')
 require(errors,'r.SetTrustedProxies(nil)' in router,'API trusted proxies are not disabled')
 require(errors,'failed to disable API trusted proxies' in router,'API proxy-trust setup is not fail-closed')
 require(errors,'api direct-client-ip trust' in checker,'direct-client-IP regression checker missing')
 mid=text('src/apps/daemon/internal/adapters/api/middleware.go'); require(errors,mid.count('c.ClientIP()')>=2,'expected rate-limit/log ClientIP consumers missing')
 # Restricted/mixed license donors are not directly reused.
 restricted={'ZedSecure-main','i2p.i2p-master'}
 for r in new_fine:
  if r['donor'] in restricted: require(errors,'direct reuse' not in r.get('transformation','').lower(),f'{r["record_id"]}: restricted donor direct reuse claimed')
 nn=[r for r in nested if r['wave']=='post-refactor-4d']
 require(errors,len(nn)==EXPECTED['new_nested'],f'new nested archive count {len(nn)}')
 require(errors,sum(int(r['members']) for r in nn)==EXPECTED['new_nested_members'],'nested member denominator mismatch')
 require(errors,all(r['issues']=='none' and int(r['symlinks'])==0 for r in nn),'nested archive safety issue remains')
 require(errors,sum(1 for r in overlap)==4,'overlap donor summary count mismatch')
 require(errors,sum(int(x.split()[0]) for x in [r['evidence'] for r in overlap])==EXPECTED['exact_overlap_surfaces'],'exact overlap denominator mismatch')
 summary=json.loads((G/f'{P}-summary.json').read_text())
 for k,v in EXPECTED.items():
  if k in summary: require(errors,int(summary[k])==v,f'summary {k} mismatch')
 require(errors,int(summary.get('exact_overlap_surfaces',-1))==EXPECTED['exact_overlap_surfaces'],'summary overlap mismatch')
 # Exact successor delta from immutable 137 baseline.
 baseline={r['path']:(r['file_type'],r['sha256'],r['link_target']) for r in baseline_rows}; current=scan_current(); expected={}
 for path in sorted(set(baseline)|set(current)):
  b,a=baseline.get(path),current.get(path)
  if b==a: continue
  if b is None: expected[path]=('added','n/a',a[1])
  elif a is None: expected[path]=('deleted',b[1],'n/a')
  else: expected[path]=('modified',b[1],a[1])
 delta={}
 for r in delta_rows:
  p=r['path'].strip(); require(errors,p and p not in delta,f'duplicate/empty delta path {p!r}'); delta[p]=r; exp=expected.get(p); require(errors,exp is not None,f'delta {p}: not changed')
  if exp: require(errors,(r['change_type'],r['baseline_sha256'],r['current_sha256'])==exp,f'delta {p}: mismatch')
  require(errors,bool(r.get('reason','').strip()),f'delta {p}: reason missing')
 missing=sorted(set(expected)-set(delta)); extra=sorted(set(delta)-set(expected))
 if missing: errors.append(f'delta missing {len(missing)} paths: {missing[:100]}')
 if extra: errors.append(f'delta extra {len(extra)} paths: {extra[:100]}')
 make=text('Makefile')
 for ck in ['check_post_refactor_83_convergence.py','check_post_refactor_97_convergence.py','check_post_refactor_117_convergence.py','check_post_refactor_137_convergence.py','check_post_refactor_141_convergence.py','check_api_direct_client_ip.py']: require(errors,ck in make,f'Makefile missing gate {ck}')
 require(errors,'post-refactor-141-baseline-files.csv' in text('scripts/checks/check_post_refactor_137_convergence.py'),'137 historical checker not frozen at 141 baseline')
 require(errors,len(resolutions)==11,'historical resolution layer changed')
 if errors:
  print(f'post-refactor-141 convergence: donors={len(donors)} surfaces={len(surfaces)} modules={len(modules)} symbols={len(symbols)} semantics={len(fine)} records={len(ledger)} delta={len(delta_rows)} errors={len(errors)}')
  for e in errors[:500]: print('ERROR:',e)
  return 1
 print(f'post-refactor-141 convergence: donors={len(donors)} waves=63+20+14+20+20+4 surfaces={len(surfaces)} directories={len(dirs)} modules={len(modules)} symbols={len(symbols)} semantics={len(fine)} records={len(ledger)} nested_new={len(nn)} delta={len(delta_rows)} errors=0')
 return 0
if __name__=='__main__': raise SystemExit(main())
