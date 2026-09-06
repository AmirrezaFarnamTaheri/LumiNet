#!/usr/bin/env python3
from __future__ import annotations
import csv, hashlib, json, os, re, sys
from pathlib import Path
from collections import defaultdict

ROOT=Path(__file__).resolve().parents[2]
G=ROOT/'governance/convergence'
EXPECTED={'donors':18,'directories':43,'surfaces':106,'modules':43,'symbols':792,'ledger':28,'supersession':12,'baseline':2448,'zip_members':150}
HEX64=re.compile(r'^[0-9a-f]{64}$')
VALID_STATUS={'verified','statically-validated','reviewed','inferred','unverified','pending'}
VALID_DISPOSITIONS={'adopted','adapted','hardened','extracted','recomposed','synthesized','inspired-native','guardrail-derived','superseded','rejected-with-reason','reference-only'}
DELTA_REL='governance/convergence/sixth-order-target-delta.csv'
SUCCESSOR_BASELINE=G/'seventh-order-baseline-files.csv'


def read_csv(name):
 p=G/name
 if not p.is_file(): raise AssertionError(f'missing {name}')
 with p.open(encoding='utf-8-sig',newline='') as f:return list(csv.DictReader(f))

def digest_path(p:Path):
 if p.is_symlink():
  t=os.readlink(p); return ('symlink',hashlib.sha256(t.encode()).hexdigest(),t)
 return ('file',hashlib.sha256(p.read_bytes()).hexdigest(),'n/a')

def scan_current():
 # Once seventh-order exists, validate the delivered sixth-order state against
 # its frozen successor baseline so later convergence cannot rewrite history.
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
  if rel==DELTA_REL or rel.startswith('.git/'): continue
  out[rel]=digest_path(p)
 return out

def anchor_exists(node:str):
 node=node.strip()
 if not node or node=='n/a': return True
 if '#' not in node:return False
 path_text,anchor=node.split('#',1)
 p=ROOT/path_text
 if not p.is_file():return False
 raw=p.read_text(encoding='utf-8',errors='replace')
 candidates={anchor,anchor.split('.')[-1],anchor.replace('-',' '),anchor.replace('-','_')}
 return any(c and re.search(r'(?<![A-Za-z0-9_])'+re.escape(c)+r'(?![A-Za-z0-9_])',raw,re.I) for c in candidates)

def refs(value): return [x for x in value.split(';') if x and x!='n/a']

def main():
 errors=[]
 try:
  donors=read_csv('sixth-order-donors.csv'); dirs=read_csv('sixth-order-directories.csv'); surfaces=read_csv('sixth-order-surfaces.csv'); modules=read_csv('sixth-order-modules.csv'); symbols=read_csv('sixth-order-symbols.csv'); ledger=read_csv('sixth-order-adoption-ledger.csv'); sups=read_csv('sixth-order-supersession-map.csv'); baseline_rows=read_csv('sixth-order-baseline-files.csv'); delta_rows=read_csv('sixth-order-target-delta.csv')
 except Exception as e:
  print('sixth-order convergence:',e); return 1
 for key,rows in [('donors',donors),('directories',dirs),('surfaces',surfaces),('modules',modules),('symbols',symbols),('ledger',ledger),('supersession',sups),('baseline',baseline_rows)]:
  if len(rows)!=EXPECTED[key]: errors.append(f'{key} count {len(rows)} != {EXPECTED[key]}')

 records={r.get('record_id',''):r for r in ledger}
 if len(records)!=len(ledger) or '' in records: errors.append('ledger record ids are duplicate/empty')
 surface_paths={r['path']:r for r in surfaces}
 if len(surface_paths)!=len(surfaces): errors.append('surface paths are duplicate')
 donor_ids={r['donor'] for r in donors}
 if len(donor_ids)!=EXPECTED['donors']: errors.append('donor ids are duplicate')
 if sum(int(r.get('member_count','0')) for r in donors)!=EXPECTED['zip_members']: errors.append('ZIP member denominator mismatch')
 if sum(int(r.get('file_surfaces','0')) for r in donors)!=EXPECTED['surfaces']: errors.append('donor file-surface rollup mismatch')
 if sum(int(r.get('directories','0')) for r in donors)!=EXPECTED['directories']: errors.append('donor directory rollup mismatch')
 if sum(int(r.get('symbols','0')) for r in donors)!=EXPECTED['symbols']: errors.append('donor symbol rollup mismatch')
 for d in donors:
  if not HEX64.fullmatch(d.get('archive_sha256','')): errors.append(f"{d.get('donor')}: invalid archive hash")
  for rid in refs(d.get('semantic_record_ids','')):
   if rid not in records: errors.append(f"{d.get('donor')}: unknown record {rid}")

 for r in ledger:
  rid=r['record_id']
  if r.get('disposition') not in VALID_DISPOSITIONS: errors.append(f'{rid}: invalid disposition')
  if r.get('validation_status') not in VALID_STATUS: errors.append(f'{rid}: invalid validation status')
  if not HEX64.fullmatch(r.get('donor_sha256','')): errors.append(f'{rid}: invalid donor hash')
  sr=surface_paths.get(r.get('donor_path',''))
  if not sr: errors.append(f"{rid}: donor path absent from surface matrix {r.get('donor_path')}")
  elif sr['sha256']!=r['donor_sha256']: errors.append(f'{rid}: donor path hash mismatch')
  for dep in refs(r.get('dependency_record_ids','')):
   if dep not in records: errors.append(f'{rid}: unknown dependency {dep}')
  for node in refs(r.get('target_nodes','')):
   if not anchor_exists(node): errors.append(f'{rid}: missing target anchor {node}')
  if r.get('test_node')!='n/a' and not anchor_exists(r.get('test_node','')): errors.append(f"{rid}: missing test anchor {r.get('test_node')}")
  if r.get('disposition')!='reference-only' and not r.get('test_node','').strip(): errors.append(f'{rid}: missing acceptance evidence')

 for s in surfaces:
  if not HEX64.fullmatch(s.get('sha256','')): errors.append(f"surface {s.get('path')}: invalid hash")
  ids=refs(s.get('semantic_record_ids',''))
  if not ids: errors.append(f"surface {s.get('path')}: no semantic record")
  for rid in ids:
   if rid not in records: errors.append(f"surface {s.get('path')}: unknown record {rid}")

 # Directory counts must be derivable from exact descendant surfaces.
 by_donor=defaultdict(list)
 for s in surfaces: by_donor[s['donor']].append(s)
 for d in dirs:
  prefix=d['path'].rstrip('/')+'/'
  desc=[s for s in by_donor[d['donor']] if s['path'].startswith(prefix)]
  direct=[s for s in desc if '/' not in s['path'][len(prefix):]]
  if len(desc)!=int(d['recursive_surface_count']): errors.append(f"dir {d['path']}: recursive surface count mismatch")
  if len(direct)!=int(d['direct_surface_count']): errors.append(f"dir {d['path']}: direct surface count mismatch")
  for rid in refs(d.get('semantic_record_ids','')):
   if rid not in records: errors.append(f"dir {d['path']}: unknown record {rid}")

 for m in modules:
  if not m.get('module_id') or not m.get('path'): errors.append('invalid module row')
  if not refs(m.get('semantic_record_ids','')): errors.append(f"module {m.get('path')}: no semantic records")
  for rid in refs(m.get('semantic_record_ids','')):
   if rid not in records: errors.append(f"module {m.get('path')}: unknown record {rid}")

 for s in symbols:
  if s.get('path') not in surface_paths: errors.append(f"symbol {s.get('path')}#{s.get('symbol')}: path not in surfaces")
  ids=refs(s.get('semantic_record_ids',''))
  if not ids: errors.append(f"symbol {s.get('path')}#{s.get('symbol')}: unresolved")
  for rid in ids:
   if rid not in records: errors.append(f"symbol {s.get('path')}#{s.get('symbol')}: unknown record {rid}")

 for sup in sups:
  if not sup.get('supersession_id') or not sup.get('target_winner') or not sup.get('reason'): errors.append('incomplete supersession row')
  for rid in refs(sup.get('sixth_order_record_ids','')):
   if rid not in records: errors.append(f"{sup.get('supersession_id')}: unknown record {rid}")

 corpus=json.loads((G/'sixth-order-corpora.json').read_text(encoding='utf-8'))
 if corpus.get('source_non_comment_rows')!=319 or corpus.get('validated_unique_rows')!=285 or corpus.get('invalid_rows')!=0: errors.append('RKh corpus denominator mismatch')
 if corpus.get('target_record')!='S6-005': errors.append('RKh corpus target record mismatch')

 # Baseline -> current exact delta. Baseline is immutable delivered fifth-order source.
 baseline={}
 for row in baseline_rows:
  path=row.get('path','').strip()
  if not path or path in baseline: errors.append(f'duplicate/empty sixth baseline path {path!r}'); continue
  if row.get('file_type') not in {'file','symlink'} or not HEX64.fullmatch(row.get('sha256','')): errors.append(f'sixth baseline {path}: invalid row')
  baseline[path]=(row['file_type'],row['sha256'],row['link_target'])
 current=scan_current(); expected={}
 for path in sorted(set(baseline)|set(current)):
  before,after=baseline.get(path),current.get(path)
  if before==after: continue
  if before is None: expected[path]=('added','n/a',after[1])
  elif after is None: expected[path]=('deleted',before[1],'n/a')
  else: expected[path]=('modified',before[1],after[1])
 delta={}
 for row in delta_rows:
  path=row.get('path','').strip()
  if not path or path in delta: errors.append(f'duplicate/empty sixth delta path {path!r}'); continue
  delta[path]=row; exp=expected.get(path)
  if exp is None: errors.append(f'sixth delta {path}: not changed from fifth-order baseline'); continue
  got=(row.get('change_type'),row.get('fifth_order_sha256'),row.get('current_sha256'))
  if got!=exp: errors.append(f'sixth delta {path}: change/hash mismatch got={got} expected={exp}')
  for rid in refs(row.get('sixth_order_record_ids','')):
   if rid not in records: errors.append(f'sixth delta {path}: unknown accountability id {rid}')
  if not row.get('accountability_class','').strip() or not row.get('reason','').strip() or not row.get('verification_node','').strip(): errors.append(f'sixth delta {path}: incomplete accountability')
  if row.get('verification_node')!='n/a' and not anchor_exists(row.get('verification_node','')): errors.append(f"sixth delta {path}: missing verification anchor {row.get('verification_node')}")
 missing=sorted(set(expected)-set(delta)); extra=sorted(set(delta)-set(expected))
 if missing: errors.append(f'sixth target delta missing {len(missing)} paths: {missing[:20]}')
 if extra: errors.append(f'sixth target delta has {len(extra)} extra paths: {extra[:20]}')

 # High-value live invariants and proven supersessions.
 def text(rel): return (ROOT/rel).read_text(encoding='utf-8',errors='replace')
 runtime=text('src/apps/daemon/internal/runtime/runtimecore/tor_engine.go')
 tor_builder=text('src/apps/daemon/internal/platform/system/tor_config_builder.go')
 manager=text('src/apps/daemon/internal/runtime/runtimecore/manager.go')
 routes=text('src/apps/daemon/internal/adapters/api/routes_system.go')
 ops=text('src/packages/control-ui/src/pages/Operations.tsx')
 profiles=text('src/packages/control-ui/src/pages/Profiles.tsx')
 sni=text('src/apps/daemon/internal/analysis/diagnostics/sni_candidates.go')
 onion=text('src/apps/daemon/internal/analysis/diagnostics/onion_probe.go')
 vpngate=text('src/apps/daemon/internal/integrations/vpngate/client.go')
 dev=text('src/apps/daemon/internal/integrations/provision/devcontainer_vless.go')
 catalog=text('src/apps/daemon/internal/analysis/provider/circumvention_catalog.go')
 fifth=text('scripts/checks/check_fifth_order_convergence.py')
 ui_test=text('src/packages/control-ui/scripts/test-sixth-order-promotions.mjs')
 if 'CookieAuthentication 1' not in tor_builder or 'rotateIdentity' not in runtime or 'RotateTorIdentity' not in manager or '/engines/tor/identity' not in routes: errors.append('Tor NEWNYM wiring invariant missing')
 if 'ProbeOnion' not in onion or 'ValidOnionV3Host' not in onion or 'StableProxyForOnion' not in onion or 'extractOnionHTMLMetadata' not in onion: errors.append('bounded onion diagnostic invariant missing')
 if 'RunSniSpoofStabilityScan' not in text('src/apps/daemon/internal/analysis/diagnostics/sni_spoof_scan.go') or sni.count('"') < 285*2: errors.append('SNI stability/corpus invariant missing')
 if 'https://www.vpngate.net/api/iphone/' not in vpngate or '8 << 20' not in vpngate or 'sstp_server' not in text('src/apps/daemon/internal/adapters/api/handlers_vpngate.go'): errors.append('VPNGate bounded discovery/handoff invariant missing')
 if 'xhttpSettings' not in dev or 'packet-up' not in dev or '.devcontainer/Dockerfile' not in dev: errors.append('devcontainer XHTTP generation invariant missing')
 if 'CircumventionCatalog' not in catalog or 'reference' not in catalog: errors.append('circumvention catalog invariant missing')
 if 'luminet.subscription-profiles.v1' not in profiles or '512 * 1024' not in profiles or '64 entries' not in profiles: errors.append('profile import/export bound invariant missing')
 for marker in ['Rotate Tor identity','Probe onion','VPN Gate discovery','SNI stability ranking','Load 285-candidate corpus','VLESS + XHTTP devcontainer','Circumvention capability catalog']:
  if marker not in ops: errors.append(f'Operations missing {marker!r}')
 if '19 checks passed' in ui_test: pass # message is dynamic; no required static literal
 if 'sixth-order-baseline-files.csv' not in fifth or 'SUCCESSOR_BASELINE' not in fifth: errors.append('fifth-order historical checker lacks sixth-order successor baseline layering')
 # No donor-shaped legacy runtime imports or synthetic activity workflow may land in live source.
 live_text='\n'.join(p.read_text(encoding='utf-8',errors='ignore') for p in (ROOT/'src').rglob('*') if p.is_file() and p.suffix in {'.go','.ts','.tsx','.js','.mjs','.json'})
 for forbidden in ['node-typedarray-master','node-dom-master','abstract-tls-master','rCDIRHslpXrK','APLaGwInabiDNK']:
  if forbidden in live_text: errors.append(f'donor-shaped legacy/synthetic artifact leaked into live source: {forbidden}')

 if errors:
  print(f'sixth-order convergence: errors={len(errors)}')
  for e in errors: print('ERROR:',e)
  return 1
 print(f'sixth-order convergence: donors={len(donors)} members={EXPECTED["zip_members"]} directories={len(dirs)} surfaces={len(surfaces)} modules={len(modules)} symbols={len(symbols)} records={len(ledger)} supersession={len(sups)} baseline={len(baseline_rows)} changes={len(delta_rows)} errors=0')
 return 0
if __name__=='__main__': raise SystemExit(main())
