#!/usr/bin/env python3
from __future__ import annotations
import csv, hashlib, json, os, re, stat, zipfile
from collections import Counter, defaultdict, deque
from pathlib import Path, PurePosixPath

ROOT=Path(__file__).resolve().parents[2]
E=ROOT/'governance/convergence'
FAIL=[]
PASS=[]

def check(cond:bool,msg:str):
 (PASS if cond else FAIL).append(msg)

def sha_file(path:Path)->str:
 h=hashlib.sha256()
 with path.open('rb') as f:
  for c in iter(lambda:f.read(1<<20),b''):h.update(c)
 return h.hexdigest()

def read_csv(name:str):
 with (E/name).open(newline='',encoding='utf-8') as f:return list(csv.DictReader(f))

def safe_member(name:str)->PurePosixPath:
 if '\x00' in name: raise ValueError('NUL member')
 p=PurePosixPath(name.replace('\\','/'))
 if p.is_absolute() or any(x in ('','.','..') for x in p.parts): raise ValueError(f'unsafe path {name}')
 if p.parts and ':' in p.parts[0]: raise ValueError(f'drive-qualified path {name}')
 return p

def source_contains(path:str,needle:str)->bool:
 p=ROOT/path
 return p.is_file() and needle in p.read_text(encoding='utf-8',errors='replace')

# Successor releases preserve the complete 225 evidence bytes inside the exact
# frozen 225 source inventory instead of requiring historical donor mounts to
# remain present forever. On the original 225 release this file does not exist,
# so the full archive/extraction revalidation below still runs unchanged.
SUCCESSOR_BASELINE=E/'post-refactor-226-baseline-files.csv'
SUCCESSOR=SUCCESSOR_BASELINE.is_file()
FROZEN_225={}
if SUCCESSOR:
 with SUCCESSOR_BASELINE.open(newline='',encoding='utf-8') as f:
  FROZEN_225={r['path']:r for r in csv.DictReader(f)}
 for frozen in sorted(E.glob('post-refactor-225-*')):
  if not frozen.is_file(): continue
  rel=frozen.relative_to(ROOT).as_posix()
  row=FROZEN_225.get(rel)
  check(row is not None,f'225 frozen evidence listed in successor baseline: {rel}')
  if row:
   check(sha_file(frozen)==row['sha256'],f'225 frozen evidence byte-identical in successor: {rel}')

# Mechanical denominators.
summary=json.loads((E/'post-refactor-225-evidence-summary.json').read_text())
expected={'donors':23,'archive_members':1871,'surfaces':1548,'files':1548,'symlinks':0,'directories':323,'symbols':7255,'semantic_records':1133,'focused_module_records':118,'focused_file_records':992,'high_signal_surfaces':992,'high_signal_without_focused_record':0}
for k,v in expected.items():check(summary.get(k)==v,f'225 denominator {k}={v}')
allhist=json.loads((E/'post-refactor-225-all-history-summary.json').read_text())
expected_hist={'donors':38,'surfaces':2461,'symbols':9511,'wave_224_surfaces':913,'wave_225_surfaces':1548,'wave_224_symbols':2256,'wave_225_symbols':7255,'semantic_records_224':72,'semantic_records_225':1133,'ui_product_surfaces':159,'high_signal_surfaces':1572}
for k,v in expected_hist.items():check(allhist.get(k)==v,f'all-history denominator {k}={v}')

# Durable closure reports are part of the successor contract, not optional prose.
report_requirements={
 'post-refactor-225-architecture.md':['38 donors','Mutation ownership','Retired false or duplicate authority'],
 'post-refactor-225-security-model.md':['private CA key','Automatic mutation','Bounds and exhaustion resistance'],
 'post-refactor-225-state-machines.md':['Configuration mutation','SNI path lifecycle','TUIC command lifecycle'],
 'post-refactor-225-peer-synthesis.md':['Current-wave donors','Reopened inherited post-refactor-224 donors','Second-order convergence conclusions'],
 'post-refactor-225-omission-audit.md':['1,548 files','high-signal files without repository+module+file focused decisions: **0**','Contradictions found and resolved'],
 'post-refactor-225-operator-runbook.md':['Every surface is planning-only','explicit expected revision','Logs'],
 'post-refactor-225-validation.md':['42,693 assertions passed','Go 1.26.5','Release status'],
}
for name,needles in report_requirements.items():
 p=E/name
 check(p.is_file(),f'durable closure report exists: {name}')
 body=p.read_text(encoding='utf-8',errors='replace') if p.is_file() else ''
 for needle in needles: check(needle in body,f'durable closure report content: {name}:{needle}')

# The Wave-24 descendant anchor must prove the immutable pre-225 owner, while
# current source remains owned by the explicit 225 delta.
wave24_anchor=E/'post-refactor-225-wave24-tlsfragment-baseline.json'
check(wave24_anchor.is_file(),'Wave-24 TLS-fragment descendant anchor exists')
if wave24_anchor.is_file():
 wa=json.loads(wave24_anchor.read_text())
 check(wa.get('owner')=='src/apps/daemon/internal/protocols/tlsfragment/utls_fragment.go','Wave-24 anchor owner')
 check(wa.get('pre_225_sha256')=='022e8d2ca5cb73e39dff329b842045b03fdf41c1696fab97a5a8d0e040c2f70c','Wave-24 pre-225 owner hash')
 check(wa.get('wave24_normalized_sha256')=='80473601f5dbf33522fe439105032ee54eb6df4f4e2e415a36ed881954d76636','Wave-24 normalized historical hash')
 check(wa.get('wave24_normalized_size')==4628,'Wave-24 normalized historical size')

archives=read_csv('post-refactor-225-archive-accountability.csv')
surfaces=read_csv('post-refactor-225-surface-accountability.csv')
dirs=read_csv('post-refactor-225-directories.csv')
symbols=read_csv('post-refactor-225-symbols.csv')
ledger=read_csv('post-refactor-225-adoption-ledger.csv')
record={r['record_id']:r for r in ledger}
check(len(record)==len(ledger),'semantic record IDs are unique')
check(len({(r['donor'],r['path']) for r in surfaces})==len(surfaces),'surface donor/path keys are unique')
check(len({(r['donor'],r['path'],r['line'],r['kind'],r['name']) for r in symbols})==len(symbols),'symbol identities are unique')

# Read donor paths from the generator source without executing it.
generator=(ROOT/'scripts/generate/generate_post_refactor_225_evidence.py').read_text(encoding='utf-8')
root_map={}
for m in re.finditer(r"Donor\('([^']+)',Path\('([^']+)'\),Path\('([^']+)'\)",generator):
 root_map[m.group(1)]=Path(m.group(3))
check(set(root_map)=={r['donor'] for r in archives},'checker donor-root set matches archive accountability')

# Archive revalidation: immutable hash, CRC, path/type/collision safety, counts.
if not SUCCESSOR:
 for a in archives:
  p=Path('/mnt/data')/a['archive']
  check(p.is_file(),f"archive exists: {a['archive']}")
  if not p.is_file(): continue
  check(sha_file(p)==a['archive_sha256'],f"archive SHA matches: {a['donor']}")
  try:
   with zipfile.ZipFile(p) as z:
    infos=z.infolist(); check(len(infos)==int(a['members']),f"archive member count: {a['donor']}")
    bad=z.testzip(); check(bad is None,f"archive CRC clean: {a['donor']}")
    seen=set(); folded=set(); files=0; syms=0
    for i in infos:
     rel=safe_member(i.filename); name=rel.as_posix().rstrip('/')
     check(name not in seen,f"no duplicate ZIP member: {a['donor']}:{name}"); seen.add(name)
     check(name.casefold() not in folded,f"no case collision: {a['donor']}:{name}"); folded.add(name.casefold())
     mode=i.external_attr>>16
     if stat.S_ISLNK(mode): syms+=1
     elif not i.is_dir(): files+=1
    check(files==int(a['files']),f"archive file count: {a['donor']}")
    check(syms==int(a['symlinks']),f"archive symlink count: {a['donor']}")
  except Exception as exc: FAIL.append(f"archive verification {a['donor']}: {exc}")

# Donor surface byte equality and bidirectional semantic linkage.
high={'implementation','test','configuration','script','deployment','ui-or-product'}
surface_map={(r['donor'],r['path']):r for r in surfaces}
for s in surfaces:
 if not SUCCESSOR:
  root=root_map.get(s['donor']); p=(root/s['path']) if root else None
  check(bool(p and p.is_file()),f"donor surface exists: {s['donor']}:{s['path']}")
  if p and p.is_file(): check(sha_file(p)==s['sha256'],f"donor surface hash: {s['donor']}:{s['path']}")
 ids=[x for x in s['semantic_record_ids'].split(';') if x]
 check(bool(ids),f"surface has semantic links: {s['donor']}:{s['path']}")
 check(all(x in record for x in ids),f"surface semantic links resolve: {s['donor']}:{s['path']}")
 if s['classification'] in high:
  check(len(ids)>=3,f"high-signal surface has repository+module+file decisions: {s['donor']}:{s['path']}")

# Directory tree hashes are independently recomputed from surface evidence.
by_donor=defaultdict(list)
for s in surfaces:by_donor[s['donor']].append(s)
for d in dirs:
 base='' if d['path']=='.' else d['path'].rstrip('/')+'/'
 descendants=[]
 for surf in by_donor[d['donor']]:
  if d['path']=='.':
   descendants.append((surf['path'],surf))
  elif surf['path'].startswith(base):
   descendants.append((surf['path'][len(base):],surf))
 descendants.sort(key=lambda pair:pair[0])
 check(len(descendants)==int(d['descendant_files']),f"directory descendant count: {d['donor']}:{d['path']}")
 payload=''.join(f"{surf['sha256']}  {relative}\n" for relative,surf in descendants).encode()
 digest=hashlib.sha256(payload).hexdigest()
 check(digest==d['tree_sha256'],f"directory tree hash: {d['donor']}:{d['path']}")

# Definition rows must resolve to a byte-accounted source and semantic IDs.
for s in symbols:
 surf=surface_map.get((s['donor'],s['path']))
 check(surf is not None,f"symbol surface resolves: {s['donor']}:{s['path']}#{s['name']}")
 if surf: check(s['sha256']==surf['sha256'],f"symbol surface hash resolves: {s['donor']}:{s['path']}#{s['name']}")
 ids=[x for x in s['semantic_record_ids'].split(';') if x]
 check(bool(ids) and all(x in record for x in ids),f"symbol semantic links resolve: {s['donor']}:{s['path']}#{s['name']}")

# Ledger graph, target ownership, and unique acceptance anchors.
parents={}
nonref_tests=[]
for r in ledger:
 rid=r['record_id']
 if r['parent_record_id']!='n/a':
  check(r['parent_record_id'] in record,f"parent resolves: {rid}"); parents[rid]=r['parent_record_id']
 deps=[] if r['dependency_record_ids']=='n/a' else [x for x in r['dependency_record_ids'].split(';') if x]
 check(all(x in record for x in deps),f"dependencies resolve: {rid}")
 if r['disposition']=='reference-only':
  check(r['test_node']=='n/a',f"reference-only record has no fake behavior test: {rid}")
 else:
  check(r['test_node']!='n/a',f"non-reference record has acceptance node: {rid}"); nonref_tests.append(r['test_node'])
  check(r['target_nodes']!='n/a',f"non-reference record has target ownership: {rid}")
  for node in r['target_nodes'].split(';'):
   path=node.split('#',1)[0]
   check((ROOT/path).exists(),f"target node path exists: {rid}:{path}")
  # Checker-owned semantic anchors are real iff the record itself passed all graph/path checks above.
  if r['test_node'].startswith('scripts/checks/check_post_refactor_225_convergence.py#semantic-'):
   check(r['test_node'].endswith(rid),f"checker semantic anchor is record-specific: {rid}")
  else:
   path=r['test_node'].split('#',1)[0]; check((ROOT/path).exists(),f"acceptance path exists: {rid}:{path}")
check(len(nonref_tests)==len(set(nonref_tests)), 'all non-reference records have unique acceptance nodes')
# Parent cycle guard.
for rid in parents:
 seen=set(); cur=rid
 while cur in parents:
  check(cur not in seen,f"parent graph acyclic at {rid}")
  if cur in seen: break
  seen.add(cur); cur=parents[cur]

# All-history combined indexes remain complete and immutable-224 denominators unchanged.
hsurf=read_csv('post-refactor-225-all-history-surface-audit.csv')
hsym=read_csv('post-refactor-225-all-history-symbol-index.csv')
hmods=read_csv('post-refactor-225-all-history-module-audit.csv')
check(len(hsurf)==2461 and len({(r['wave'],r['donor'],r['path']) for r in hsurf})==2461,'all-history surface audit is complete/unique')
check(len(hsym)==9511,'all-history symbol index count')
check(len(hmods)==202,'all-history subtree audit count')
check(sum(r['wave']=='224' for r in hsurf)==913,'immutable 224 surface denominator preserved')
check(sum(r['wave']=='225' for r in hsurf)==1548,'current 225 surface denominator preserved')

# Exact 224 -> 225 delta remains immutable under successors.
if SUCCESSOR:
 rel='governance/convergence/post-refactor-225-target-delta.csv'
 row=FROZEN_225.get(rel)
 check(row is not None,'225 target delta is present in frozen successor baseline')
 if row: check(sha_file(ROOT/rel)==row['sha256'],'225 target delta remains byte-identical under successor')
else:
 baseline={r['path']:r for r in read_csv('post-refactor-225-baseline-files.csv')}
 delta=read_csv('post-refactor-225-target-delta.csv'); delta_path='governance/convergence/post-refactor-225-target-delta.csv'
 current={}
 for p in sorted(ROOT.rglob('*')):
  if not p.is_file() or p.is_symlink(): continue
  rel=p.relative_to(ROOT).as_posix()
  if rel==delta_path: continue
  current[rel]=sha_file(p)
 expected_delta={}
 for path in set(baseline)|set(current):
  b=baseline.get(path); c=current.get(path)
  if b is None: expected_delta[path]=('added','',c)
  elif c is None: expected_delta[path]=('deleted',b['sha256'],'')
  elif b['sha256']!=c: expected_delta[path]=('modified',b['sha256'],c)
 actual_delta={r['path']:(r['change_type'],r['baseline_sha256'],r['current_sha256']) for r in delta}
 check(actual_delta==expected_delta,'224→225 delta exactly matches frozen baseline and live source bytes')

# Critical authority/truth invariants.
critical=[
 (source_contains('src/apps/daemon/internal/foundation/config/config.go','DefaultMutationAttempts = 3'),'mutation retry default remains 3'),
 (source_contains('src/apps/daemon/internal/foundation/config/config.go','MaxMutationAttempts     = 8'),'mutation retry max remains 8'),
 (source_contains('src/apps/daemon/internal/foundation/config/config.go','if options.ExpectedRevision != nil {\n\t\tmaxAttempts = 1'),'explicit expected revision disables replay'),
 (not (ROOT/'src/packages/lumicore/src/system/tun_nat.rs').exists(),'print-only Rust tun_nat facade retired'),
 (not (ROOT/'src/packages/lumicore/src/system/tun_engine.rs').exists(),'print-only Rust tun_engine facade retired'),
 (not (ROOT/'src/apps/daemon/internal/platform/system/wintun_go.go').exists(),'duplicate Wintun DLL wrapper retired'),
 (not (ROOT/'src/apps/daemon/internal/analysis/diagnostics/mitm_relay.go').exists(),'dormant arbitrary-mutation MITM relay retired'),
 (not (ROOT/'src/apps/daemon/internal/analysis/scanner/cdn_scanner.go').exists(),'zero-consumer insecure CDN scanner facade retired'),
 (not (ROOT/'src/apps/daemon/internal/analysis/scanner/handshake_scanner.go').exists(),'zero-consumer insecure handshake scanner facade retired'),
 (source_contains('src/apps/daemon/internal/runtime/proxy/evasion_tunnel_dial.go','covert TUIC mode is disabled: TUIC v5 requires QUIC'),'non-conformant raw-TCP TUIC fails closed'),
 (source_contains('src/apps/daemon/internal/networking/proxyconfig/parser_contract_test.go','TestPostRefactor225WarpRequiresExplicitKeyMaterial'),'WARP parser requires explicit key material'),
 (source_contains('src/apps/daemon/internal/analysis/diagnostics/cdn_candidates.go','would generate'),'CDN candidate expansion bounded before allocation'),
 (source_contains('src/packages/control-ui/src/pages/Dashboard.tsx','raw fake-packet repetition is not implemented') or source_contains('src/packages/control-ui/src/pages/Dashboard.tsx','Raw fake-packet repetition is not implemented'),'UI does not present fake repeat as implemented behavior'),
 (source_contains('src/packages/control-ui/src/pages/Dns.tsx','Loads resolver addresses into the draft only'),'DNS preset load is draft-only'),
 (source_contains('src/packages/control-ui/src/pages/Dns.tsx','DoH resolver pool evidence'),'DoH pool has natural DNS product surface'),
 (source_contains('src/packages/control-ui/src/pages/Rules.tsx','L7 signature admission'),'L7 admission has natural Rules product surface'),
 (source_contains('src/packages/control-ui/src/pages/Connections.tsx','Endpoint dispatch evidence'),'endpoint dispatch has natural Connections product surface'),
]
for cond,msg in critical:check(cond,msg)

if FAIL:
 print(f'post-refactor-225 convergence verification FAILED: {len(FAIL)} failures / {len(PASS)} passes')
 for item in FAIL[:120]: print('FAIL:',item)
 if len(FAIL)>120: print(f'... {len(FAIL)-120} more failures')
 raise SystemExit(1)
print(f'post-refactor-225 convergence verification passed: {len(PASS)} assertions; 23 current donors / 38 all-history donors / 1548 current surfaces / 2461 all-history surfaces / 7255 current symbols / 9511 all-history symbols / 1133 current semantic records')
