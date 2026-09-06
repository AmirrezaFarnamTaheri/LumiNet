#!/usr/bin/env python3
"""Independent verification for the post-refactor-230 thirteen-donor convergence wave."""
from __future__ import annotations
import csv, hashlib, json, os, stat, sys, zipfile
from collections import defaultdict
from pathlib import Path, PurePosixPath
ROOT=Path(os.environ.get('LUMINET_230_TARGET_ROOT',Path(__file__).resolve().parents[2]))
WORK=Path(os.environ.get('LUMINET_230_WORK_ROOT','/mnt/data/luminet230_work'))
DONOR_BASE=WORK/'donors'; E=ROOT/'governance/convergence'; BASE=E/'post-refactor-230-baseline-files.csv'
HIGH={'implementation','ui-or-product','configuration','deployment','script','test'}
assertions=0; errors=[]
def check(c,msg):
 global assertions; assertions+=1
 if not c: errors.append(msg)
def sha_file(p):
 h=hashlib.sha256()
 with Path(p).open('rb') as f:
  for b in iter(lambda:f.read(1<<20),b''):h.update(b)
 return h.hexdigest()
def readcsv(name):
 with (E/name).open(newline='',encoding='utf-8') as f:return list(csv.DictReader(f))
def text(p): return (ROOT/p).read_text(encoding='utf-8',errors='replace')
def normalized_member(name):
 p=PurePosixPath(name.replace('\\','/'))
 if p.is_absolute() or any(x in {'','.', '..'} for x in p.parts) or (p.parts and ':' in p.parts[0]): raise ValueError(name)
 return p
SUCCESSOR_231=E/'post-refactor-231-baseline-files.csv'
if SUCCESSOR_231.is_file():
 check(sha_file(SUCCESSOR_231)=='a651ade4b116a3b940adbf5d8a42bf5eee5ea99dab9a1d62ab3603e5f8a99fa7','231 embeds exact released 230 source inventory')
 with SUCCESSOR_231.open(newline='',encoding='utf-8') as f: successor_rows=list(csv.DictReader(f))
 check(len(successor_rows)==3186,'230 frozen inventory has 3186 files')
 frozen=[r for r in successor_rows if r['path'].startswith('governance/convergence/post-refactor-230-')]
 check(len(frozen)==23,'23 frozen post-refactor-230 governance artifacts')
 for r in frozen:
  q=ROOT/r['path'];check(q.is_file(),f'230 frozen artifact exists {r["path"]}')
  if q.is_file():
   check(sha_file(q)==r['sha256'],f'230 frozen artifact hash {r["path"]}')
   check(str(q.stat().st_size)==r['size_bytes'],f'230 frozen artifact size {r["path"]}')
   check(oct(stat.S_IMODE(q.stat().st_mode))==r['mode'],f'230 frozen artifact mode {r["path"]}')
 frozen_summary=json.loads((E/'post-refactor-230-evidence-summary.json').read_text())
 for k,v in {'outer_donors':13,'surfaces':5001,'definitions':20744,'module_records':554,'semantic_value_records':38,'unresolved_high_signal_surfaces':0}.items():check(frozen_summary.get(k)==v,f'230 frozen summary {k}')
 print(f'post-refactor-230 successor evidence: assertions={assertions} errors={len(errors)}')
 if errors:
  for e in errors:print('ERROR',e)
  sys.exit(1)
 sys.exit(0)

required=['post-refactor-230-archive-accountability.csv','post-refactor-230-surface-accountability.csv','post-refactor-230-directories.csv','post-refactor-230-symbols.csv','post-refactor-230-symlinks.csv','post-refactor-230-module-audit.csv','post-refactor-230-adoption-ledger.csv','post-refactor-230-supersession-map.csv','post-refactor-230-evidence-summary.json','post-refactor-230-baseline-files.csv','post-refactor-230-target-delta.csv','post-refactor-230-all-history-surface-audit.csv','post-refactor-230-all-history-symbol-index.csv','post-refactor-230-all-history-module-audit.csv','post-refactor-230-all-history-summary.json','post-refactor-230-architecture.md','post-refactor-230-security-model.md','post-refactor-230-state-machines.md','post-refactor-230-peer-synthesis.md','post-refactor-230-omission-audit.md','post-refactor-230-operator-runbook.md','post-refactor-230-validation.md','post-refactor-230-all-history-second-order-audit.md']
for n in required:check((E/n).is_file(),f'missing evidence {n}')
if errors:
 print('\n'.join(errors));sys.exit(1)
summary=json.loads((E/'post-refactor-230-evidence-summary.json').read_text())
expected={'outer_donors':13,'archive_members':7165,'surfaces':5001,'directories':2094,'definitions':20744,'symlinks':67,'module_records':554,'high_signal_surfaces':2742,'ui_product_surfaces':432,'semantic_value_records':38,'repository_records':13,'file_records':5001,'ledger_records':5606,'baseline_files':3151,'unresolved_high_signal_surfaces':0}
for k,v in expected.items():check(summary.get(k)==v,f'summary {k}: {summary.get(k)!r} != {v!r}')
check(sha_file(BASE)=='29cf2a4a936b8c3940a0e8576b3bbdd41617d905ca92d37f3a9cb8cc30ae33fa','exact released 229 inventory embedded')
# Archive admission and member-level safety.
arch=readcsv('post-refactor-230-archive-accountability.csv');check(len(arch)==13,'13 archives')
arch_by={r['archive']:r for r in arch};check(len(arch_by)==13,'archive keys unique')
expected_arch={
'mitmengine-master.zip':'d1a9ea21875e190cd181897bde798331188a9aefe20f7afaf302cc68e6d64dc5','mitmproxy-main.zip':'b8a42c63f91b582990141dc8f74a5e277764d281fc661ae95e85ac5cc966aa13','bine-master.zip':'f571052cfed13b8032121ec3d85b0c5df7f208e59fa029d003df7b31c34cec97','bridgedb-main.zip':'b1abc2c56f8a96f2b0f302d9147d2113d04781129a4293f9e7713621aa9fd9c2','conjure-master.zip':'658565c2f5fa55e41810da054f78a90020acaae0f9863ae27cd66042e1f18c78','Hiddify-Manager-dev.zip':'dfa1dfaecb42ef8b04ec48b54e207cbe4e082ee880da48c860aafcfde7532243','probe-legacy-master.zip':'66e5676c0b81c52aef24cc0b3bcf6d321dea54cea6126a4fa7109b437ae0901d','SenPaiScanner-main.zip':'3f708ac72487af2b371921c518f8f19cc787c3b04b4ff09f820d320bb0a73898','qjs-master.zip':'7f7fcd3df74b6852409f981ee1843d636ab2510af2d99eeaf939ea082d5bb414','IPScanner-main.zip':'d1e82df93853ea95d2d31128c798363be91c0a271a0eba2267a549d5a42cc7d1','pion-dtls-main.zip':'3035dad0ce47887a418fac5e629386daf9745ff3ef7d604444457128fb3400b6','smux-master.zip':'ae284ba2680853fef33e276c0d23628df03e623bbe6fe0b9183875c54b0aa525','NoMoreWalls-master.zip':'842ef8b67824c3ea720198985d8f24f8e7a1b78ab5455ea01d0ea4bb925c841c'}
for name,digest in expected_arch.items():
 p=Path('/mnt/data')/name; row=arch_by.get(name);check(row is not None,f'archive evidence {name}');check(p.is_file(),f'archive exists {name}')
 if not p.is_file() or row is None:continue
 check(sha_file(p)==digest==row['sha256'],f'archive hash {name}')
 with zipfile.ZipFile(p) as z:
  check(z.testzip() is None,f'CRC {name}'); infos=z.infolist(); check(len(infos)==int(row['members']),f'member count {name}')
  seen=set();fold=set();files=dirs=links=0;total=0
  for info in infos:
   try: rel=normalized_member(info.filename)
   except ValueError: check(False,f'unsafe member {name}:{info.filename}');continue
   key=rel.as_posix().rstrip('/'); check(key not in seen,f'duplicate {name}:{key}');check(key.casefold() not in fold,f'case collision {name}:{key}');seen.add(key);fold.add(key.casefold());check(not(info.flag_bits&1),f'encrypted {name}:{key}')
   mode=info.external_attr>>16; kind=stat.S_IFMT(mode); islink=stat.S_ISLNK(mode)
   check(kind in {0,stat.S_IFREG,stat.S_IFDIR,stat.S_IFLNK},f'special member {name}:{key}')
   if islink:links+=1
   elif info.is_dir():dirs+=1
   else:files+=1
   total+=info.file_size
   if info.compress_size:check(info.file_size/info.compress_size<=1000.0,f'compression ratio {name}:{key}')
  check(files==int(row['regular_files']),f'file count {name}');check(dirs==int(row['directories']),f'dir count {name}');check(links==int(row['symlinks']),f'symlink count {name}');check(total==int(row['uncompressed_bytes']),f'uncompressed bytes {name}')
# Exact file bytes and normalized symlink evidence.
surfs=readcsv('post-refactor-230-surface-accountability.csv');check(len(surfs)==5001,'5001 surfaces');by={(r['donor'],r['path']):r for r in surfs};check(len(by)==5001,'surface keys unique')
for r in surfs:
 p=DONOR_BASE/r['donor']/r['donor']/r['path'];check(p.is_file(),f'donor file exists {r["donor"]}:{r["path"]}')
 if p.is_file():check(str(p.stat().st_size)==r['size_bytes'],f'size {r["donor"]}:{r["path"]}');check(sha_file(p)==r['sha256'],f'hash {r["donor"]}:{r["path"]}')
 check(r['semantic_record_ids']!='',f'surface backlinks {r["donor"]}:{r["path"]}');check(r['post_refactor_230_disposition'] not in {'','pending','unresolved'},f'disposition {r["donor"]}:{r["path"]}')
 if r['classification'] in HIGH:check('PR230-F' in r['semantic_record_ids'] and 'PR230-M' in r['semantic_record_ids'],f'high-signal ownership {r["donor"]}:{r["path"]}')
links=readcsv('post-refactor-230-symlinks.csv');check(len(links)==67,'67 symlinks');check(all(r['materialized']=='false' for r in links),'all archive symlinks nonmaterialized')
# Recompute normalized Merkle index independently from current donor bytes and symlink target evidence.
link_by=defaultdict(list)
for r in links:link_by[r['donor']].append(r)
rows_by=defaultdict(list)
for r in surfs:rows_by[r['donor']].append(r)
def merkle_for(donor,directory):
 prefix='' if directory=='.' else directory+'/'
 desc=[r for r in rows_by[donor] if directory=='.' or r['path'].startswith(prefix)]
 sl=[r for r in link_by[donor] if directory=='.' or r['path'].startswith(prefix)]
 h=hashlib.sha256()
 for r in sorted(desc,key=lambda x:x['path']):h.update(b'F\0'+r['path'].encode()+b'\0'+r['sha256'].encode()+b'\0'+r['size_bytes'].encode()+b'\n')
 for r in sorted(sl,key=lambda x:x['path']):h.update(b'L\0'+r['path'].encode()+b'\0'+r['target'].encode(errors='replace')+b'\0'+r['target_bytes_sha256'].encode()+b'\n')
 allpaths=[r['path'] for r in rows_by[donor]]+[r['path'] for r in link_by[donor]]
 direct_files=sum(1 for p in allpaths if p.startswith(prefix) and '/' not in p[len(prefix):])
 dirs=set()
 for p in allpaths:
  parts=p.split('/')[:-1]
  for i in range(1,len(parts)+1):dirs.add('/'.join(parts[:i]))
 child=set()
 for d in dirs:
  if d==directory:continue
  if directory=='.':
   if '/' not in d:child.add(d)
  elif d.startswith(prefix) and '/' not in d[len(prefix):]:child.add(d)
 return h.hexdigest(),direct_files,len(child),len(desc),len(sl)
dirs=readcsv('post-refactor-230-directories.csv');check(len(dirs)==2094,'2094 directory records');dirkeys={(r['donor'],r['directory']) for r in dirs};check(len(dirkeys)==2094,'directory keys unique')
for r in dirs:
 got=merkle_for(r['donor'],r['directory']);check(got[0]==r['tree_sha256'],f'merkle {r["donor"]}:{r["directory"]}');check(str(got[1])==r['direct_files'],f'direct files {r["donor"]}:{r["directory"]}');check(str(got[2])==r['direct_dirs'],f'direct dirs {r["donor"]}:{r["directory"]}');check(str(got[3])==r['descendant_files'],f'desc files {r["donor"]}:{r["directory"]}');check(str(got[4])==r['descendant_symlinks'],f'desc links {r["donor"]}:{r["directory"]}')
# Definition evidence must resolve to exact file hash and source line/snippet.
defs=readcsv('post-refactor-230-symbols.csv');check(len(defs)==20744,'20744 definitions')
line_cache={}
for r in defs:
 s=by.get((r['donor'],r['path']));check(s is not None,f'def file backlink {r["donor"]}:{r["path"]}');
 if s:check(s['sha256']==r['sha256'],f'def file hash {r["donor"]}:{r["path"]}')
 check(r['kind']!='' and r['symbol']!='',f'def identity {r["donor"]}:{r["path"]}:{r["line"]}')
 k=(r['donor'],r['path'])
 if k not in line_cache:
  p=DONOR_BASE/r['donor']/r['donor']/r['path'];line_cache[k]=p.read_text(encoding='utf-8',errors='replace').splitlines()
 try:actual=line_cache[k][int(r['line'])-1].strip()[:320]
 except Exception:actual='__MISSING__'
 check(actual==r['snippet'],f'def source line {r["donor"]}:{r["path"]}:{r["line"]}')
# Ledger graph and backlinks.
ledger=readcsv('post-refactor-230-adoption-ledger.csv');check(len(ledger)==5606,'5606 ledger rows');ids={r['record_id'] for r in ledger};check(len(ids)==5606,'ledger IDs unique');parent={r['record_id']:r['parent_record_id'] for r in ledger}
check(sum(r['record_id'].startswith('PR230-R') for r in ledger)==13,'13 repo records');check(sum(r['record_id'].startswith('PR230-F') for r in ledger)==5001,'5001 file records');check(sum(r['record_id'].startswith('PR230-M') for r in ledger)==554,'554 module records');focus=[r for r in ledger if r['record_id'].startswith('PR230-S')];check(len(focus)==38,'38 focused semantics')
for r in ledger:
 if r['parent_record_id']!='n/a':check(r['parent_record_id'] in ids,f'parent exists {r["record_id"]}')
 check(r['validation_status'] in {'verified','statically-validated','reviewed','inferred','unverified','pending'},f'valid status {r["record_id"]}')
for r in focus:
 s=by.get((r['donor'],r['donor_path']));check(s is not None,f'focus source exists {r["record_id"]}')
 if s:check(r['record_id'] in s['semantic_record_ids'].split(';'),f'focus backlink {r["record_id"]}')
 for n in [x for x in r['target_nodes'].split(';') if x and x!='n/a']:
  check((ROOT/n.split('#',1)[0]).exists(),f'focus target exists {r["record_id"]}:{n}')
 if r['test_node']!='n/a':check((ROOT/r['test_node'].split('#',1)[0]).exists(),f'focus test exists {r["record_id"]}')
# Parent graph acyclic.
for rid in ids:
 seen=set();cur=rid
 while cur!='n/a':check(cur not in seen,f'parent cycle {rid}');seen.add(cur);cur=parent.get(cur,'n/a')
mods=readcsv('post-refactor-230-module-audit.csv');check(len(mods)==554,'554 modules');check(sum(int(r['surfaces']) for r in mods)==5001,'module surface partition');check(sum(int(r['high_signal_surfaces']) for r in mods)==2742,'module high-signal partition');check(sum(int(r['ui_product_surfaces']) for r in mods)==432,'module ui partition')
# All-history exact append.
ah=json.loads((E/'post-refactor-230-all-history-summary.json').read_text());expah={'unique_donors':71,'surfaces':16342,'definitions':77167,'module_records':1024,'high_signal_surfaces':11522,'ui_product_surfaces':2486}
for k,v in expah.items():check(ah.get(k)==v,f'all-history {k}')
check(len(readcsv('post-refactor-230-all-history-surface-audit.csv'))==16342,'history surfaces');check(len(readcsv('post-refactor-230-all-history-symbol-index.csv'))==77167,'history defs');check(len(readcsv('post-refactor-230-all-history-module-audit.csv'))==1024,'history modules')
# Exact 229->230 delta, excluding only the self-referential delta file and transient caches.
with BASE.open(newline='',encoding='utf-8') as f:base={r['path']:r for r in csv.DictReader(f)}
delta=readcsv('post-refactor-230-target-delta.csv');dby={(r['change_type'],r['path']):r for r in delta};check(len(dby)==len(delta),'delta keys unique')
cur={}
for p in ROOT.rglob('*'):
 if not p.is_file() or p.is_symlink():continue
 rel=p.relative_to(ROOT).as_posix()
 if rel=='governance/convergence/post-refactor-230-target-delta.csv' or rel.startswith('.git/') or '/node_modules/' in '/'+rel or '__pycache__' in rel:continue
 cur[rel]={'sha256':sha_file(p),'size_bytes':str(p.stat().st_size),'mode':oct(stat.S_IMODE(p.stat().st_mode))}
expected_delta={}
for path in set(base)|set(cur):
 b,c=base.get(path),cur.get(path)
 if b is None:typ='added'
 elif c is None:typ='deleted'
 elif (b['sha256'],b['size_bytes'],b['mode'])!=(c['sha256'],c['size_bytes'],c['mode']):typ='modified'
 else:continue
 expected_delta[(typ,path)]=(b,c)
check(set(dby)==set(expected_delta),'delta path/type exact')
for key,(b,c) in expected_delta.items():
 r=dby.get(key)
 if r:check(r['baseline_sha256']==(b['sha256'] if b else 'n/a'),f'delta baseline {key}');check(r['current_sha256']==(c['sha256'] if c else 'n/a'),f'delta current {key}')
# Target semantic/authority contracts.
contracts={
'src/apps/daemon/internal/analysis/diagnostics/tor_bridge_selection_plan.go':['maxTorBridgeCandidates = 512','PerformsNetworkIO','PersistsClientKey','Stable','Running'],
'src/apps/daemon/internal/analysis/diagnostics/tor_bootstrap_evidence_plan.go':['control-unavailable','authentication-required','network-disabled','bootstrapping','circuit-pending','socks-unavailable','ready','SAFECOOKIE'],
'src/apps/daemon/internal/analysis/diagnostics/censorship_measurement_plan.go':['control','strong','moderate','weak','PerformsProbes'],
'src/apps/daemon/internal/analysis/diagnostics/dtls_session_policy_plan.go':['InsecureSkipVerify','KeyLog','ExtendedMasterSecret','Replay','MTU','ALPN','ConnectionID','Padding'],
'src/apps/daemon/internal/analysis/diagnostics/phantom_pool_plan.go':['maxPhantomCandidates = 1024','not-live','netpolicy.IsPublicAddress','PerformsNetworkIO'],
'src/apps/daemon/internal/analysis/diagnostics/flow_filter_plan.go':['maxFlowFilterClauses = 16','ModifiesFlows','ReplaysFlows','cannot modify, replay, intercept, or close'],
'src/apps/daemon/internal/analysis/diagnostics/cdn_candidates.go':['GeneratePublicCdnIPs','netpolicy.IsPublicAddress'],
'src/apps/daemon/internal/analysis/diagnostics/multiplex_policy_plan.go':['MaxFrameSize','MaxReceiveBuffer','MaxStreamBuffer','KeepAliveInterval','KeepAliveTimeout'],
'src/apps/daemon/internal/runtime/proxy/kcp_transport.go':['smuxConfig.Version = 1','smuxConfig.MaxFrameSize = 32768','smuxConfig.MaxReceiveBuffer = 4 << 20','smuxConfig.MaxStreamBuffer = 64 << 10'],
'src/apps/daemon/internal/analysis/diagnostics/gateway_composition_plan.go':['layered-fronted-egress']}
for p,toks in contracts.items():
 body=text(p)
 for tok in toks:check(tok in body,f'contract {p}:{tok}')
runner=text('src/apps/daemon/internal/workflows/jobs/runners.go');check('GeneratePublicCdnIPs' in runner,'CDN runner uses public-only generator')
routes=text('src/apps/daemon/internal/adapters/api/routes_system.go')
for route in ['/tor-bridge-selection-plan','/tor-bootstrap-evidence-plan','/censorship-measurement-plan','/dtls-session-policy-plan','/phantom-pool-plan','/flow-filter-plan']:check(route in routes,f'230 route {route}')
handlers=text('src/apps/daemon/internal/adapters/api/handlers_post_refactor_230_planners.go');check(all(x not in handlers for x in ['http.Get(','http.Post(','exec.Command(','os.WriteFile(']),'230 handlers side-effect free')
parsers=text('src/packages/control-ui/src/api/planners.ts')
for tok in ['parseTorBridgeSelectionPlan','parseTorBootstrapEvidencePlan','parseCensorshipMeasurementPlan','parseDTLSSessionPolicyPlan','parsePhantomPoolPlan','parseFlowFilterPlan']:check(tok in parsers,f'UI parser {tok}')
ops=text('src/packages/control-ui/src/pages/Operations.tsx')
for tok in ['torBridgeSelect','torBootstrap','censorshipEvidence','dtlsPolicy','phantomPool','flowFilter','Convergence policy lab']:check(tok in ops,f'Operations surface {tok}')
pkg=json.loads(text('src/packages/control-ui/package.json'));check(pkg['scripts'].get('test:230')=='node scripts/test-post-refactor-230.mjs','test:230 script');check('npm run test:230' in pkg['scripts']['test'],'aggregate UI includes 230')
product=text('src/packages/control-ui/scripts/test-post-refactor-230.mjs');check('checks !== 118' in product,'230 UI denominator 118')
mk=text('Makefile');check('post-refactor-230-evidence' in mk and 'check_post_refactor_230_convergence.py' in mk,'Makefile owns 230')
REPORTS={'post-refactor-230-architecture.md':['13 outer donors','5,001 files','smux'],'post-refactor-230-security-model.md':['CA installation','SAFECOOKIE','public routable'],'post-refactor-230-state-machines.md':['control-unavailable','not-live','DTLS'],'post-refactor-230-peer-synthesis.md':['13 donor','BridgeDB','qjs'],'post-refactor-230-omission-audit.md':['5,001/5,001','20,744/20,744','unresolved high-signal surfaces: 0'],'post-refactor-230-operator-runbook.md':['Convergence policy lab','planning/evidence only','CDN scan'],'post-refactor-230-all-history-second-order-audit.md':['71 unique donor','16,342','77,167']}
for name,toks in REPORTS.items():
 body=(E/name).read_text(encoding='utf-8',errors='replace')
 for tok in toks:check(tok in body,f'{name} token {tok}')
print(f'post-refactor-230 convergence: assertions={assertions} errors={len(errors)}')
if errors:
 for e in errors[:500]:print('ERROR',e)
 if len(errors)>500:print(f'... {len(errors)-500} more')
 sys.exit(1)
