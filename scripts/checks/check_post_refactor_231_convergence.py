#!/usr/bin/env python3
"""Independent verification for the post-refactor-231 five-donor convergence wave."""
from __future__ import annotations
import csv, hashlib, json, os, stat, sys, zipfile
from collections import defaultdict, Counter
from pathlib import Path, PurePosixPath
ROOT=Path(os.environ.get('LUMINET_231_TARGET_ROOT',Path(__file__).resolve().parents[2]))
WORK=Path(os.environ.get('LUMINET_231_WORK_ROOT','/mnt/data/luminet231_work'))
DONOR_BASE=WORK/'donors'; E=ROOT/'governance/convergence'; BASE=E/'post-refactor-231-baseline-files.csv'
HIGH={'implementation','ui-or-product','configuration','deployment','script','test'}
assertions=0;errors=[]
def check(c,msg):
 global assertions;assertions+=1
 if not c:errors.append(msg)
def sha_file(p):
 h=hashlib.sha256()
 with Path(p).open('rb') as f:
  for b in iter(lambda:f.read(1<<20),b''):h.update(b)
 return h.hexdigest()
def readcsv(name):
 with (E/name).open(newline='',encoding='utf-8') as f:return list(csv.DictReader(f))
def text(p):return (ROOT/p).read_text(encoding='utf-8',errors='replace')
def norm(name):
 p=PurePosixPath(name.replace('\\','/'))
 if p.is_absolute() or any(x in {'','.', '..'} for x in p.parts) or (p.parts and ':' in p.parts[0]):raise ValueError(name)
 return p
SUCCESSOR_232=E/'post-refactor-232-baseline-files.csv'
if SUCCESSOR_232.is_file():
 check(sha_file(SUCCESSOR_232)=='1eaf71719e55474a146ce6d2be2baafda3ae44cacadff9fc0df8878f3da463e7','232 embeds exact released 231 source inventory')
 with SUCCESSOR_232.open(newline='',encoding='utf-8') as f: successor_rows=list(csv.DictReader(f))
 check(len(successor_rows)==3219,'231 frozen inventory has 3219 files')
 frozen=[r for r in successor_rows if r['path'].startswith('governance/convergence/post-refactor-231-')]
 check(len(frozen)==23,'23 frozen post-refactor-231 governance artifacts')
 for r in frozen:
  q=ROOT/r['path'];check(q.is_file(),f'231 frozen artifact exists {r["path"]}')
  if q.is_file():
   check(sha_file(q)==r['sha256'],f'231 frozen artifact hash {r["path"]}')
   check(str(q.stat().st_size)==r['size_bytes'],f'231 frozen artifact size {r["path"]}')
   check(oct(stat.S_IMODE(q.stat().st_mode))==r['mode'],f'231 frozen artifact mode {r["path"]}')
 frozen_summary=json.loads((E/'post-refactor-231-evidence-summary.json').read_text())
 for k,v in {'outer_donors':5,'surfaces':35331,'definitions':2163,'module_records':562,'semantic_value_records':33,'unresolved_high_signal_surfaces':0}.items():check(frozen_summary.get(k)==v,f'231 frozen summary {k}')
 print(f'post-refactor-231 successor evidence: assertions={assertions} errors={len(errors)}')
 if errors:
  for e in errors:print('ERROR',e)
  sys.exit(1)
 sys.exit(0)
required=['post-refactor-231-archive-accountability.csv','post-refactor-231-surface-accountability.csv','post-refactor-231-directories.csv','post-refactor-231-symbols.csv','post-refactor-231-symlinks.csv','post-refactor-231-module-audit.csv','post-refactor-231-adoption-ledger.csv','post-refactor-231-supersession-map.csv','post-refactor-231-evidence-summary.json','post-refactor-231-baseline-files.csv','post-refactor-231-target-delta.csv','post-refactor-231-all-history-surface-audit.csv','post-refactor-231-all-history-symbol-index.csv','post-refactor-231-all-history-module-audit.csv','post-refactor-231-all-history-summary.json','post-refactor-231-architecture.md','post-refactor-231-security-model.md','post-refactor-231-state-machines.md','post-refactor-231-peer-synthesis.md','post-refactor-231-omission-audit.md','post-refactor-231-operator-runbook.md','post-refactor-231-validation.md','post-refactor-231-all-history-second-order-audit.md']
for n in required:check((E/n).is_file(),f'missing evidence {n}')
if errors:
 print('\n'.join(errors));sys.exit(1)
summary=json.loads((E/'post-refactor-231-evidence-summary.json').read_text())
expected={'outer_donors':5,'archive_members':43384,'surfaces':35331,'directories':8044,'definitions':2163,'symlinks':7,'module_records':562,'high_signal_surfaces':1504,'ui_product_surfaces':125,'semantic_value_records':33,'repository_records':5,'file_records':35331,'ledger_records':35931,'baseline_files':3186,'vendored_surfaces':33047,'unresolved_high_signal_surfaces':0}
for k,v in expected.items():check(summary.get(k)==v,f'summary {k}: {summary.get(k)!r} != {v!r}')
check(sha_file(BASE)=='a651ade4b116a3b940adbf5d8a42bf5eee5ea99dab9a1d62ab3603e5f8a99fa7','exact released 230 inventory embedded')
# Surface and symlink indexes first, used to validate archive bytes.
surfs=readcsv('post-refactor-231-surface-accountability.csv');check(len(surfs)==35331,'35331 surfaces');by={(r['donor'],r['path']):r for r in surfs};check(len(by)==35331,'surface keys unique')
links=readcsv('post-refactor-231-symlinks.csv');check(len(links)==7,'7 symlinks');link_by_key={(r['donor'],r['path']):r for r in links};check(len(link_by_key)==7,'symlink keys unique')
# Archive safety/CRC and direct member-byte equality against surface records.
arch=readcsv('post-refactor-231-archive-accountability.csv');check(len(arch)==5,'5 archives');arch_by={r['archive']:r for r in arch};check(len(arch_by)==5,'archive keys unique')
expected_arch={'nthlink-os-windows-main(1).zip':'3c7554f35125753b2a92be3d29de4e1a094f3381956176dfdab731cb3e01ac44','stegotorus-master(1).zip':'7aa9d3f363c54382932a0910645aff43b702c448302e7feb240174f9f9bb1bea','IPtProxy-master(1).zip':'8d4094918973e2cd9fba1a64fc449c9b623ad3452e620c98756a5dd7c42474ba','naiveproxy-master(1).zip':'87333e5dc9d70be95aea7e8166ea0c7c21b38bf9a275945d2560db59b4ba2e31','orbot-android-master(2).zip':'9c1f83be184bb7e7d46ab272c112fef429fbcedba7dc1607c88b0dd899b58e6d'}
for name,digest in expected_arch.items():
 p=Path('/mnt/data')/name;row=arch_by.get(name);check(row is not None,f'archive evidence {name}');check(p.is_file(),f'archive exists {name}')
 if row is None or not p.is_file():continue
 check(sha_file(p)==digest==row['sha256'],f'archive hash {name}')
 donor=row['donor'];prefix=donor+'/'
 with zipfile.ZipFile(p) as z:
  check(z.testzip() is None,f'CRC {name}');infos=z.infolist();check(len(infos)==int(row['members']),f'member count {name}')
  seen=set();fold=set();files=dirs=symlinks=0;total=0
  for info in infos:
   try:rel=norm(info.filename)
   except ValueError:check(False,f'unsafe member {name}:{info.filename}');continue
   key=rel.as_posix().rstrip('/');check(key not in seen,f'duplicate {name}:{key}');check(key.casefold() not in fold,f'case collision {name}:{key}');seen.add(key);fold.add(key.casefold());check(not(info.flag_bits&1),f'encrypted {name}:{key}')
   mode=info.external_attr>>16;kind=stat.S_IFMT(mode);islink=stat.S_ISLNK(mode);check(kind in {0,stat.S_IFREG,stat.S_IFDIR,stat.S_IFLNK},f'special member {name}:{key}')
   inner=key[len(prefix):] if key.startswith(prefix) else key
   if islink:
    symlinks+=1;er=link_by_key.get((donor,inner));check(er is not None,f'symlink evidence {donor}:{inner}')
    if er is not None:
     target=z.read(info).decode('utf-8',errors='replace');check(target==er['target'],f'symlink target {donor}:{inner}')
   elif info.is_dir():dirs+=1
   else:
    files+=1;total+=info.file_size;sr=by.get((donor,inner));check(sr is not None,f'file evidence {donor}:{inner}')
    if sr is not None:
     data=z.read(info);check(str(len(data))==sr['size_bytes'],f'archive size {donor}:{inner}');check(hashlib.sha256(data).hexdigest()==sr['sha256'],f'archive bytes {donor}:{inner}')
  check(files==int(row['regular_files']),f'file count {name}');check(dirs==int(row['directories']),f'dir count {name}');check(symlinks==int(row['symlinks']),f'symlink count {name}');check(total==int(row['uncompressed_bytes']),f'uncompressed bytes {name}')
# Extracted files remain exact and modes match surface evidence.
for r in surfs:
 p=DONOR_BASE/r['donor']/r['donor']/r['path'];check(p.is_file() and not p.is_symlink(),f'donor file exists {r["donor"]}:{r["path"]}')
 if p.is_file():check(str(p.stat().st_size)==r['size_bytes'],f'size {r["donor"]}:{r["path"]}');check(oct(stat.S_IMODE(p.stat().st_mode))==r['mode'],f'mode {r["donor"]}:{r["path"]}');check(sha_file(p)==r['sha256'],f'hash {r["donor"]}:{r["path"]}')
 check(r['semantic_record_ids']!='',f'surface backlinks {r["donor"]}:{r["path"]}');check(r['post_refactor_231_disposition'] not in {'','pending','unresolved'},f'disposition {r["donor"]}:{r["path"]}')
 if r['classification'] in HIGH:check('PR231-F' in r['semantic_record_ids'] and 'PR231-M' in r['semantic_record_ids'],f'high-signal ownership {r["donor"]}:{r["path"]}')
# Rebuild Merkle records in O(total path depth), matching the raw evidence algorithm exactly.
rows_by=defaultdict(list);links_by=defaultdict(list)
for r in surfs:rows_by[r['donor']].append(r)
for r in links:links_by[r['donor']].append(r)
recomputed={}
for donor in sorted(rows_by):
 desc_files=defaultdict(list);desc_links=defaultdict(list);direct_files=defaultdict(int);child_dirs=defaultdict(set);dirs_seen={'.'}
 for r in sorted(rows_by[donor],key=lambda x:x['path']):
  parts=r['path'].split('/');anc=['.']+['/'.join(parts[:i]) for i in range(1,len(parts))]
  for d in anc:desc_files[d].append(r);dirs_seen.add(d)
  parent='.' if len(parts)==1 else '/'.join(parts[:-1]);direct_files[parent]+=1
  for i in range(1,len(parts)):
   d='/'.join(parts[:i]);parent='.' if i==1 else '/'.join(parts[:i-1]);child_dirs[parent].add(d)
 for r in sorted(links_by[donor],key=lambda x:x['path']):
  parts=r['path'].split('/');anc=['.']+['/'.join(parts[:i]) for i in range(1,len(parts))]
  for d in anc:desc_links[d].append(r);dirs_seen.add(d)
  for i in range(1,len(parts)):
   d='/'.join(parts[:i]);parent='.' if i==1 else '/'.join(parts[:i-1]);child_dirs[parent].add(d)
 for d in dirs_seen:
  h=hashlib.sha256()
  for r in desc_files[d]:h.update(f"F\0{r['path']}\0{r['sha256']}\0{r['size_bytes']}\0{r['mode']}\n".encode())
  for r in desc_links[d]:h.update(f"L\0{r['path']}\0{r['target']}\0{r['mode']}\n".encode())
  recomputed[(donor,d)]=(h.hexdigest(),str(direct_files[d]),str(len(child_dirs[d])),str(len(desc_files[d])),str(len(desc_links[d])))
dirs=readcsv('post-refactor-231-directories.csv');check(len(dirs)==8044,'8044 directory records');check(len({(r['donor'],r['directory']) for r in dirs})==8044,'directory keys unique')
for r in dirs:
 got=recomputed.get((r['donor'],r['directory']));check(got is not None,f'merkle key {r["donor"]}:{r["directory"]}')
 if got is not None:
  check(got[0]==r['tree_sha256'],f'merkle {r["donor"]}:{r["directory"]}');check(got[1]==r['direct_files'],f'direct files {r["donor"]}:{r["directory"]}');check(got[2]==r['direct_dirs'],f'direct dirs {r["donor"]}:{r["directory"]}');check(got[3]==r['descendant_files'],f'desc files {r["donor"]}:{r["directory"]}');check(got[4]==r['descendant_symlinks'],f'desc links {r["donor"]}:{r["directory"]}')
# Definition evidence resolves to exact file hash/source line.
defs=readcsv('post-refactor-231-symbols.csv');check(len(defs)==2163,'2163 definitions');line_cache={}
for r in defs:
 s=by.get((r['donor'],r['path']));check(s is not None,f'def file backlink {r["donor"]}:{r["path"]}')
 if s:check(s['sha256']==r['sha256'],f'def file hash {r["donor"]}:{r["path"]}');check(s['classification']!='vendored' or r['path'].startswith('src/net/tools/naive/'),f'vendor definition boundary {r["donor"]}:{r["path"]}')
 k=(r['donor'],r['path'])
 if k not in line_cache:line_cache[k]=(DONOR_BASE/r['donor']/r['donor']/r['path']).read_text(encoding='utf-8',errors='replace').splitlines()
 try:actual=line_cache[k][int(r['line'])-1].strip()[:320]
 except Exception:actual='__MISSING__'
 check(actual==r['snippet'],f'def source line {r["donor"]}:{r["path"]}:{r["line"]}')
# Ledger graph and bidirectional backlinks.
ledger=readcsv('post-refactor-231-adoption-ledger.csv');check(len(ledger)==35931,'35931 ledger rows');ids={r['record_id'] for r in ledger};check(len(ids)==35931,'ledger IDs unique');parent={r['record_id']:r['parent_record_id'] for r in ledger}
check(sum(r['record_id'].startswith('PR231-R') for r in ledger)==5,'5 repo records');check(sum(r['record_id'].startswith('PR231-F') for r in ledger)==35331,'35331 file records');check(sum(r['record_id'].startswith('PR231-M') for r in ledger)==562,'562 module records');focus=[r for r in ledger if r['record_id'].startswith('PR231-S')];check(len(focus)==33,'33 focused semantics')
for r in ledger:
 if r['parent_record_id']!='n/a':check(r['parent_record_id'] in ids,f'parent exists {r["record_id"]}')
 check(r['validation_status'] in {'verified','statically-validated','reviewed','inferred','unverified','pending'},f'valid status {r["record_id"]}')
for r in focus:
 s=by.get((r['donor'],r['donor_path']));check(s is not None,f'focus source {r["record_id"]}')
 if s:check(r['record_id'] in s['semantic_record_ids'].split(';'),f'focus backlink {r["record_id"]}')
 for n in [x for x in r['target_nodes'].split(';') if x and x!='n/a']:
  check((ROOT/n.split('#',1)[0]).exists(),f'focus target {r["record_id"]}:{n}')
 if r['test_node']!='n/a':check((ROOT/r['test_node'].split('#',1)[0]).exists(),f'focus test {r["record_id"]}')
for rid in ids:
 seen=set();cur=rid
 while cur!='n/a':check(cur not in seen,f'parent cycle {rid}');seen.add(cur);cur=parent.get(cur,'n/a')
mods=readcsv('post-refactor-231-module-audit.csv');check(len(mods)==562,'562 modules');check(sum(int(r['surfaces']) for r in mods)==35331,'module surface partition');check(sum(int(r['high_signal_surfaces']) for r in mods)==1504,'module high partition');check(sum(int(r['ui_product_surfaces']) for r in mods)==125,'module ui partition')
# All-history is exact predecessor append, not regenerated historical reinterpretation.
prev_s=readcsv('post-refactor-230-all-history-surface-audit.csv');hist_s=readcsv('post-refactor-231-all-history-surface-audit.csv');check(len(prev_s)==16342 and len(hist_s)==51673,'history surface counts');check(hist_s[:len(prev_s)]==prev_s,'history surface predecessor prefix exact')
prev_d=readcsv('post-refactor-230-all-history-symbol-index.csv');hist_d=readcsv('post-refactor-231-all-history-symbol-index.csv');check(len(prev_d)==77167 and len(hist_d)==79330,'history definition counts');check(hist_d[:len(prev_d)]==prev_d,'history definition predecessor prefix exact')
prev_m=readcsv('post-refactor-230-all-history-module-audit.csv');hist_m=readcsv('post-refactor-231-all-history-module-audit.csv');check(len(prev_m)==1024 and len(hist_m)==1586,'history module counts');check(hist_m[:len(prev_m)]==prev_m,'history module predecessor prefix exact')
ah=json.loads((E/'post-refactor-231-all-history-summary.json').read_text());expah={'unique_donors':76,'surfaces':51673,'definitions':79330,'module_records':1586,'high_signal_surfaces':13026,'ui_product_surfaces':2611}
for k,v in expah.items():check(ah.get(k)==v,f'all-history {k}')
# Exact predecessor -> 231 delta.
with BASE.open(newline='',encoding='utf-8') as f:base={r['path']:r for r in csv.DictReader(f)}
delta=readcsv('post-refactor-231-target-delta.csv');dby={(r['change_type'],r['path']):r for r in delta};check(len(dby)==len(delta),'delta keys unique');cur={}
for p in ROOT.rglob('*'):
 if not p.is_file() or p.is_symlink():continue
 rel=p.relative_to(ROOT).as_posix()
 if rel=='governance/convergence/post-refactor-231-target-delta.csv' or rel.startswith('.git/') or '/node_modules/' in '/'+rel or '__pycache__' in rel:continue
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
# Target-native behavior/authority contracts.
contracts={
'src/apps/daemon/internal/analysis/diagnostics/pluggable_transport_plan.go':['maxPTPeers        = 64','SingletonRequired','StateDirRequired','SafeLogging','does not support an outbound proxy','discovered local listener port','StartsTransport: false','PerformsNetworkIO: false','WritesState: false'],
'src/apps/daemon/internal/analysis/diagnostics/circumvention_fallback_plan.go':['MaximumTransitions: 3','direct -> snowflake -> custom-or-obfs4 -> obfs4 -> fail','CustomBridgesAvailable','PerformsNetworkIO: false','StartsTransport: false','MutatesPreferences: false'],
'src/apps/daemon/internal/analysis/diagnostics/naive_proxy_policy_plan.go':['naiveFirstPaddedFrames = 8','naiveFrameHeaderBytes  = 3','naiveMaxPaddingBytes   = 255','naiveMaxPayloadBytes   = 65535','SOCKS proxy authentication is not admitted','multi-proxy chains containing SOCKS are not admitted','QUIC proxy cannot follow a TCP-based proxy','redir listener is supported only on linux','IPv6 resolver range is not admitted','FirstConnectFastOpenAllowed: padding != "variant1"','PerformsNetworkIO: false','StartsProxy: false'],
'src/apps/daemon/internal/analysis/diagnostics/stego_scheme_plan.go':['cookie-transmit','uri-transmit','req.PayloadBytes < 300','req.PayloadBytes < 700','raw.RecentFailures >= 3','raw.CapacityBytes < req.PayloadBytes','sha256.Sum256','EmbedsPayload: false','LoadsCoverAssets: false','PerformsNetworkIO: false','MutatesSchemeState: false']}
for p,toks in contracts.items():
 body=text(p)
 for tok in toks:check(tok in body,f'contract {p}:{tok}')
routes=text('src/apps/daemon/internal/adapters/api/routes_system.go')
for route in ['/pluggable-transport-plan','/circumvention-fallback-plan','/naive-proxy-policy-plan','/stego-scheme-plan']:check(route in routes,f'231 route {route}')
handlers=text('src/apps/daemon/internal/adapters/api/handlers_post_refactor_231_planners.go');check(all(x not in handlers for x in ['http.Get(','http.Post(','net.Dial(','exec.Command(','os.WriteFile(','os.Remove(']),'231 handlers side-effect free')
parsers=text('src/packages/control-ui/src/api/planners.ts')
for tok in ['parsePluggableTransportPlan','parseCircumventionFallbackPlan','parseNaiveProxyPolicyPlan','parseStegoSchemePlan']:check(tok in parsers,f'UI parser {tok}')
ops=text('src/packages/control-ui/src/pages/Operations.tsx')
for tok in ['ptLifecycle','circumventionFallback','naivePolicy','stegoScheme','Convergence policy lab']:check(tok in ops,f'Operations surface {tok}')
pkg=json.loads(text('src/packages/control-ui/package.json'));check(pkg['scripts'].get('test:231')=='node scripts/test-post-refactor-231.mjs','test:231 script');check(pkg['scripts']['test'].endswith('&& npm run test:231'),'aggregate UI ends 231')
product=text('src/packages/control-ui/scripts/test-post-refactor-231.mjs');check('checks !== 98' in product,'231 UI denominator 98')
gotest=text('src/apps/daemon/internal/analysis/diagnostics/post_refactor_231_plans_test.go')
for tok in ['TestPostRefactor231PluggableTransportPlan','TestPostRefactor231CircumventionFallbackPlan','TestPostRefactor231NaiveProxyPolicyPlan','TestPostRefactor231StegoSchemePlan']:check(tok in gotest,f'Go planner test {tok}')
mk=text('Makefile');check('post-refactor-231-evidence' in mk and 'check_post_refactor_231_convergence.py' in mk,'Makefile owns 231')
REPORTS={'post-refactor-231-architecture.md':['Five donors','35,331 files','33,047 vendored'],'post-refactor-231-security-model.md':['Snowflake and DNSTT','SOCKS auth','Hard-coded application bypass'],'post-refactor-231-state-machines.md':['direct -> snowflake','first CONNECT','deterministic fallback'],'post-refactor-231-peer-synthesis.md':['nthLink','IPtProxy','Orbot','NaiveProxy','Stegotorus'],'post-refactor-231-omission-audit.md':['35,331/35,331','2,163/2,163','unresolved high-signal surfaces: 0'],'post-refactor-231-operator-runbook.md':['Convergence policy lab','authenticated planning surfaces'],'post-refactor-231-all-history-second-order-audit.md':['76 unique donor','51,673','79,330']}
for name,toks in REPORTS.items():
 body=(E/name).read_text(encoding='utf-8',errors='replace')
 for tok in toks:check(tok in body,f'{name} token {tok}')
print(f'post-refactor-231 convergence: assertions={assertions} errors={len(errors)}')
if errors:
 for e in errors[:500]:print('ERROR',e)
 if len(errors)>500:print(f'... {len(errors)-500} more')
 sys.exit(1)
