#!/usr/bin/env python3
from __future__ import annotations
import csv,hashlib,json,os,re,stat,sys,zipfile
from collections import Counter
from pathlib import Path,PurePosixPath
ROOT=Path(os.environ.get('LUMINET_226_TARGET_ROOT',Path(__file__).resolve().parents[2]))
OUT=ROOT/'governance/convergence';INPUTS=Path(os.environ.get('LUMINET_226_INPUT_ROOT','/mnt/data/luminet226_inputs'));DONORS=Path(os.environ.get('LUMINET_226_DONOR_ROOT','/mnt/data/luminet226_work/donors'))
ARCH=OUT/'post-refactor-226-archive-accountability.csv';SURF=OUT/'post-refactor-226-surface-accountability.csv';DIRS=OUT/'post-refactor-226-directories.csv';SYMS=OUT/'post-refactor-226-symbols.csv';LEDGER=OUT/'post-refactor-226-adoption-ledger.csv';SUM=OUT/'post-refactor-226-evidence-summary.json';ALLSUM=OUT/'post-refactor-226-all-history-summary.json';ALLSURF=OUT/'post-refactor-226-all-history-surface-audit.csv';ALLSYM=OUT/'post-refactor-226-all-history-symbol-index.csv';ALLMOD=OUT/'post-refactor-226-all-history-module-audit.csv';DELTA=OUT/'post-refactor-226-target-delta.csv';BASE=OUT/'post-refactor-226-baseline-files.csv'
ROOTMAP={'shadowsocks-crypto':'shadowsocks-crypto-main','shadowsocksr':'shadowsocksR-master','shadowsocks-rust':'shadowsocks-rust-master','srsc':'srsc-dev','ssh':'ssh-master','subconverter':'subconverter-master(1)','tailscale-client':'tailscale-client-go-main(3)','tinytun':'TinyTun-master(3)','tools':'Tools-main(3)','browser-ext':'ts-browser-ext-main(3)','tsheadroom':'tsheadroom-main(3)','mwgp':'mwgp-2','paas-gateway':'PaaS-vmess-trojan-argo-main','reverse-tls':'Reverse_tls-main'}
assertions=0;errors=[]
def check(cond,msg):
 global assertions
 assertions+=1
 if not cond:errors.append(msg)
def readcsv(p):
 with p.open(newline='',encoding='utf-8') as f:return list(csv.DictReader(f))
def sha_file(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for c in iter(lambda:f.read(1<<20),b''):h.update(c)
 return h.hexdigest()
def sha_bytes(b):return hashlib.sha256(b).hexdigest()
def safe(name):
 p=PurePosixPath(name.replace('\\','/'));return bool(p.parts) and not p.is_absolute() and all(x not in ('','.','..') for x in p.parts) and ':' not in p.parts[0]
for p in (ARCH,SURF,DIRS,SYMS,LEDGER,SUM,ALLSUM,ALLSURF,ALLSYM,ALLMOD,DELTA,BASE):check(p.is_file(),f'missing {p.relative_to(ROOT)}')
REPORTS={
 'post-refactor-226-architecture.md':('52 donors','15,975','core_manager.go'),
 'post-refactor-226-security-model.md':('fail closed','SS2022','loopback'),
 'post-refactor-226-state-machines.md':('ExpectedRevision','WebSocket readiness','24h'),
 'post-refactor-226-peer-synthesis.md':('893','TinyTun','PaaS'),
 'post-refactor-226-omission-audit.md':('745/745','25,486','0'),
 'post-refactor-226-operator-runbook.md':('planner','WebSocket','three attempts'),
 'post-refactor-226-validation.md':('69,338','390 assertions','0 errors, 1 warning'),
}
for name,tokens in REPORTS.items():
 p=OUT/name;check(p.is_file(),f'missing durable 226 report {name}')
 if p.is_file():
  body=p.read_text(encoding='utf-8',errors='replace')
  for token in tokens:check(token in body,f'{name}: missing release-evidence token {token!r}')
if errors:
 print('\n'.join(errors));sys.exit(1)
# Successor releases freeze the complete 226 governance evidence in the exact
# 226 source inventory instead of requiring historical donor mounts or the
# 225->226 live delta to remain current on descendants. The original 226
# release has no 227 baseline, so its full validation below remains unchanged.
SUCCESSOR_BASELINE=OUT/'post-refactor-227-baseline-files.csv'
SUCCESSOR=SUCCESSOR_BASELINE.is_file()
if SUCCESSOR:
 frozen={r['path']:r for r in readcsv(SUCCESSOR_BASELINE)}
 check(sha_file(SUCCESSOR_BASELINE)=='43dd416f1ab6d72deb56b5b11aa5076bbe0b3e72ba2afc5a6b5ee61d73b8a833','226 frozen source inventory identity in 227 successor')
 for evidence in sorted(OUT.glob('post-refactor-226-*')):
  if not evidence.is_file(): continue
  rel=evidence.relative_to(ROOT).as_posix(); row=frozen.get(rel)
  check(row is not None,f'226 frozen evidence listed in 227 baseline: {rel}')
  if row: check(sha_file(evidence)==row['sha256'],f'226 frozen evidence byte-identical in successor: {rel}')
 if errors:
  print('\n'.join(errors));sys.exit(1)
 print(f'post-refactor-226 convergence: successor-frozen assertions={assertions} errors=0')
 sys.exit(0)
check(sha_file(BASE)=='dd08f06593a896d26678da2d30b264000b9ba89fb60246aaf091095127ed7860','225 frozen source inventory digest drift')
summary=json.loads(SUM.read_text());expected={'donors':14,'archive_members':1557,'surfaces':1299,'files':1299,'symlinks':0,'directories_excluding_roots':244,'directory_merkle_records':258,'symbols':15975,'focused_file_records':745,'focused_module_records':134,'semantic_records':893,'high_signal_surfaces':745,'high_signal_without_focused_record':0,'rich_cpp_symbols':159}
for k,v in expected.items():check(summary.get(k)==v,f'summary {k}: {summary.get(k)} != {v}')
# Original ZIP -> extracted donor byte equality and archive accountability.
arch=readcsv(ARCH);check(len(arch)==14,'archive row count')
for r in arch:
 d=r['donor'];ap=INPUTS/r['archive'];dr=DONORS/ROOTMAP[d]
 check(ap.is_file(),f'{d}: archive missing');check(dr.is_dir(),f'{d}: extracted root missing');check(sha_file(ap)==r['archive_sha256'],f'{d}: archive sha')
 with zipfile.ZipFile(ap) as z:
  infos=z.infolist();check(len(infos)==int(r['members']),f'{d}: member count');check(z.testzip() is None,f'{d}: CRC')
  names=[];fold=set();seen=set();files={}
  for i in infos:
   check(safe(i.filename),f'{d}: unsafe path {i.filename}');p=PurePosixPath(i.filename.replace('\\','/'));name=p.as_posix().rstrip('/');check(name not in seen,f'{d}: duplicate {name}');check(name.casefold() not in fold,f'{d}: case collision {name}');seen.add(name);fold.add(name.casefold())
   mode=i.external_attr>>16;kind=stat.S_IFMT(mode);check(kind in (0,stat.S_IFREG,stat.S_IFDIR),f'{d}: link/special {name}')
   if not i.is_dir():
    rel=PurePosixPath(*p.parts[1:]).as_posix();files[rel]=sha_bytes(z.read(i))
  check(len(files)==int(r['files']),f'{d}: file count')
  actual={p.relative_to(dr).as_posix():sha_file(p) for p in dr.rglob('*') if p.is_file()}
  check(set(actual)==set(files),f'{d}: extracted paths');
  for path,h in files.items():check(actual.get(path)==h,f'{d}: extracted byte {path}')
# Surfaces + backlinks.
surfs=readcsv(SURF);check(len(surfs)==1299,'surface count');by={(r['donor'],r['path']):r for r in surfs};check(len(by)==len(surfs),'duplicate surface rows')
ledger=readcsv(LEDGER);ids={r['record_id'] for r in ledger};check(len(ids)==len(ledger)==893,'ledger ids/count')
for r in surfs:
 p=DONORS/ROOTMAP[r['donor']]/r['path'];check(p.is_file(),f'surface missing {r["donor"]}:{r["path"]}');check(sha_file(p)==r['sha256'],f'surface hash {r["donor"]}:{r["path"]}')
 links=[x for x in r['semantic_record_ids'].split(';') if x];check(all(x in ids for x in links),f'surface bad link {r["donor"]}:{r["path"]}')
 if r['classification'] in {'implementation','test','configuration','script','deployment','ui-or-product'}:check(len(links)>=3,f'high signal lacks file/module link {r["donor"]}:{r["path"]}')
# Directory Merkle records.
dirs=readcsv(DIRS);check(len(dirs)==258,'directory record count')
for r in dirs:
 root=DONORS/ROOTMAP[r['donor']];d=root if r['path']=='.' else root/r['path'];check(d.is_dir(),f'dir missing {r["donor"]}:{r["path"]}')
 entries=[]
 for p in sorted(root.rglob('*'),key=lambda q:q.relative_to(root).as_posix()):
  if not p.is_file():continue
  try:rel=p.relative_to(d).as_posix()
  except ValueError:continue
  entries.append((rel,sha_file(p)))
 payload=''.join(f'{h}  {rel}\n' for rel,h in entries).encode();check(len(entries)==int(r['descendant_files']),f'dir descendant count {r["donor"]}:{r["path"]}');check(sha_bytes(payload)==r['tree_sha256'],f'dir merkle {r["donor"]}:{r["path"]}')
# Definition index.
syms=readcsv(SYMS);check(len(syms)==15975,'symbol count');pol=Counter(r['extraction_policy'] for r in syms);check(pol==Counter({'legacy-225-compatible':10548,'rich-rust-top-level':5245,'rich-go-package-registration':23,'rich-cpp-structural':159}),f'symbol extraction policies {pol}')
for r in syms:
 s=by.get((r['donor'],r['path']));check(s is not None,f'symbol orphan {r["donor"]}:{r["path"]}');
 if s:check(r['sha256']==s['sha256'],f'symbol hash drift {r["donor"]}:{r["path"]}');check(r['semantic_record_ids']==s['semantic_record_ids'],f'symbol backlink {r["donor"]}:{r["path"]}')
# Ledger parent/dependency graph, donor hashes, target nodes, unique anchors.
parent={r['record_id']:r['parent_record_id'] for r in ledger};test_nodes=[]
check(sum(r['record_id'].startswith('PR226-R') for r in ledger)==14,'repo records');check(sum(r['record_id'].startswith('PR226-M') for r in ledger)==134,'module records');check(sum(r['record_id'].startswith('PR226-F') for r in ledger)==745,'file records')
for r in ledger:
 rid=r['record_id'];par=r['parent_record_id'];check(par=='n/a' or par in ids,f'{rid}: parent')
 for dep in [x for x in r['dependency_record_ids'].split(';') if x and x!='n/a']:check(dep in ids,f'{rid}: dependency {dep}')
 dp=DONORS/ROOTMAP[r['donor']]/r['donor_path'];check(dp.is_file(),f'{rid}: donor evidence missing');check(sha_file(dp)==r['donor_sha256'],f'{rid}: donor evidence hash')
 if r['disposition']!='reference-only':
  check(r['test_node']!='n/a',f'{rid}: missing acceptance anchor');test_nodes.append(r['test_node'])
  for node in [x for x in r['target_nodes'].split(';') if x and x!='n/a']:
   path=node.split('#',1)[0];check((ROOT/path).exists(),f'{rid}: target node path missing {path}')
# unique convergence anchors prevent one generic test masquerading as many records.
check(len(test_nodes)==len(set(test_nodes)),'non-reference acceptance anchors must be unique')
# Parent graph acyclic.
for rid in ids:
 seen=set();cur=rid
 while cur!='n/a':
  check(cur not in seen,f'parent cycle at {rid}');seen.add(cur);cur=parent.get(cur,'n/a')
# All-history overlay.
a=json.loads(ALLSUM.read_text());exp={'donors':52,'unique_donor_names':52,'surfaces':3760,'symbols':25486,'modules':284,'wave_224_surfaces':913,'wave_225_surfaces':1548,'wave_226_surfaces':1299,'wave_224_symbols':2256,'wave_225_symbols':7255,'wave_226_symbols':15975,'semantic_records_224':72,'semantic_records_225':1133,'semantic_records_226':893,'ui_product_surfaces':161,'high_signal_surfaces':2317}
for k,v in exp.items():check(a.get(k)==v,f'all-history {k}: {a.get(k)} != {v}')
check(len(readcsv(ALLSURF))==3760,'all-history surface rows');check(len(readcsv(ALLSYM))==25486,'all-history symbol rows');check(len(readcsv(ALLMOD))==284,'all-history module rows')
# Exact 225->226 delta correspondence (delta excludes its own file by design).
base={r['path']:r for r in readcsv(BASE)};cur={}
for p in ROOT.rglob('*'):
 if not p.is_file() or p.is_symlink():continue
 rel=p.relative_to(ROOT).as_posix()
 if rel=='governance/convergence/post-refactor-226-target-delta.csv' or rel.startswith('.git/'):continue
 cur[rel]={'sha256':sha_file(p),'size_bytes':str(p.stat().st_size),'mode':oct(stat.S_IMODE(p.stat().st_mode))}
actual={}
for path in sorted(set(base)|set(cur)):
 b=base.get(path);c=cur.get(path)
 if b is None:typ='added'
 elif c is None:typ='deleted'
 elif (b['sha256'],b['size_bytes'],b['mode'])!=(c['sha256'],c['size_bytes'],c['mode']):typ='modified'
 else:continue
 actual[path]=(typ,b['sha256'] if b else 'n/a',c['sha256'] if c else 'n/a')
rows=readcsv(DELTA);decl={r['path']:(r['change_type'],r['baseline_sha256'],r['current_sha256']) for r in rows};check(decl==actual,'target delta does not correspond exactly to frozen 225 inventory')
# Critical behavioral/authority guards.
def text(path):return (ROOT/path).read_text(errors='replace')
config=text('src/apps/daemon/internal/foundation/config/config.go');check('DefaultMutationAttempts = 3' in config,'mutation default attempts');check('MaxMutationAttempts     = 8' in config,'mutation max attempts');check('if options.ExpectedRevision != nil' in config and 'maxAttempts = 1' in config,'ExpectedRevision one attempt');check('RevisionConflict' in config,'revision conflict retry guard')
core=text('src/apps/daemon/internal/runtime/proxy/core_manager.go');check(core.count('unsupported protocol')>=2,'core managers fail closed');check('case protocolSOCKS5:' in core and 'case protocolHTTP:' in core,'SOCKS/HTTP explicit')
ss=text('src/apps/daemon/internal/networking/proxyconfig/parser_ss.go');check('2022-blake3-aes-128-gcm' in ss and '2022-blake3-aes-256-gcm' in ss and '2022-blake3-chacha20-poly1305' in ss,'SS2022 method lengths')
check(not (ROOT/'src/apps/daemon/internal/runtime/proxy/ss_cipher.go').exists(),'duplicate Go Shadowsocks cipher retired');check(not (ROOT/'src/apps/daemon/internal/runtime/proxy/ss_server.go').exists(),'duplicate Go Shadowsocks server retired');check(not (ROOT/'src/packages/lumicore/src/crypto/shadowsocks.rs').exists(),'duplicate Rust shadowsocks crypto retired');check(not (ROOT/'src/packages/lumicore/src/proxy/shadowsocks_aead.rs').exists(),'duplicate Rust shadowsocks AEAD retired')
socks=text('src/packages/lumicore/src/transport/socks5_client.rs');check('UnsupportedAddressType' in socks and 'InvalidTarget' in socks,'Rust SOCKS fail closed')
wg=text('src/apps/daemon/internal/analysis/diagnostics/wireguard_device_policy_plan.go');check('SourceIdentity' in wg and 'ExpiresAt' in wg and 'traffic-shape-modification-only' in wg,'MWGP guardrails')
handler=text('src/apps/daemon/internal/adapters/api/handlers_post_refactor_226_planners.go');check('http.Get' not in handler and 'http.Post' not in handler and 'exec.Command' not in handler and 'os.WriteFile' not in handler,'226 handlers are non-executing')
routes=text('src/apps/daemon/internal/adapters/api/routes.go') if (ROOT/'src/apps/daemon/internal/adapters/api/routes.go').exists() else ''.join(p.read_text(errors='replace') for p in (ROOT/'src/apps/daemon/internal/adapters/api').glob('*.go'))
for route in ('local-ruleset-plan','tailnet-transaction-plan','browser-proxy-handoff-plan','worker-affinity-plan','websocket-readiness-plan','gateway-composition-plan'):check(route in routes,f'route missing {route}')
# Natural product placement.
for path,need in [('src/packages/control-ui/src/pages/Rules.tsx','LocalRuleSetPlanner'),('src/packages/control-ui/src/pages/Settings.tsx','PostRefactor226SettingsPlanning'),('src/packages/control-ui/src/pages/Health.tsx','WorkerAffinityPlanner'),('src/packages/control-ui/src/pages/Connections.tsx','WebSocketReadinessPlanner'),('src/packages/control-ui/src/pages/Operations.tsx','GatewayCompositionPlanner')]:check(need in text(path),f'product placement {path}')
# Evidence generator/checker are canonical Makefile-owned tools once release closes.
make=text('Makefile');check('generate_post_refactor_226_evidence.py' in make,'226 evidence generator not wired in Makefile');check('check_post_refactor_226_convergence.py' in make,'226 checker not wired in Makefile')
if errors:
 print(f'POST_REFACTOR_226_FAIL assertions={assertions} errors={len(errors)}')
 for e in errors[:200]:print('ERROR',e)
 sys.exit(1)
print(f'POST_REFACTOR_226_OK assertions={assertions} donors=14 surfaces=1299 directories=244 symbols=15975 semantics=893 all_history_donors=52 delta={len(rows)}')
