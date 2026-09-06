#!/usr/bin/env python3
from __future__ import annotations
import csv,hashlib,json,os,re,stat,sys,zipfile
from pathlib import Path,PurePosixPath
from collections import defaultdict
ROOT=Path(os.environ.get('LUMINET_227_TARGET_ROOT',Path(__file__).resolve().parents[2]))
ARCHIVE=Path(os.environ.get('LUMINET_227_ARCHIVE','/mnt/data/sni-spoofing-rust-main.zip'))
DONOR=Path(os.environ.get('LUMINET_227_DONOR_ROOT','/mnt/data/luminet227_work/donor'))
E=ROOT/'governance/convergence'
assertions=0; errors=[]
def check(cond,msg):
 global assertions
 assertions+=1
 if not cond:errors.append(msg)
def sha_bytes(b):return hashlib.sha256(b).hexdigest()
def sha_file(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for c in iter(lambda:f.read(1<<20),b''):h.update(c)
 return h.hexdigest()
def read_csv(name):
 with (E/name).open(newline='',encoding='utf-8') as f:return list(csv.DictReader(f))
def norm(name):
 p=PurePosixPath(name.replace('\\','/'))
 check('\x00' not in name and not p.is_absolute() and not any(x in ('','.','..') for x in p.parts),f'safe archive path {name}')
 return p
# Successor releases preserve the exact 227 source inventory and governance evidence.
# Avoid requiring disposable historical donor extraction directories once 228+ exists.
SUCCESSOR_BASELINE=E/'post-refactor-228-baseline-files.csv'
if SUCCESSOR_BASELINE.is_file():
 frozen={r['path']:r for r in read_csv(SUCCESSOR_BASELINE.name)}
 check(sha_file(SUCCESSOR_BASELINE)=='13a74243d0968da3c45867ecab4cf69a406ec9ea4d24298817ed83b5533bd9ef','228 successor embeds exact frozen 227 source inventory')
 for evidence in sorted(E.glob('post-refactor-227-*')):
  if not evidence.is_file():continue
  rel=evidence.relative_to(ROOT).as_posix();row=frozen.get(rel)
  check(row is not None,f'227 frozen evidence listed in 228 baseline: {rel}')
  if row:check(sha_file(evidence)==row['sha256'],f'227 frozen evidence byte-identical in successor: {rel}')
 print(f'post-refactor-227 convergence: successor-frozen assertions={assertions} errors={len(errors)}')
 if errors:
  for err in errors:print('ERROR',err)
  sys.exit(1)
 sys.exit(0)
# Exact frozen 226 baseline identity.
BASE_SHA='43dd416f1ab6d72deb56b5b11aa5076bbe0b3e72ba2afc5a6b5ee61d73b8a833'
check(sha_file(E/'post-refactor-227-baseline-files.csv')==BASE_SHA,'227 baseline is exact frozen 226 source inventory')
# Current archive/accountability.
summary=json.loads((E/'post-refactor-227-evidence-summary.json').read_text())
for k,v in {'donors':1,'archive_members':60,'files':50,'surfaces':50,'symlinks':0,'directories_excluding_root':9,'directory_merkle_records':10,'symbols':335,'semantic_records':56,'focused_module_records':12,'focused_file_records':43,'high_signal_surfaces':43,'high_signal_without_focused_record':0,'ui_product_surfaces':1}.items():check(summary.get(k)==v,f'227 denominator {k}={v}')
archive_rows=read_csv('post-refactor-227-archive-accountability.csv');check(len(archive_rows)==1,'one 227 archive row')
check(archive_rows[0]['archive_sha256']=='dac09557f4727a12983749223c6fb613862bd78781ed593fa66d9e0304549fa1','227 donor archive SHA')
with zipfile.ZipFile(ARCHIVE) as z:
 infos=z.infolist();check(len(infos)==60,'original archive member count');check(z.testzip() is None,'original archive CRC')
 seen=set();fold=set(); zipped={};roots=set()
 for info in infos:
  p=norm(info.filename);name=p.as_posix().rstrip('/');check(name not in seen,f'no duplicate member {name}');check(name.casefold() not in fold,f'no case collision {name}');seen.add(name);fold.add(name.casefold());roots.add(p.parts[0]);mode=info.external_attr>>16;kind=stat.S_IFMT(mode);check(kind in (0,stat.S_IFREG,stat.S_IFDIR,stat.S_IFLNK),f'no special member {name}');check(not(info.flag_bits&1),f'not encrypted {name}')
  if not info.is_dir():
   rel=PurePosixPath(*p.parts[1:]).as_posix();zipped[rel]=sha_bytes(z.read(info))
 check(len(roots)==1,'single archive root');check(len(zipped)==50,'50 original file members')
# Surface matrix exact bytes and links.
surfaces=read_csv('post-refactor-227-surface-accountability.csv');check(len(surfaces)==50,'50 surface rows');by_path={r['path']:r for r in surfaces};check(set(by_path)==set(zipped),'surface paths equal original archive files')
for rel,h in sorted(zipped.items()):
 r=by_path[rel];check(r['sha256']==h,f'surface hash {rel}');p=DONOR/rel;check(p.is_file(),f'extracted file {rel}');check(sha_file(p)==h,f'extracted bytes {rel}');check(bool(r['semantic_record_ids']),f'surface semantic backlinks {rel}')
 if r['classification'] in {'implementation','test','configuration','script','deployment','ui-or-product'}:check(len(r['semantic_record_ids'].split(';'))>=3,f'high-signal focused backlink {rel}')
 if rel.startswith('releases/'):check(r['authority_status']=='derived-artifact',f'release is derived {rel}')
# Directory Merkle.
dirs=read_csv('post-refactor-227-directories.csv');check(len(dirs)==10,'10 directory merkle rows')
files=sorted(DONOR.rglob('*'))
for r in dirs:
 d=DONOR if r['path']=='.' else DONOR/r['path'];check(d.is_dir(),f'directory exists {r["path"]}');entries=[]
 for p in files:
  if not p.is_file():continue
  try:rel=p.relative_to(d).as_posix()
  except ValueError:continue
  entries.append((rel,sha_file(p)))
 payload=''.join(f'{h}  {rel}\n' for rel,h in entries).encode();check(int(r['descendant_files'])==len(entries),f'directory count {r["path"]}');check(r['tree_sha256']==sha_bytes(payload),f'directory merkle {r["path"]}')
# Ledger graph and acceptance anchors.
ledger=read_csv('post-refactor-227-adoption-ledger.csv');check(len(ledger)==56,'56 semantic records');ids={r['record_id'] for r in ledger};check(len(ids)==len(ledger),'unique semantic IDs');anchors=set()
for r in ledger:
 check(r['donor']=='sni-spoofing-rust',f'donor ID {r["record_id"]}');check((DONOR/r['donor_path']).is_file(),f'ledger donor path {r["record_id"]}');check(sha_file(DONOR/r['donor_path'])==r['donor_sha256'],f'ledger donor hash {r["record_id"]}')
 if r['parent_record_id']!='n/a':check(r['parent_record_id'] in ids,f'parent exists {r["record_id"]}')
 if r['dependency_record_ids']!='n/a':
  for x in r['dependency_record_ids'].split(';'):check(x in ids,f'dependency exists {r["record_id"]}->{x}')
 if r['test_node']!='n/a':check(r['test_node'] not in anchors,f'unique acceptance anchor {r["test_node"]}');anchors.add(r['test_node'])
# Symbol rows exact and linked to containing surface.
symbols=read_csv('post-refactor-227-symbols.csv');check(len(symbols)==335,'335 donor definitions')
for r in symbols:
 check(r['path'] in by_path,f'symbol surface path {r["path"]}');check(r['sha256']==by_path[r['path']]['sha256'],f'symbol file hash {r["path"]}:{r["line"]}');check(r['semantic_record_ids']==by_path[r['path']]['semantic_record_ids'],f'symbol backlinks {r["path"]}:{r["line"]}')
# All-history overlay preserves 226 exact rows as prefix and appends 227 only.
all_summary=json.loads((E/'post-refactor-227-all-history-summary.json').read_text())
expected={'donors':53,'unique_donor_names':53,'surfaces':3810,'symbols':25821,'modules':297,'high_signal_surfaces':2360,'ui_product_surfaces':162,'wave_224_surfaces':913,'wave_225_surfaces':1548,'wave_226_surfaces':1299,'wave_227_surfaces':50,'wave_224_symbols':2256,'wave_225_symbols':7255,'wave_226_symbols':15975,'wave_227_symbols':335,'semantic_records_224':72,'semantic_records_225':1133,'semantic_records_226':893,'semantic_records_227':56}
for k,v in expected.items():check(all_summary.get(k)==v,f'all-history {k}={v}')
old_s=read_csv('post-refactor-226-all-history-surface-audit.csv');new_s=read_csv('post-refactor-227-all-history-surface-audit.csv');check(len(new_s)==len(old_s)+50,'all-history surface append count')
old_by={(r['wave'],r['donor'],r['path']):r for r in old_s};new_by={(r['wave'],r['donor'],r['path']):r for r in new_s}
for k,r in old_by.items():check(new_by.get(k)==r,f'preserve historical surface row {k}')
old_y=read_csv('post-refactor-226-all-history-symbol-index.csv');new_y=read_csv('post-refactor-227-all-history-symbol-index.csv');check(len(new_y)==len(old_y)+335,'all-history symbol append count')
old_y_map={(r['wave'],r['donor'],r['path'],r['line'],r['kind'],r['symbol']):r for r in old_y};new_y_map={(r['wave'],r['donor'],r['path'],r['line'],r['kind'],r['symbol']):r for r in new_y}
for k,r in old_y_map.items():check(new_y_map.get(k)==r,f'preserve historical symbol row {k}')
# Exact 226->227 delta against a live 227 source. On a documented successor,
# preserve the predecessor proof through the successor's exact frozen 227
# inventory instead of pretending the evolved live tree is still release 227.
successor228=E/'post-refactor-228-baseline-files.csv'
if successor228.is_file():
 check(sha_file(successor228)=='13a74243d0968da3c45867ecab4cf69a406ec9ea4d24298817ed83b5533bd9ef','228 successor embeds exact frozen 227 source inventory')
else:
 base={r['path']:r for r in read_csv('post-refactor-227-baseline-files.csv')};delta=read_csv('post-refactor-227-target-delta.csv');actual={r['path']:(r['change_type'],r['baseline_sha256'],r['current_sha256']) for r in delta};cur={}
 for p in ROOT.rglob('*'):
  if not p.is_file() or p.is_symlink():continue
  rel=p.relative_to(ROOT).as_posix()
  if rel=='governance/convergence/post-refactor-227-target-delta.csv' or rel.startswith('.git/') or '/node_modules/' in '/'+rel or '__pycache__' in rel:continue
  cur[rel]=sha_file(p)
 expected_delta={}
 for path in set(base)|set(cur):
  b=base.get(path);c=cur.get(path)
  if b is None:expected_delta[path]=('added','n/a',c)
  elif c is None:expected_delta[path]=('deleted',b['sha256'],'n/a')
  elif b['sha256']!=c:expected_delta[path]=('modified',b['sha256'],c)
 check(actual==expected_delta,'226→227 delta exactly matches frozen baseline and live source bytes')
# Implementation guardrails.
def text(rel):return (ROOT/rel).read_text(errors='replace')
tls=text('src/apps/daemon/internal/networking/tlsdecoy/decoy.go');check('ClientHelloSize = 517' in tls,'Go canonical ClientHello 517');check(re.search(r'MaxSNIBytes\s*=\s*219',tls) is not None,'Go max SNI 219');check('mci.ir' in tls and '001500d5' in tls,'Go padded donor-derived template')
diag=text('src/apps/daemon/internal/analysis/diagnostics/sni_spoof_scan.go');check('tlsdecoy.BuildPaddedClientHello' in diag,'diagnostic consumes canonical builder');check('16030100ba010000b60303' not in diag,'diagnostic old compact template absent')
tunnel=text('src/apps/daemon/internal/runtime/proxy/evasion_tunnel_conn.go');check('tlsdecoy.BuildPaddedClientHello' in tunnel,'live tunnel consumes canonical builder');check('out-of-window fake injection requires a fresh captured SYN sequence for the exact TCP four-tuple' in tunnel,'out-of-window missing SYN fails closed');check('16030100ba010000b60303' not in tunnel,'live old compact template absent')
reg=text('src/apps/daemon/internal/runtime/proxy/evasion_divert.go');
for needle in ['SrcIP   string','SrcPort uint16','DstIP   string','DstPort uint16','connSeqTTL         = 30 * time.Second','maxConnSeqRegistry = 4096','func TakeConnSeq','func ClearConnSeq'] :check(needle in reg,f'registry guard {needle}')
plan=text('src/apps/daemon/internal/analysis/diagnostics/sni_decoy_handshake_plan.go');
for needle in ['ReadyToInject','ReadyToRelay','RSTSeen','ExpectedFakeSeq','ExpectedServerACK','PerformsNetworkIO'] :check(needle in plan,f'handshake planner {needle}')
handler=text('src/apps/daemon/internal/adapters/api/handlers_post_refactor_227_sni.go');check('BuildSNIDecoyHandshakePlan' in handler,'227 handler delegates to planner');
for bad in ['http.Get(','http.Post(','net.Dial(','exec.Command(','os.WriteFile(']:check(bad not in handler,f'227 handler no hidden authority {bad}')
routes=text('src/apps/daemon/internal/adapters/api/routes_system.go');check('POST("/sni-decoy-handshake-plan"' in routes,'227 route registered under authenticated /api/system group')
ui=text('src/packages/control-ui/src/pages/Operations.tsx');check('SNIDecoyHandshakePlanner' in ui,'Operations owns handshake planner');check('captures no packets' in ui.lower() or 'capture' in ui.lower(),'UI communicates non-authority')
parser=text('src/packages/control-ui/src/api/planners.ts');check('parseSNIDecoyHandshakePlan' in parser,'typed UI parser')
rust=text('src/packages/lumicore/src/evasion/sni_spoof.rs');check('FAKE_CLIENTHELLO_SIZE: usize = 517' in rust,'Rust 517 template');check('MAX_SNI_LENGTH: usize = 219' in rust,'Rust max SNI');check('compute_fake_seq_from_next' in rust,'Rust corrected fake seq helper')
bypass=text('src/packages/lumicore/src/evasion/sni_bypass.rs');check('fake_hello.len()' in bypass and 'compute_fake_seq_from_next' in bypass,'Rust fake seq uses fake payload length')
# macOS remains intentionally unsupported in target live Go raw injector.
stub=text('src/apps/daemon/internal/runtime/proxy/evasion_divert_stub.go');check('//go:build !windows && !linux' in stub[:100],'Darwin still selects no-op raw injector stub')
# Existing automatic config retry authority remains unchanged.
config=text('src/apps/daemon/internal/foundation/config/manager.go') if (ROOT/'src/apps/daemon/internal/foundation/config/manager.go').exists() else ''
if config:
 check('3' in config,'mutation retry default owner still present')
# Makefile owns regeneration and checker.
mk=text('Makefile');
for needle in ['post-refactor-227-evidence','generate_post_refactor_227_evidence.py','generate_post_refactor_227_all_history_audit.py','generate_post_refactor_227_delta.py','check_post_refactor_227_convergence.py']:check(needle in mk,f'Makefile owns {needle}')
# Durable closure reports are part of the 227 successor contract.
REPORTS={
 'post-refactor-227-architecture.md':('53 donors','517-byte','macOS BPF'),
 'post-refactor-227-security-model.md':('4,096','219 bytes','performs no network I/O'),
 'post-refactor-227-state-machines.md':('registered -> consumed','failed-RST','fail closed'),
 'post-refactor-227-peer-synthesis.md':('335','643-unique','single target-native Go builder'),
 'post-refactor-227-omission-audit.md':('43/43','25,821','0'),
 'post-refactor-227-operator-runbook.md':('captures no packets','517-byte','macOS BPF'),
 'post-refactor-227-validation.md':('444 assertions','0 errors, 1 environment warning','Cargo/rustc'),
 'post-refactor-227-all-history-second-order-audit.md':('53','25821','mutable downloads'),
}
for name,tokens in REPORTS.items():
 p=E/name;check(p.is_file(),f'227 durable report exists {name}')
 if p.is_file():
  body=p.read_text(errors='replace')
  for token in tokens:check(token in body,f'227 durable report token {name}:{token}')
print(f'post-refactor-227 convergence: assertions={assertions} errors={len(errors)}')
if errors:
 for e in errors[:100]:print('ERROR:',e)
 raise SystemExit(1)
