#!/usr/bin/env python3
from __future__ import annotations
import csv, hashlib, json, os, re, stat, zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from collections import defaultdict

ROOT=Path(os.environ.get('LUMINET_227_TARGET_ROOT','/mnt/data/luminet227_work/target'))
ARCHIVE=Path(os.environ.get('LUMINET_227_ARCHIVE','/mnt/data/sni-spoofing-rust-main.zip'))
DONOR=Path(os.environ.get('LUMINET_227_DONOR_ROOT','/mnt/data/luminet227_work/donor'))
OUT=ROOT/'governance/convergence'
DONOR_ID='sni-spoofing-rust'
HIGH={'implementation','test','configuration','script','deployment','ui-or-product'}

def sha_bytes(b:bytes)->str:return hashlib.sha256(b).hexdigest()
def sha_file(p:Path)->str:
 h=hashlib.sha256()
 with p.open('rb') as f:
  for c in iter(lambda:f.read(1<<20),b''):h.update(c)
 return h.hexdigest()
def norm(name:str)->PurePosixPath:
 p=PurePosixPath(name.replace('\\','/'))
 if '\x00' in name or p.is_absolute() or any(x in ('','.','..') for x in p.parts):raise ValueError(f'unsafe path {name!r}')
 if p.parts and ':' in p.parts[0]:raise ValueError(f'drive path {name!r}')
 return p

def language(path:str)->str:
 e=Path(path).suffix.lower();n=Path(path).name.lower()
 return {'.rs':'Rust','.sh':'Shell','.json':'JSON','.toml':'TOML','.md':'Markdown','.yml':'YAML','.yaml':'YAML','.txt':'Text','.lock':'Lockfile','.gz':'Archive','.zip':'Archive'}.get(e,'Dockerfile' if n.startswith('dockerfile') else 'binary' if path.startswith('releases/') else 'other')
def classify(path:str)->str:
 q=path.lower();n=Path(q).name
 if q.startswith('.github/'):return 'repository-administration'
 if q.startswith('releases/'):return 'deployment'
 if q.startswith('docker/') or n.startswith('dockerfile'):return 'deployment'
 if q=='data/scan-snis.txt':return 'fixture'
 if re.search(r'(^|/)(test|tests)(/|$)',q) or '_test.' in q:return 'test'
 if q=='src/bin/ui.rs':return 'ui-or-product'
 if q.endswith('.rs'):return 'implementation'
 if n in ('cargo.toml','cargo.lock','makefile','config.json') or q.endswith(('.yml','.yaml','.toml','.json')):return 'configuration'
 if q.endswith('.sh'):return 'script'
 if n.startswith('readme') or 'license' in n or q.endswith(('.md','.txt')):return 'documentation'
 return 'repository-administration'

def module_key(path:str)->str:
 p=PurePosixPath(path); parts=p.parts
 if not parts:return '@root'
 if parts[0]=='.github':return '.github/workflows'
 if parts[0] in ('data','docker','releases'):return parts[0]
 if parts[0]!='src':return '@root'
 if len(parts)>1 and parts[1]=='packet':return 'src/packet'
 if len(parts)>1 and parts[1]=='sniffer':return 'src/sniffer'
 if len(parts)>1 and parts[1]=='bin':return 'src/bin'
 name=Path(path).stem
 if name in ('handler','listener','proxy','relay','proto'):return 'src/connection-lifecycle'
 if name in ('scan',):return 'src/scan'
 if name in ('xray',):return 'src/xray'
 if name in ('config','error'):return 'src/config-error'
 return 'src/runtime-shell'

@dataclass(frozen=True)
class Decision:
 disposition:str; transformation:str; topology:str; capability:str; nodes:str; invariant:str; negative:str; test:str; operator:str; validation:str; rationale:str; risk:str='medium'

def decision(key:str)->Decision:
 if key=='src/connection-lifecycle':
  return Decision('hardened','state-machine extraction + target hardening','many-to-one','SNI decoy connection evidence and sequence ownership','src/apps/daemon/internal/runtime/proxy/evasion_divert.go#connSeqKey;src/apps/daemon/internal/runtime/proxy/evasion_divert.go#TakeConnSeq;src/apps/daemon/internal/analysis/diagnostics/sni_decoy_handshake_plan.go#BuildSNIDecoyHandshakePlan','captured SYN evidence is exact-four-tuple scoped, bounded, expiring, and consumed once; handshake evidence has explicit allowed/failed transitions','port-only, stale, cross-flow, or fabricated fallback sequence evidence cannot authorize out-of-window injection; RST cannot be ignored','src/apps/daemon/internal/runtime/proxy/evasion_divert_test.go#TestConnSeqRegistryFourTupleIsolation;src/apps/daemon/internal/analysis/diagnostics/sni_decoy_handshake_plan_test.go#TestBuildSNIDecoyHandshakePlan','Operations/Connections','verified','The donor full-connection lifecycle exposed collision, lifetime, and handshake-state gaps. LumiNet extracts the safe evidence model without importing another relay/sniffer authority.','high')
 if key=='src/packet':
  return Decision('hardened','primitive extraction + single-owner consolidation','many-to-one','canonical TLS decoy construction','src/apps/daemon/internal/networking/tlsdecoy/decoy.go#BuildPaddedClientHello;src/packages/lumicore/src/evasion/sni_spoof.rs#build_padded_client_hello','decoy ClientHello construction is bounded to valid ASCII DNS SNI <=219 bytes and produces the canonical padded 517-byte structure','diagnostic and live Go paths cannot drift to independent TLS templates; malformed SNI or unchecked entropy cannot create a decoy','src/apps/daemon/internal/networking/tlsdecoy/decoy_test.go#TestBuildPaddedClientHello','Connections/Operations','verified','The donor 517-byte padded template is used as a protocol oracle; Go consumers now share one lower owner and Rust mirrors the corrected structure without claiming runtime validation.','high')
 if key=='src/sniffer':
  return Decision('reference-only','mechanism comparison + bounded extraction','one-to-many','platform raw-packet evidence','src/apps/daemon/internal/runtime/proxy/evasion_divert.go#RegisterConnSeq','existing Linux/Windows raw-packet owners remain authoritative; Darwin remains unsupported by the target live injector','donor AF_PACKET/WinDivert/BPF backends cannot silently create duplicate raw-packet authority or an unverified macOS support claim','scripts/checks/check_post_refactor_227_convergence.py#sniffer-authority','n/a','reviewed','Linux/Windows lifecycle ideas harden existing owners; the donor macOS BPF backend remains future-platform evidence because this environment cannot establish safe production parity.','high')
 if key=='src/scan':
  return Decision('superseded','oracle comparison','many-to-one','bounded SNI reachability diagnostics','src/apps/daemon/internal/analysis/diagnostics/sni_spoof_scan.go#RunSNISpoofScan','existing target scanner bounds, public-target admission, cancellation, and repeated stability evidence remain authoritative','donor defaults or candidate fan-out cannot weaken target admission/resource bounds','src/apps/daemon/internal/analysis/diagnostics/sni_spoof_scan_test.go','Operations','verified','The donor scanner is a useful behavioral oracle, but LumiNet already has a more bounded diagnostic owner and does not need a second scanner.','medium')
 if key=='data':
  return Decision('reference-only','corpus comparison','one-to-one','SNI candidate corpus evidence','src/apps/daemon/internal/analysis/diagnostics/sni_candidate_corpus.go#CuratedSNICandidates','candidate corpus changes require deliberate product/resource review','a larger peer list cannot be adopted merely to increase counts or implicit scan fan-out','scripts/checks/check_post_refactor_227_convergence.py#corpus-boundary','Operations','reviewed','The peer corpus is larger and useful for comparison, but the shipped curated corpus is retained because replacing it changes fan-out and evidence without a target requirement.','low')
 if key=='src/xray':
  return Decision('superseded','authority comparison','many-to-one','profile/core runtime ownership','src/apps/daemon/internal/runtime/proxy/core_manager.go#CoreManager','existing profile parser and core manager remain the only runtime/config owners','donor Xray parsing, launch, download, or config generation cannot bypass canonical profile/update/core ownership','scripts/checks/check_post_refactor_227_convergence.py#xray-supersession','Profiles/Connections','reviewed','Peer Xray integration duplicates mature target ownership and is retained only as compatibility/reference evidence.','high')
 if key=='src/bin':
  return Decision('guardrail-derived','negative-to-guardrail + UX comparison','negative-to-guardrail','operator SNI evidence workflow','src/packages/control-ui/src/pages/Operations.tsx#SNIDecoyHandshakePlanner','UI may collect/visualize evidence but remains non-authoritative','mutable latest downloads, direct runtime installation, raw-packet privilege acquisition, or local UI state cannot bypass target update/runtime authorities','src/packages/control-ui/scripts/test-post-refactor-227.mjs#ui-authority','Operations','verified','The peer UI contributes workflow context but its mutable downloader/installer authority is deliberately not inherited; LumiNet exposes only read-only handshake evidence.','high')
 if key=='releases':
  return Decision('rejected-with-reason','negative-to-guardrail','negative-to-guardrail','signed update admission','src/apps/daemon/internal/foundation/updateadmission','release artifacts are derived and update admission remains verified/signed/target-owned','bundled or mutable peer binaries cannot become source of truth or bypass signed update admission','scripts/checks/check_post_refactor_227_convergence.py#release-artifacts','Updates','reviewed','Prebuilt binaries are provenance/reference material only and never source authority.','high')
 if key in ('docker','.github/workflows'):
  return Decision('reference-only','operational comparison','one-to-one','build/deployment evidence','n/a','peer build/deploy surfaces remain evidence only','peer deployment automation cannot mutate target release authority','n/a','n/a','reviewed','Build/deploy material is accounted but not adopted because the target already has canonical release workflows.','low')
 if key in ('src/config-error','src/runtime-shell','@root'):
  return Decision('superseded','contract comparison + selective hardening','many-to-one','canonical SNI spoof runtime ownership','src/apps/daemon/internal/runtime/proxy/evasion_tunnel_conn.go#injectFakePacket;src/apps/daemon/internal/networking/tlsdecoy/decoy.go#BuildPaddedClientHello','existing runtime/config/error owners remain authoritative while donor-derived invariants are absorbed at their natural target seams','a second Rust proxy/listener/runtime/config stack cannot become parallel authority','scripts/checks/check_post_refactor_227_convergence.py#runtime-single-owner','Connections','reviewed','General runtime/config shell is donor packaging; only independently useful protocol/state invariants are promoted.','medium')
 raise KeyError(key)

# Validate archive + exact extracted bytes.
if not ARCHIVE.is_file() or not DONOR.is_dir():raise FileNotFoundError('227 donor archive/extraction missing')
with zipfile.ZipFile(ARCHIVE) as z:
 infos=z.infolist(); seen=set(); folded=set(); roots=set(); files=[]; total=0; symlinks=0
 for info in infos:
  p=norm(info.filename); name=p.as_posix().rstrip('/'); key=name.casefold()
  if name in seen or key in folded:raise ValueError(f'duplicate/case collision {name}')
  seen.add(name);folded.add(key);roots.add(p.parts[0]); mode=info.external_attr>>16; kind=stat.S_IFMT(mode)
  if stat.S_ISLNK(mode):symlinks+=1
  if kind not in (0,stat.S_IFREG,stat.S_IFDIR,stat.S_IFLNK):raise ValueError(f'special member {name}')
  if info.flag_bits&1:raise ValueError(f'encrypted {name}')
  if info.compress_size and info.file_size/info.compress_size>1000:raise ValueError(f'compression ratio {name}')
  total+=info.file_size
  if not info.is_dir():files.append((info,p,mode))
 if z.testzip():raise ValueError('CRC failure')
 if len(roots)!=1:raise ValueError(f'roots={roots}')
 archive_root=next(iter(roots))
 extracted={p.relative_to(DONOR).as_posix():p for p in DONOR.rglob('*') if p.is_file() or p.is_symlink()}
 zipped={}
 for info,p,mode in files:
  rel=PurePosixPath(*p.parts[1:]).as_posix()
  if rel:zipped[rel]=(info,mode,sha_bytes(z.read(info)))
 if set(zipped)!=set(extracted):raise ValueError(f'extracted path mismatch zip={len(zipped)} fs={len(extracted)}')
 for rel,(info,mode,h) in zipped.items():
  ep=extracted[rel]; eh=sha_bytes(os.readlink(ep).encode()) if ep.is_symlink() else sha_file(ep)
  if h!=eh:raise ValueError(f'byte mismatch {rel}')
archive_rows=[{'donor':DONOR_ID,'archive':ARCHIVE.name,'archive_sha256':sha_file(ARCHIVE),'members':len(infos),'files':len(zipped),'symlinks':symlinks,'uncompressed_bytes':total,'archive_root':archive_root,'validation':'verified-safe+crc+byte-equal'}]

surfaces=[]
for rel,(info,mode,h) in sorted(zipped.items()):
 c=classify(rel); derived=rel.startswith('releases/')
 surfaces.append({'donor':DONOR_ID,'path':rel,'sha256':h,'size_bytes':info.file_size,'file_type':'symlink' if stat.S_ISLNK(mode) else 'file','language':language(rel),'classification':c,'authority_status':'derived-artifact' if derived else ('authoritative-source' if c in HIGH else 'supporting-evidence'),'semantic_record_ids':'','surface_disposition':'','surface_rationale':''})

# Directory Merkle records including donor root.
rel_files=sorted([p for p in DONOR.rglob('*') if p.is_file() or p.is_symlink()],key=lambda p:p.relative_to(DONOR).as_posix())
dirs=[DONOR]+sorted([p for p in DONOR.rglob('*') if p.is_dir()],key=lambda p:p.relative_to(DONOR).as_posix())
directories=[]
for d in dirs:
 entries=[]
 for p in rel_files:
  try:r=p.relative_to(d)
  except ValueError:continue
  h=sha_bytes(os.readlink(p).encode()) if p.is_symlink() else sha_file(p); entries.append((r.as_posix(),h))
 payload=''.join(f'{h}  {r}\n' for r,h in entries).encode()
 directories.append({'donor':DONOR_ID,'path':'.' if d==DONOR else d.relative_to(DONOR).as_posix(),'descendant_files':len(entries),'tree_sha256':sha_bytes(payload)})

# repository -> module -> every high-signal file.
records=[]; module_record={}; file_record={}; seq=1
rep=surfaces[0]; base='PR227-R001'
records.append({'record_id':base,'parent_record_id':'n/a','composition_group_id':'CG227-repository','donor':DONOR_ID,'domain':'repository-accountability','value_unit':'sni-spoofing-rust complete repository accountability','source_granularity':'repository','value_form':'evidence corpus','separability':'context-dependent','donor_path':rep['path'],'donor_sha256':rep['sha256'],'donor_symbol':'n/a','transformation':'exhaustive review','mapping_topology':'one-to-many','disposition':'reference-only','decision_rationale':'Every donor surface is hash-accounted; independent module clusters and high-signal files receive child records.','target_capability':'convergence evidence','target_nodes':'n/a','invariant':'all donor files/directories/definitions remain traceable','negative_invariant':'repository accountability alone is never implementation evidence','test_node':'n/a','operator_surface':'governance/convergence/post-refactor-227-surface-accountability.csv','migration_impact':'none','license_note':'MIT provenance recorded from donor LICENSE; technical adoption decisions remain target-native','risk_tier':'low','dependency_record_ids':'n/a','evidence_confidence':'high','validation_status':'verified'})
seq=2
by_module=defaultdict(list)
for s in surfaces:by_module[module_key(s['path'])].append(s)
for key,items in sorted(by_module.items()):
 if not any(s['classification'] in HIGH for s in items) and key not in ('data',):continue
 d=decision(key); rep=min(items,key=lambda s:s['path']); rid=f'PR227-M{seq:03d}';seq+=1;module_record[key]=rid
 test='n/a' if d.disposition=='reference-only' and d.test=='n/a' else f'scripts/checks/check_post_refactor_227_convergence.py#semantic-{rid}'
 records.append({'record_id':rid,'parent_record_id':base,'composition_group_id':'CG227-'+re.sub(r'[^a-z0-9]+','-',d.capability.lower()).strip('-'),'donor':DONOR_ID,'domain':key,'value_unit':key+' semantics','source_granularity':'module/path cluster','value_form':'mechanism + tests + operational evidence','separability':'independently reviewable module cluster','donor_path':rep['path'],'donor_sha256':rep['sha256'],'donor_symbol':'n/a','transformation':d.transformation,'mapping_topology':d.topology,'disposition':d.disposition,'decision_rationale':d.rationale+(' Behavioral evidence: '+d.test if d.test!='n/a' else ''),'target_capability':d.capability,'target_nodes':d.nodes,'invariant':d.invariant,'negative_invariant':d.negative,'test_node':test,'operator_surface':d.operator,'migration_impact':'bounded successor hardening; existing runtime/write owners remain authoritative','license_note':'MIT donor provenance retained','risk_tier':d.risk,'dependency_record_ids':base,'evidence_confidence':'high','validation_status':d.validation})
for s in surfaces:
 if s['classification'] not in HIGH:continue
 key=module_key(s['path']); parent=module_record[key]; d=decision(key); rid=f'PR227-F{len(file_record)+1:04d}';file_record[s['path']]=rid
 test='n/a' if d.disposition=='reference-only' and d.test=='n/a' else f'scripts/checks/check_post_refactor_227_convergence.py#surface-{rid}'
 records.append({'record_id':rid,'parent_record_id':parent,'composition_group_id':'CG227-'+re.sub(r'[^a-z0-9]+','-',d.capability.lower()).strip('-'),'donor':DONOR_ID,'domain':'file:'+s['path'],'value_unit':s['path']+' file semantics','source_granularity':'file','value_form':s['classification']+' surface','separability':'independently hash-accounted file surface','donor_path':s['path'],'donor_sha256':s['sha256'],'donor_symbol':'n/a','transformation':d.transformation,'mapping_topology':d.topology,'disposition':d.disposition,'decision_rationale':d.rationale+f' File-level disposition: {s["path"]} independently reviewed inside {key}.','target_capability':d.capability,'target_nodes':d.nodes,'invariant':d.invariant,'negative_invariant':d.negative,'test_node':test,'operator_surface':d.operator,'migration_impact':'inherits module-level bounded convergence and cannot independently grant authority','license_note':'MIT donor provenance retained','risk_tier':d.risk,'dependency_record_ids':parent,'evidence_confidence':'high','validation_status':d.validation})
for s in surfaces:
 ids=[base];m=module_record.get(module_key(s['path']));f=file_record.get(s['path'])
 if m:ids.append(m)
 if f:ids.append(f)
 if s['classification'] in HIGH and (not m or not f):raise ValueError(f'high signal without focused record: {s["path"]}')
 s['semantic_record_ids']=';'.join(ids)
 s['surface_disposition']='focused-file-'+s['classification'] if f else 'accounted-supporting-'+s['classification']
 s['surface_rationale']='independent file-level disposition' if f else 'supporting/documentation/fixture surface explicitly accounted by donor record'+('; derived release artifact not source authority' if s['authority_status']=='derived-artifact' else '')

# Rust symbol accountability: functions/types/const/static/module/macro definitions.
symbols=[]; surf={s['path']:s for s in surfaces}
pat=[(re.compile(r'^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)'),'function'),(re.compile(r'^\s*(?:pub(?:\([^)]*\))?\s+)?(?:struct|enum|trait|type)\s+([A-Za-z_][A-Za-z0-9_]*)'),'type'),(re.compile(r'^\s*(?:pub(?:\([^)]*\))?\s+)?(?:const|static(?:\s+mut)?)\s+([A-Za-z_][A-Za-z0-9_]*)'),'constant'),(re.compile(r'^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)'),'module'),(re.compile(r'^\s*macro_rules!\s+([A-Za-z_][A-Za-z0-9_]*)'),'macro')]
for s in surfaces:
 if s['language']!='Rust':continue
 p=DONOR/s['path']
 for ln,line in enumerate(p.read_text(errors='replace').splitlines(),1):
  for rx,kind in pat:
   m=rx.match(line)
   if m:
    symbols.append({'donor':DONOR_ID,'path':s['path'],'sha256':s['sha256'],'line':ln,'kind':kind,'name':m.group(1),'extraction_policy':'rust-definition-index','semantic_record_ids':s['semantic_record_ids']});break

# Capability supersession map.
groups=defaultdict(list)
for r in records:
 if r['domain']!='repository-accountability':groups[r['target_capability']].append(r)
sup=[]
for cap,rs in sorted(groups.items()):
 sup.append({'target_capability':cap,'contributing_records':';'.join(r['record_id'] for r in rs),'donors':DONOR_ID,'dispositions':';'.join(sorted(set(r['disposition'] for r in rs))),'target_nodes':';'.join(sorted(set(r['target_nodes'] for r in rs))),'second_order_result':'peer mechanisms decompose into existing target owners; runtime/raw/update authority remains single-owned'})

OUT.mkdir(parents=True,exist_ok=True)
def write(name,rows,fields):
 with (OUT/name).open('w',newline='',encoding='utf-8') as f:w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(rows)
write('post-refactor-227-archive-accountability.csv',archive_rows,['donor','archive','archive_sha256','members','files','symlinks','uncompressed_bytes','archive_root','validation'])
write('post-refactor-227-surface-accountability.csv',surfaces,['donor','path','sha256','size_bytes','file_type','language','classification','authority_status','semantic_record_ids','surface_disposition','surface_rationale'])
write('post-refactor-227-directories.csv',directories,['donor','path','descendant_files','tree_sha256'])
write('post-refactor-227-symbols.csv',sorted(symbols,key=lambda r:(r['path'],int(r['line']),r['kind'],r['name'])),['donor','path','sha256','line','kind','name','extraction_policy','semantic_record_ids'])
ledger_fields=['record_id','parent_record_id','composition_group_id','donor','domain','value_unit','source_granularity','value_form','separability','donor_path','donor_sha256','donor_symbol','transformation','mapping_topology','disposition','decision_rationale','target_capability','target_nodes','invariant','negative_invariant','test_node','operator_surface','migration_impact','license_note','risk_tier','dependency_record_ids','evidence_confidence','validation_status']
write('post-refactor-227-adoption-ledger.csv',records,ledger_fields)
write('post-refactor-227-supersession-map.csv',sup,['target_capability','contributing_records','donors','dispositions','target_nodes','second_order_result'])
summary={'donors':1,'archive_members':len(infos),'surfaces':len(surfaces),'files':len(surfaces),'symlinks':symlinks,'directories_excluding_root':len(directories)-1,'directory_merkle_records':len(directories),'symbols':len(symbols),'semantic_records':len(records),'focused_module_records':len(module_record),'focused_file_records':len(file_record),'high_signal_surfaces':sum(s['classification'] in HIGH for s in surfaces),'high_signal_without_focused_record':sum(s['classification'] in HIGH and len(s['semantic_record_ids'].split(';'))<3 for s in surfaces),'ui_product_surfaces':sum(s['classification']=='ui-or-product' for s in surfaces)}
(OUT/'post-refactor-227-evidence-summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
print(json.dumps(summary,sort_keys=True))
