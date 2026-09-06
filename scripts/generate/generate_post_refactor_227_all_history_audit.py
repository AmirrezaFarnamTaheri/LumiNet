#!/usr/bin/env python3
from __future__ import annotations
import csv,hashlib,json,re,os
from pathlib import Path,PurePosixPath
from collections import defaultdict,Counter
ROOT=Path(os.environ.get('LUMINET_227_TARGET_ROOT','/mnt/data/luminet227_work/target'))
OUT=ROOT/'governance/convergence'

def read(name):
 with (OUT/name).open(newline='',encoding='utf-8') as f:return list(csv.DictReader(f))
def write(name,rows):
 if not rows:raise ValueError(name)
 with (OUT/name).open('w',newline='',encoding='utf-8') as f:
  w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
def mod(path):
 p=PurePosixPath(path); parts=p.parts
 if not parts:return '@root'
 if parts[0]=='.github':return '.github/workflows'
 if parts[0] in ('data','docker','releases'):return parts[0]
 if parts[0]!='src':return '@root'
 if len(parts)>1 and parts[1] in ('packet','sniffer','bin'):return 'src/'+parts[1]
 n=Path(path).stem
 if n in ('handler','listener','proxy','relay','proto'):return 'src/connection-lifecycle'
 if n=='scan':return 'src/scan'
 if n=='xray':return 'src/xray'
 if n in ('config','error'):return 'src/config-error'
 return 'src/runtime-shell'

old=[dict(r) for r in read('post-refactor-226-all-history-surface-audit.csv')]
cur=read('post-refactor-227-surface-accountability.csv')
layers={'implementation':'backend/runtime','test':'test/oracle','configuration':'data/config','script':'operations/deployment','deployment':'operations/deployment','ui-or-product':'frontend/UI/UX','fixture':'test/fixture','documentation':'documentation','repository-administration':'support/repository'}
outcome={
 'src/connection-lifecycle':('runtime/security/control-plane','four-tuple expiring single-use SYN evidence + explicit handshake lifecycle','Operations/Connections'),
 'src/packet':('networking/security','single canonical 517-byte padded TLS decoy builder','Connections/Operations'),
 'src/sniffer':('runtime/security','existing Linux/Windows raw owners retained; macOS BPF stays reference-only','n/a'),
 'src/scan':('analysis/control-plane','existing bounded SNI scanner remains authoritative','Operations'),
 'data':('analysis/reference','peer SNI corpus retained as comparison evidence; curated target corpus unchanged','Operations'),
 'src/xray':('runtime/integration','Xray/profile runtime superseded by canonical core/profile owners','Profiles/Connections'),
 'src/bin':('frontend/security','read-only handshake evidence UX; mutable downloader authority rejected','Operations'),
 'releases':('release/security','derived peer binaries rejected as source/update authority','Updates'),
 'docker':('deployment/reference','peer deployment evidence only','n/a'),
 '.github/workflows':('deployment/reference','peer CI/release evidence only','n/a'),
 'src/config-error':('runtime/config','target-native config/error owners remain authoritative','Connections'),
 'src/runtime-shell':('runtime','peer runtime shell superseded; extracted invariants live in existing owners','Connections'),
 '@root':('support/reference','repository/build metadata evidence','n/a'),
}
rows=old[:]
for r in cur:
 key=mod(r['path']);layer,oc,prod=outcome[key]
 rows.append({'wave':'227','donor':r['donor'],'path':r['path'],'sha256':r['sha256'],'size_bytes':r['size_bytes'],'classification':r['classification'],'source_layer':layers.get(r['classification'],'support'),'semantic_record_ids':r['semantic_record_ids'],'original_disposition':r['surface_disposition'],'current_target_layer':layer,'cross_wave_outcome':oc,'current_product_surface':prod})
rows.sort(key=lambda r:(int(r['wave']) if str(r['wave']).isdigit() else 999,r['donor'],r['path']))
write('post-refactor-227-all-history-surface-audit.csv',rows)
# Symbols preserve old bytes/meaning and append current wave.
sym=[dict(r) for r in read('post-refactor-226-all-history-symbol-index.csv')]
for r in read('post-refactor-227-symbols.csv'):
 sym.append({'wave':'227','donor':r['donor'],'path':r['path'],'sha256':r['sha256'],'line':r['line'],'kind':r['kind'],'symbol':r['name'],'semantic_record_ids':r['semantic_record_ids']})
sym.sort(key=lambda r:(int(r['wave']) if str(r['wave']).isdigit() else 999,r['donor'],r['path'],int(r['line']) if str(r['line']).isdigit() else 0,r['kind'],r['symbol']))
write('post-refactor-227-all-history-symbol-index.csv',sym)
# Preserve previous module rows, append 227 module groups.
mods=[dict(r) for r in read('post-refactor-226-all-history-module-audit.csv')]
g=defaultdict(list)
for r in rows:
 if r['wave']=='227':g[(r['wave'],r['donor'],mod(r['path']))].append(r)
for (wave,donor,m),items in sorted(g.items()):
 c=Counter(i['classification'] for i in items); lays=sorted(set(i['source_layer'] for i in items)); products=sorted(set(i['current_product_surface'] for i in items if i['current_product_surface']!='n/a'))
 mods.append({'wave':wave,'donor':donor,'module':m,'surfaces':len(items),'high_signal_surfaces':sum(c[k] for k in ('implementation','test','configuration','script','deployment','ui-or-product')),'ui_product_surfaces':c['ui-or-product'],'implementation_surfaces':c['implementation'],'test_surfaces':c['test'],'layers':';'.join(lays),'current_outcome':' | '.join(sorted(set(i['cross_wave_outcome'] for i in items))),'current_product_surfaces':';'.join(products) if products else 'n/a','surface_sha256':hashlib.sha256('\n'.join(f"{i['path']}\0{i['sha256']}" for i in sorted(items,key=lambda x:x['path'])).encode()).hexdigest()})
mods.sort(key=lambda r:(int(r['wave']) if str(r['wave']).isdigit() else 999,r['donor'],r['module']))
write('post-refactor-227-all-history-module-audit.csv',mods)
summary={'donors':len(set((r['wave'],r['donor']) for r in rows)),'unique_donor_names':len(set(r['donor'] for r in rows)),'surfaces':len(rows),'symbols':len(sym),'modules':len(mods),'wave_224_surfaces':sum(r['wave']=='224' for r in rows),'wave_225_surfaces':sum(r['wave']=='225' for r in rows),'wave_226_surfaces':sum(r['wave']=='226' for r in rows),'wave_227_surfaces':sum(r['wave']=='227' for r in rows),'wave_224_symbols':sum(r['wave']=='224' for r in sym),'wave_225_symbols':sum(r['wave']=='225' for r in sym),'wave_226_symbols':sum(r['wave']=='226' for r in sym),'wave_227_symbols':sum(r['wave']=='227' for r in sym),'semantic_records_224':len(read('post-refactor-224-adoption-ledger.csv')),'semantic_records_225':len(read('post-refactor-225-adoption-ledger.csv')),'semantic_records_226':len(read('post-refactor-226-adoption-ledger.csv')),'semantic_records_227':len(read('post-refactor-227-adoption-ledger.csv')),'ui_product_surfaces':sum(r['classification']=='ui-or-product' for r in rows),'high_signal_surfaces':sum(r['classification'] in {'implementation','test','configuration','script','deployment','ui-or-product'} for r in rows)}
(OUT/'post-refactor-227-all-history-summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
lines=['# Post-refactor-227 all-history second-order convergence audit','', 'The immutable 224/225/226 evidence is preserved and the single 227 donor is appended without rewriting historical record IDs.','', '## Mechanical denominator','',f"- Wave-scoped donors: **{summary['donors']}**.",f"- Surfaces: **{summary['surfaces']}** ({summary['wave_224_surfaces']} + {summary['wave_225_surfaces']} + {summary['wave_226_surfaces']} + {summary['wave_227_surfaces']}).",f"- Definition-level symbols: **{summary['symbols']}** ({summary['wave_224_symbols']} + {summary['wave_225_symbols']} + {summary['wave_226_symbols']} + {summary['wave_227_symbols']}).",f"- Module/subtree groups: **{summary['modules']}**.",f"- High-signal surfaces: **{summary['high_signal_surfaces']}**.",f"- UI/product donor surfaces: **{summary['ui_product_surfaces']}**.",f"- Semantic records retained/appended: **{summary['semantic_records_224']} + {summary['semantic_records_225']} + {summary['semantic_records_226']} + {summary['semantic_records_227']}**.",'','## 227 second-order result','','- Connection identity/lifetime evidence hardens the existing SYN-sequence owner rather than introducing the donor sniffer/relay state authority.','- The donor TLS template is extracted into one Go networking owner shared by diagnostics and the live tunnel; Rust mirrors the corrected structure but remains static-only in this environment.','- Full SYN/SYN-ACK/third-ACK/fake/server-ACK/RST semantics are exposed as a read-only evidence planner because the live target capture path does not yet observe the complete server lifecycle.','- Linux/Windows raw-packet runtime ownership remains target-native; donor macOS BPF remains reference-only until Darwin runtime evidence exists.','- Donor Xray runtime, mutable downloads, prebuilt binaries and installation paths do not bypass canonical profile/core/update ownership.','- The larger peer SNI corpus remains reference evidence; the curated target corpus is unchanged rather than enlarged for count alone.']
(OUT/'post-refactor-227-all-history-second-order-audit.md').write_text('\n'.join(lines)+'\n')
print(json.dumps(summary,sort_keys=True))
