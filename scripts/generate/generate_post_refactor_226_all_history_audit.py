#!/usr/bin/env python3
from __future__ import annotations
import csv,hashlib,json
from collections import Counter,defaultdict
from pathlib import Path,PurePosixPath
ROOT=Path(__file__).resolve().parents[2];OUT=ROOT/'governance/convergence'

def read(p):
 with p.open(newline='',encoding='utf-8') as f:return list(csv.DictReader(f))
def write(p,rows,fields=None):
 p.parent.mkdir(parents=True,exist_ok=True)
 if not rows:return
 with p.open('w',newline='',encoding='utf-8') as f:
  w=csv.DictWriter(f,fieldnames=fields or list(rows[0]));w.writeheader();w.writerows(rows)
def mod(path):
 p=PurePosixPath(path);return 'root' if len(p.parts)<=1 else p.parts[0]

old=read(OUT/'post-refactor-225-all-history-surface-audit.csv')
cur=read(OUT/'post-refactor-226-surface-accountability.csv')
product={
 'shadowsocks-crypto':('runtime/security','SS2022 key admission + sole external-core runtime','Profiles/Connections'),
 'shadowsocksr':('security/runtime','unsupported SSR/unknown protocol fails closed','Connections'),
 'shadowsocks-rust':('runtime/security','runtime/crypto oracle; duplicate local authorities retired','Profiles/Connections'),
 'srsc':('data/control-plane/product','local bounded rule normalization only','Rules'),
 'subconverter':('data/control-plane/product','local bounded rule normalization; remote/template/script server authority superseded','Rules'),
 'ssh':('runtime/security','pre-network authentication admission around dependency-owned SSH','Connections'),
 'tailscale-client':('control-plane/product','credential-free transactional change plan','Settings'),
 'tinytun':('runtime/security','SOCKS wire bounds; TUN/eBPF/process runtime superseded','Connections'),
 'tools':('control-plane/product','HTTP 101 WebSocket protocol readiness evidence','Connections'),
 'browser-ext':('control-plane/product','profile/native-host/loopback handoff readiness without mutation','Settings'),
 'tsheadroom':('control-plane/product','deterministic affinity/deadline/restart planning','Health'),
 'mwgp':('security/control-plane','source-bound expiring receiver-index mappings + obfuscation claim guardrail','Operations'),
 'paas-gateway':('deployment/control-plane/product','immutable gateway DAG/start/rollback/recovery plan','Operations'),
 'reverse-tls':('deployment/control-plane/product','reverse/listener lifecycle recomposed into gateway DAG','Operations'),
}
layers={'implementation':'backend/runtime','test':'test/oracle','configuration':'data/config','script':'operations/deployment','deployment':'operations/deployment','ui-or-product':'frontend/UI/UX','fixture':'test/fixture','documentation':'documentation','repository-administration':'support/repository'}
rows=[]
for r in old:
 rows.append(dict(r))
for r in cur:
 layer,outcome,surface=product[r['donor']]
 rows.append({'wave':'226','donor':r['donor'],'path':r['path'],'sha256':r['sha256'],'size_bytes':r['size_bytes'],'classification':r['classification'],'source_layer':layers.get(r['classification'],'support'),'semantic_record_ids':r['semantic_record_ids'],'original_disposition':r['surface_disposition'],'current_target_layer':layer,'cross_wave_outcome':outcome,'current_product_surface':surface})
rows.sort(key=lambda r:(r['wave'],r['donor'],r['path']))
write(OUT/'post-refactor-226-all-history-surface-audit.csv',rows)
# Symbols: inherit normalized 225 all-history + current rich 226.
sym=[]
for r in read(OUT/'post-refactor-225-all-history-symbol-index.csv'):
 sym.append(dict(r))
for r in read(OUT/'post-refactor-226-symbols.csv'):
 sym.append({'wave':'226','donor':r['donor'],'path':r['path'],'sha256':r['sha256'],'line':r['line'],'kind':r['kind'],'symbol':r['name'],'semantic_record_ids':r['semantic_record_ids']})
sym.sort(key=lambda r:(r['wave'],r['donor'],r['path'],int(r['line']) if str(r['line']).isdigit() else 0,r['kind'],r['symbol']))
write(OUT/'post-refactor-226-all-history-symbol-index.csv',sym)
# Preserve immutable 225 module rows, append 226 top-level subtree groups.
mods=[dict(r) for r in read(OUT/'post-refactor-225-all-history-module-audit.csv')]
g=defaultdict(list)
for r in rows:
 if r['wave']=='226':g[(r['wave'],r['donor'],mod(r['path']))].append(r)
for (wave,donor,m),items in sorted(g.items()):
 c=Counter(i['classification'] for i in items);lays=sorted(set(i['source_layer'] for i in items));products=sorted(set(i['current_product_surface'] for i in items if i['current_product_surface']!='n/a'))
 mods.append({'wave':wave,'donor':donor,'module':m,'surfaces':len(items),'high_signal_surfaces':sum(c[k] for k in ('implementation','test','configuration','script','deployment','ui-or-product')),'ui_product_surfaces':c['ui-or-product'],'implementation_surfaces':c['implementation'],'test_surfaces':c['test'],'layers':';'.join(lays),'current_outcome':' | '.join(sorted(set(i['cross_wave_outcome'] for i in items))),'current_product_surfaces':';'.join(products) if products else 'n/a','surface_sha256':hashlib.sha256('\n'.join(f"{i['path']}\0{i['sha256']}" for i in sorted(items,key=lambda x:x['path'])).encode()).hexdigest()})
mods.sort(key=lambda r:(r['wave'],r['donor'],r['module']))
write(OUT/'post-refactor-226-all-history-module-audit.csv',mods)
summary={
 'donors':len(set((r['wave'],r['donor']) for r in rows)),
 'unique_donor_names':len(set(r['donor'] for r in rows)),
 'surfaces':len(rows),'symbols':len(sym),'modules':len(mods),
 'wave_224_surfaces':sum(r['wave']=='224' for r in rows),'wave_225_surfaces':sum(r['wave']=='225' for r in rows),'wave_226_surfaces':sum(r['wave']=='226' for r in rows),
 'wave_224_symbols':sum(r['wave']=='224' for r in sym),'wave_225_symbols':sum(r['wave']=='225' for r in sym),'wave_226_symbols':sum(r['wave']=='226' for r in sym),
 'semantic_records_224':len(read(OUT/'post-refactor-224-adoption-ledger.csv')),'semantic_records_225':len(read(OUT/'post-refactor-225-adoption-ledger.csv')),'semantic_records_226':len(read(OUT/'post-refactor-226-adoption-ledger.csv')),
 'ui_product_surfaces':sum(r['classification']=='ui-or-product' for r in rows),
 'high_signal_surfaces':sum(r['classification'] in {'implementation','test','configuration','script','deployment','ui-or-product'} for r in rows),
}
(OUT/'post-refactor-226-all-history-summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
lines=['# Post-refactor-226 all-history second-order convergence audit','',f"The immutable 224/225 evidence is preserved and the 14-donor 226 wave is overlaid without rewriting historical record IDs.",'','## Mechanical denominator','',f"- Wave-scoped donors: **{summary['donors']}**.",f"- Surfaces: **{summary['surfaces']}** ({summary['wave_224_surfaces']} + {summary['wave_225_surfaces']} + {summary['wave_226_surfaces']}).",f"- Definition-level symbols: **{summary['symbols']}** ({summary['wave_224_symbols']} + {summary['wave_225_symbols']} + {summary['wave_226_symbols']}).",f"- Top-level module/subtree groups: **{summary['modules']}**.",f"- High-signal surfaces: **{summary['high_signal_surfaces']}**.",f"- UI/product donor surfaces: **{summary['ui_product_surfaces']}**.",f"- Semantic records retained/appended: **{summary['semantic_records_224']} + {summary['semantic_records_225']} + {summary['semantic_records_226']}**.",'','## 226 composition results','']
for d,(layer,outcome,surface) in sorted(product.items()):lines.append(f'- **{d}** → {layer}: {outcome}. Product surface: {surface}.')
lines += ['','## Cross-wave invariants','','- Existing 224/225 source/evidence identities are historical facts; successor changes are represented as a new wave rather than back-edited into old ledgers.','- Runtime/write authority remains single-owned. New 226 planners are non-executing and cannot dial, fetch, register browser hosts, call Tailnet, start processes, or install service configuration.','- Unsupported proxy protocols fail closed; SS2022 key material is validated before runtime handoff.','- Receiver-index translation never weakens WireGuard authentication/replay semantics and packet obfuscation is classified as traffic-shape modification only.','- Automatic configuration mutation retry remains single-owned with 3 default attempts, max 8, fresh state on revision conflicts, conflict-only replay, and one attempt under explicit ExpectedRevision.']
(OUT/'post-refactor-226-all-history-second-order-audit.md').write_text('\n'.join(lines)+'\n')
print(json.dumps(summary,sort_keys=True))
