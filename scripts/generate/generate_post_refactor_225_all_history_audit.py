#!/usr/bin/env python3
from __future__ import annotations
import csv, hashlib, json
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'governance/convergence'

SURFACES={
 '224':OUT/'post-refactor-224-surface-accountability.csv',
 '225':OUT/'post-refactor-225-surface-accountability.csv',
}
SYMBOLS={
 '224':OUT/'post-refactor-224-symbols.csv',
 '225':OUT/'post-refactor-225-symbols.csv',
}
LEDGERS={
 '224':OUT/'post-refactor-224-adoption-ledger.csv',
 '225':OUT/'post-refactor-225-adoption-ledger.csv',
}

# Cross-wave product/ownership uplift: immutable 224 evidence remains untouched;
# this overlay records where current 225 product/backend composition now exposes
# or strengthens value originally mined in 224.
UPLIFT={
 'kcp-go-master':('runtime/control-plane','shared KCP policy + real Go KCP runtime; AES-GCM opt-in; bounded FEC/tuning','Operations convergence lab; Connections runtime evidence'),
 'libkcp-master':('runtime/control-plane','KCP/FEC protocol/test oracles consolidated into shared KCP policy/runtime','Operations convergence lab'),
 'l7mp-master':('control-plane/product','health/load/circuit dispatch semantics recomposed into bounded endpoint pool','Connections · Endpoint dispatch evidence'),
 'load-balancer-master':('control-plane/product','load/dispatch/failure semantics superseded by bounded quality-first endpoint pool','Connections · Endpoint dispatch evidence'),
 'log-demultiplexer-master':('observability/product','backpressure/drop evidence productized as local filter/export and websocket loss counters','Logs'),
 'luci-app-https-dns-proxy-main':('data/control-plane/product','resolver provider catalog + policy/fallback evidence exposed without UCI ownership','DNS · presets, policy, DoH pool evidence'),
 'l7-protocols-master':('security/control-plane/product','offline bounded RE2 signature admission; no DPI install authority','Rules · L7 signature admission'),
 'Iran-v2ray-rules-main':('data/control-plane/product','routing corpus provenance and immutable-artifact admission, mutable donor lists remain non-authoritative','Rules · routing artifact provenance'),
 'Iran-configs-main':('test/security','proxy-format/parser oracles only; credential-bearing live endpoints never imported','Proxy parser tests / governance'),
 'JJTcpOverHttpRelayVpn-python_testing_tcp_relay':('runtime/control-plane','adaptive idle polling extracted; scripted/MITM relay authority rejected','Runtime relay + Operations relay inspection'),
 'marionette-master':('control-plane','bounded declarative traffic profile/state-graph planner; plugins/actions never execute','Operations convergence lab'),
 'l7-snake-main':('control-plane','mesh route evidence with stale/unhealthy exclusion and bounded degraded penalty','Operations mesh diagnostics'),
 'libXray-main':('runtime/test','format/config/platform utility oracles; target runtime/parser owners remain authoritative','Proxy/runtime tests'),
 'mhurl-main':('security/test','ambiguous multi-authority URL cases become parser guardrails','Proxy parser tests'),
 'LACUNA-Chain-main':('security/authority','negative guardrail: call-stack/EDR-spoofing capability removed from production surface','No operator authority'),
}

PRODUCT_225={
 'uptimeflare':('observability/product','incident/maintenance lifecycle + recovery/grace/cooldown evidence','Health; Logs'),
 'sing-dns':('data/control-plane/product','DNS transport/fallback/cache/ECS/truncation policy without a second resolver','DNS'),
 'sing-mux':('runtime/control-plane/product','multiplex admission/capacity/padding/accounting policy around single SMUX owner','Connections'),
 'sing-box-rules':('data/control-plane/product','remote routing artifact provenance/digest admission without install authority','Rules'),
 'routing-list':('data/control-plane/product','rule grammar/provenance fixtures without importing mutable lists','Rules'),
 'v2rayng':('product/runtime/security','profile search/mobile lifecycle/import/update/VPN oracles; stronger target owners retained','Profiles; Rules; Settings'),
 'warpscanner-android':('control-plane/product','ranked WARP scan evidence and export without activation/persistence authority','Settings'),
 'utls':('runtime/control-plane','fingerprint trial/reuse policy while TLS/ECH/QUIC internals remain upstream/current-owner','Operations; TLS runtime'),
 'wintun':('runtime/security','ring/packet admission hardens live Wintun owner; duplicate wrapper removed','Windows TUN runtime'),
 'wireguard-go':('runtime/control-plane/security','AllowedIPs/replay/rate/cookie/key lifecycle readiness around existing WireGuard owner','Operations WireGuard planner'),
 'wormhole':('control-plane','bounded declarative network workflow with reverse cleanup; no shell/docker/netns execution','Operations workflow planner'),
 'tuic-impl':('runtime/security','TUIC wire/option bounds; false raw-TCP covert TUIC retired','Core TUIC owner'),
 'tuic-spec':('runtime/security','protocol framing/auth/0-RTT semantics used as target wire oracle','Core TUIC owner'),
 'tun2socket':('runtime/security','packet/NAT edge oracles harden actual userspace TUN owner; fake facades retired','TUN runtime'),
 'udp-ring-queue':('observability/control-plane','bounded eviction/batch/restore/counter policy; unsafe wire decoder rejected','Operations queue planner'),
 'sni-spoofing-go':('runtime/control-plane/product','structured ClientHello/SNI, path evidence and bounded diagnostic UX; packet injector not copied','Dashboard/Operations'),
 'sni-spoofing-python':('runtime/test','parser/connection/packet-template oracles; packet injection authority superseded','SNI diagnostics'),
 'sni-bypass':('deployment/control-plane','reversible DNS/TLS-router/redirect preflight, no installer mutation authority','Operations SNI gateway planner'),
 'snispf-hj':('control-plane','first-response-qualified SNI pool lifecycle and bounded discovery; insecure CERT_NONE rejected','Operations/Dashboard'),
 'mitm-proxy':('security/control-plane','private-key-bearing artifacts become quarantine guard; interception runtime rejected','Operations artifact admission'),
 'mitm-relay':('security/control-plane','relay/STARTTLS design inspection; arbitrary mutation/insecure TLS rejected','Operations relay inspection'),
 'v2raya-scoop':('deployment/security','immutable package/hash/service lifecycle reference; dynamic expression execution rejected','Update/install governance'),
 'tt':('product','terminal width/input/layout/progress primitives superseded by Bubble Tea/Lip Gloss TUI','TUI'),
}

LAYER_BY_CLASS={
 'implementation':'backend/runtime', 'test':'test/oracle', 'configuration':'data/config',
 'script':'operations/deployment', 'deployment':'operations/deployment', 'ui-or-product':'frontend/UI/UX',
 'fixture':'test/fixture', 'documentation':'documentation', 'governance':'governance',
 'media':'frontend/media', 'repository-administration':'support/repository',
}

def read_csv(path:Path):
 with path.open(newline='',encoding='utf-8') as h:return list(csv.DictReader(h))

def sha_file(path:Path)->str:
 h=hashlib.sha256()
 with path.open('rb') as f:
  for chunk in iter(lambda:f.read(1<<20),b''):h.update(chunk)
 return h.hexdigest()

def module(path:str)->str:
 p=PurePosixPath(path)
 if not p.parts:return 'root'
 if len(p.parts)==1:return 'root'
 return p.parts[0]

def write_csv(path:Path, fields:list[str], rows:list[dict]):
 path.parent.mkdir(parents=True,exist_ok=True)
 with path.open('w',newline='',encoding='utf-8') as h:
  w=csv.DictWriter(h,fieldnames=fields);w.writeheader();w.writerows(rows)

surface_rows=[]
for wave,path in SURFACES.items():
 for r in read_csv(path):
  cls=r['classification']
  donor=r['donor']
  overlay=UPLIFT.get(donor) if wave=='224' else PRODUCT_225.get(donor)
  current_layer,current_outcome,current_surface=overlay if overlay else (LAYER_BY_CLASS.get(cls,'support'),r.get('surface_rationale','accounted'), 'n/a')
  surface_rows.append({
   'wave':wave,'donor':donor,'path':r['path'],'sha256':r['sha256'],'size_bytes':r['size_bytes'],
   'classification':cls,'source_layer':LAYER_BY_CLASS.get(cls,'support'),
   'semantic_record_ids':r.get('semantic_record_ids',''),'original_disposition':r.get('surface_disposition',''),
   'current_target_layer':current_layer,'cross_wave_outcome':current_outcome,'current_product_surface':current_surface,
  })
surface_rows.sort(key=lambda r:(r['wave'],r['donor'],r['path']))
write_csv(OUT/'post-refactor-225-all-history-surface-audit.csv',list(surface_rows[0]),surface_rows)

# Normalized symbol index across both waves.
symbol_rows=[]
for wave,path in SYMBOLS.items():
 for r in read_csv(path):
  symbol_rows.append({
   'wave':wave,'donor':r['donor'],'path':r['path'],'sha256':r.get('sha256') or r.get('surface_sha256',''),
   'line':r['line'],'kind':r['kind'],'symbol':r.get('name') or r.get('symbol',''),
   'semantic_record_ids':r.get('semantic_record_ids','')
  })
symbol_rows.sort(key=lambda r:(r['wave'],r['donor'],r['path'],int(r['line']) if str(r['line']).isdigit() else 0,r['kind'],r['symbol']))
write_csv(OUT/'post-refactor-225-all-history-symbol-index.csv',list(symbol_rows[0]),symbol_rows)

# Module-level cross-wave audit, including all layers represented in each subtree.
groups=defaultdict(list)
for r in surface_rows:groups[(r['wave'],r['donor'],module(r['path']))].append(r)
module_rows=[]
for (wave,donor,mod),items in sorted(groups.items()):
 counts=Counter(i['classification'] for i in items)
 layers=sorted(set(i['source_layer'] for i in items))
 overlays=sorted(set(i['cross_wave_outcome'] for i in items))
 products=sorted(set(i['current_product_surface'] for i in items if i['current_product_surface']!='n/a'))
 module_rows.append({
  'wave':wave,'donor':donor,'module':mod,'surfaces':len(items),
  'high_signal_surfaces':sum(counts[k] for k in ('implementation','test','configuration','script','deployment','ui-or-product')),
  'ui_product_surfaces':counts['ui-or-product'],'implementation_surfaces':counts['implementation'],'test_surfaces':counts['test'],
  'layers':';'.join(layers),'current_outcome':' | '.join(overlays),
  'current_product_surfaces':';'.join(products) if products else 'n/a',
  'surface_sha256':hashlib.sha256('\n'.join(f"{i['path']}\0{i['sha256']}" for i in sorted(items,key=lambda x:x['path'])).encode()).hexdigest(),
 })
write_csv(OUT/'post-refactor-225-all-history-module-audit.csv',list(module_rows[0]),module_rows)

ledgers={wave:read_csv(path) for wave,path in LEDGERS.items()}
summary={
 'donors':len(set((r['wave'],r['donor']) for r in surface_rows)),
 'unique_donor_names':len(set(r['donor'] for r in surface_rows)),
 'surfaces':len(surface_rows),'symbols':len(symbol_rows),'modules':len(module_rows),
 'wave_224_surfaces':sum(r['wave']=='224' for r in surface_rows),'wave_225_surfaces':sum(r['wave']=='225' for r in surface_rows),
 'wave_224_symbols':sum(r['wave']=='224' for r in symbol_rows),'wave_225_symbols':sum(r['wave']=='225' for r in symbol_rows),
 'semantic_records_224':len(ledgers['224']),'semantic_records_225':len(ledgers['225']),
 'ui_product_surfaces':sum(r['classification']=='ui-or-product' for r in surface_rows),
 'high_signal_surfaces':sum(r['classification'] in {'implementation','test','configuration','script','deployment','ui-or-product'} for r in surface_rows),
}
(OUT/'post-refactor-225-all-history-summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n',encoding='utf-8')

# Durable second-order report. Keep this generated from the graph so counts and
# product uplifts cannot drift from the CSV evidence.
by_wave=Counter(r['wave'] for r in surface_rows)
by_class=Counter(r['classification'] for r in surface_rows)
lines=[
 '# Post-refactor-225 all-history second-order convergence audit','',
 'This audit reopens every donor represented by the immutable post-refactor-224 wave and the current post-refactor-225 wave across backend/runtime, frontend/UI/UX, control-plane, data/config, tests/oracles, deployment/operations, and security/authority layers. It does not rewrite immutable 224 record IDs; it overlays current target ownership and product placement.','',
 '## Mechanical denominator','',
 f"- Donors: **{summary['donors']}** wave-scoped peers (15 from 224 + 23 from 225).",
 f"- Surfaces: **{summary['surfaces']}** ({summary['wave_224_surfaces']} inherited 224 + {summary['wave_225_surfaces']} current 225).",
 f"- Definition-level symbols: **{summary['symbols']}** ({summary['wave_224_symbols']} + {summary['wave_225_symbols']}).",
 f"- Module/subtree audit groups: **{summary['modules']}**.",
 f"- High-signal implementation/test/config/script/deployment/UI surfaces: **{summary['high_signal_surfaces']}**.",
 f"- UI/product donor surfaces re-reviewed: **{summary['ui_product_surfaces']}**.",
 f"- Semantic records retained: **{summary['semantic_records_224']} immutable 224 + {summary['semantic_records_225']} current 225**.",
 '', '## Cross-wave product/backend uplifts',''
]
for donor,(layer,outcome,product) in sorted(UPLIFT.items()):
 lines.append(f"- **{donor}** → {layer}: {outcome}. Current surface: {product}.")
lines += ['', '## Current-wave higher-level composition','']
for donor,(layer,outcome,product) in sorted(PRODUCT_225.items()):
 lines.append(f"- **{donor}** → {layer}: {outcome}. Current surface: {product}.")
lines += ['', '## Second-order invariants','',
 '- A donor-wide or module-wide record is context, not proof that every small implementation/test/config/UI leaf was semantically reviewed. Current 225 high-signal leaves therefore retain focused file/module decisions.',
 '- Product/UI convergence cannot create a second authority path: presets load drafts, planners are read-only, WARP scan output can be copied/exported but not activated, and routing/L7/DoH evidence cannot install runtime state.',
 '- Runtime convergence prefers a single live owner: duplicate Wintun and fake TUN/TUIC/MITM facades were retired rather than retained alongside stronger owners.',
 '- Negative donor evidence is first-class: insecure TLS, bundled private keys, unchecked frame counts, fabricated credentials, unverified restore/update paths, secret-bearing logs, and ambiguous authority are converted to guards or explicit rejection.',
 '- Automatic config mutation retry remains single-owned: 3 default attempts, 8 maximum, fresh state for each conflict retry, revision-conflict-only replay, and explicit ExpectedRevision disables automatic replay.',
 '', '## Evidence files','',
 '- `post-refactor-225-all-history-surface-audit.csv` — every 224/225 donor surface with current layer/product overlay.',
 '- `post-refactor-225-all-history-module-audit.csv` — subtree composition and layer coverage.',
 '- `post-refactor-225-all-history-symbol-index.csv` — normalized 9k+ definition index across both waves.',
 '- `post-refactor-225-all-history-summary.json` — machine-readable denominators.',
]
(OUT/'post-refactor-225-all-history-second-order-audit.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
print(json.dumps(summary,sort_keys=True))
