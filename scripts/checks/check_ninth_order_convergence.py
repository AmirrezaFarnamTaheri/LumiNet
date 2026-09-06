#!/usr/bin/env python3
from __future__ import annotations
import csv, hashlib, os, re, sys
from pathlib import Path
from collections import defaultdict

ROOT=Path(__file__).resolve().parents[2]
G=ROOT/'governance/convergence'
EXPECTED={'donors':20,'members':2379,'directories':425,'surfaces':1954,'modules':137,'symbols':8676,'records':168,'supersession':8,'baseline':2522}
HEX64=re.compile(r'^[0-9a-f]{64}$')
VALID_STATUS={'verified','statically-validated','reviewed','inferred','unverified','pending'}
VALID_DISPOSITIONS={'adopted','adapted','hardened','extracted','recomposed','synthesized','inspired-native','guardrail-derived','superseded','rejected-with-reason','reference-only'}
DELTA_REL='governance/convergence/ninth-order-target-delta.csv'
SUCCESSOR_BASELINE=G/'final-pass-baseline-files.csv'

def read_csv(name):
 p=G/name
 if not p.is_file(): raise AssertionError(f'missing {name}')
 with p.open(encoding='utf-8-sig',newline='') as f:return list(csv.DictReader(f))
def refs(v):return [x for x in (v or '').split(';') if x and x!='n/a']
def digest_path(p):
 if p.is_symlink():
  t=os.readlink(p);return ('symlink',hashlib.sha256(t.encode()).hexdigest(),t)
 return ('file',hashlib.sha256(p.read_bytes()).hexdigest(),'n/a')
def scan_current():
 # Once the final cross-wave pass exists, validate delivered ninth-order state
 # against its frozen successor baseline so later convergence cannot rewrite
 # historical ninth-order evidence.
 if SUCCESSOR_BASELINE.is_file():
  out={}
  with SUCCESSOR_BASELINE.open(encoding='utf-8',newline='') as f:
   for row in csv.DictReader(f):
    rel=row['path'].strip()
    if rel==DELTA_REL:continue
    out[rel]=(row['file_type'].strip(),row['sha256'].strip(),row['link_target'])
  return out
 out={}
 for p in sorted(ROOT.rglob('*')):
  if not (p.is_file() or p.is_symlink()):continue
  rel=p.relative_to(ROOT).as_posix()
  if rel==DELTA_REL or rel.startswith('.git/'):continue
  out[rel]=digest_path(p)
 return out
def anchor_exists(node):
 node=(node or '').strip()
 if not node or node=='n/a':return True
 if '#' not in node:return False
 rel,a=node.split('#',1);p=ROOT/rel
 if not p.is_file():return False
 raw=p.read_text(encoding='utf-8',errors='replace')
 cands={a,a.split('.')[-1],a.replace('-',' '),a.replace('-','_')}
 return any(c and re.search(r'(?<![A-Za-z0-9_])'+re.escape(c)+r'(?![A-Za-z0-9_])',raw,re.I) for c in cands)

def main():
 errors=[]
 try:
  donors=read_csv('ninth-order-donors.csv'); dirs=read_csv('ninth-order-directories.csv'); surfaces=read_csv('ninth-order-surfaces.csv'); modules=read_csv('ninth-order-modules.csv'); symbols=read_csv('ninth-order-symbols.csv'); ledger=read_csv('ninth-order-adoption-ledger.csv'); sups=read_csv('ninth-order-supersession-map.csv'); baseline_rows=read_csv('ninth-order-baseline-files.csv'); delta_rows=read_csv('ninth-order-target-delta.csv'); licenses=read_csv('ninth-order-license-map.csv'); repairs=read_csv('ninth-order-target-repairs.csv')
 except Exception as e:
  print('ninth-order convergence:',e);return 1
 counts={'donors':len(donors),'directories':len(dirs),'surfaces':len(surfaces),'modules':len(modules),'symbols':len(symbols),'records':len(ledger),'supersession':len(sups),'baseline':len(baseline_rows)}
 for k,v in counts.items():
  if v!=EXPECTED[k]:errors.append(f'{k} count {v} != {EXPECTED[k]}')
 if sum(int(r['member_count']) for r in donors)!=EXPECTED['members']:errors.append('archive member denominator mismatch')
 if sum(int(r['file_surfaces']) for r in donors)!=EXPECTED['surfaces']:errors.append('surface rollup mismatch')
 if sum(int(r['directories']) for r in donors)!=EXPECTED['directories']:errors.append('directory rollup mismatch')
 if sum(int(r['symbols']) for r in donors)!=EXPECTED['symbols']:errors.append('symbol rollup mismatch')
 if len(licenses)!=EXPECTED['donors']:errors.append('license map donor mismatch')
 if len({r['donor'] for r in donors})!=EXPECTED['donors']:errors.append('duplicate donor identities')
 records={r.get('record_id',''):r for r in ledger}
 if len(records)!=len(ledger) or '' in records:errors.append('duplicate/empty ledger ids')
 surface={(r['donor'],r['path']):r for r in surfaces}
 if len(surface)!=len(surfaces):errors.append('duplicate donor surface rows')
 for d in donors:
  if not HEX64.fullmatch(d.get('archive_sha256','')):errors.append(f"{d.get('donor')}: invalid archive hash")
  if not d.get('archive_issues','').startswith('none'):errors.append(f"{d.get('donor')}: archive safety not closed")
  for rid in refs(d.get('semantic_record_ids')):
   if rid not in records:errors.append(f"{d.get('donor')}: unknown record {rid}")
 for r in ledger:
  rid=r['record_id']
  if r.get('disposition') not in VALID_DISPOSITIONS:errors.append(f'{rid}: invalid disposition')
  if r.get('validation_status') not in VALID_STATUS:errors.append(f'{rid}: invalid validation status')
  if r.get('risk_tier') not in {'critical','high','medium','low'}:errors.append(f'{rid}: invalid risk')
  if not HEX64.fullmatch(r.get('donor_sha256','')):errors.append(f'{rid}: invalid donor hash')
  sr=surface.get((r.get('donor'),r.get('donor_path')))
  if not sr:errors.append(f"{rid}: donor surface missing {r.get('donor')}:{r.get('donor_path')}")
  elif sr['sha256']!=r['donor_sha256']:errors.append(f'{rid}: donor hash mismatch')
  for dep in refs(r.get('dependency_record_ids')):
   if dep not in records:errors.append(f'{rid}: unknown dependency {dep}')
  for node in refs(r.get('target_nodes')):
   if not anchor_exists(node):errors.append(f'{rid}: missing target anchor {node}')
  test=r.get('test_node','n/a')
  if test!='n/a' and not anchor_exists(test):errors.append(f'{rid}: missing test anchor {test}')
  if r.get('disposition')!='reference-only' and test=='n/a':errors.append(f'{rid}: non-reference disposition lacks evidence')
 for s in surfaces:
  if not HEX64.fullmatch(s.get('sha256','')):errors.append(f"surface {s['donor']}:{s['path']}: invalid hash")
  ids=refs(s.get('semantic_record_ids'))
  if not ids:errors.append(f"surface {s['donor']}:{s['path']}: unresolved")
  for rid in ids:
   if rid not in records:errors.append(f"surface {s['donor']}:{s['path']}: unknown {rid}")
 by=defaultdict(list)
 for s in surfaces:by[s['donor']].append(s)
 for d in dirs:
  if d['path']=='.':desc=by[d['donor']];direct=[x for x in desc if '/' not in x['path']]
  else:
   pref=d['path'].rstrip('/')+'/';desc=[x for x in by[d['donor']] if x['path'].startswith(pref)];direct=[x for x in desc if '/' not in x['path'][len(pref):]]
  if len(desc)!=int(d['recursive_surface_count']):errors.append(f"dir {d['donor']}:{d['path']}: recursive mismatch")
  if len(direct)!=int(d['direct_surface_count']):errors.append(f"dir {d['donor']}:{d['path']}: direct mismatch")
  for rid in refs(d.get('semantic_record_ids')):
   if rid not in records:errors.append(f"dir {d['donor']}:{d['path']}: unknown {rid}")
 module_sizes={}
 for m in modules:
  ids=refs(m.get('semantic_record_ids'))
  if not ids:errors.append(f"module {m.get('donor')}:{m.get('path')}: unresolved");continue
  for rid in ids:
   if rid not in records:errors.append(f"module {m.get('donor')}:{m.get('path')}: unknown {rid}")
  module_sizes[ids[0]]=0
 for s in surfaces:
  for rid in refs(s.get('semantic_record_ids')):
   if rid in module_sizes:module_sizes[rid]+=1
 over=[(rid,n) for rid,n in module_sizes.items() if n>100]
 if over:errors.append(f'module grouping exceeds 100 surfaces: {over[:10]}')
 for s in symbols:
  if (s['donor'],s['path']) not in surface:errors.append(f"symbol path absent {s['donor']}:{s['path']}#{s['symbol']}")
  ids=refs(s.get('semantic_record_ids'))
  if not ids:errors.append(f"symbol unresolved {s['donor']}:{s['path']}#{s['symbol']}")
  for rid in ids:
   if rid not in records:errors.append(f"symbol {s['symbol']}: unknown {rid}")
 for sup in sups:
  for rid in refs(sup.get('ninth_order_record_ids')):
   if rid not in records:errors.append(f"{sup.get('supersession_id')}: unknown {rid}")

 # Exact eighth-order baseline -> current ninth-order delta.
 baseline={}
 for r in baseline_rows:
  p=r['path'].strip()
  if not p or p in baseline:errors.append(f'duplicate/empty ninth baseline path {p!r}');continue
  if r['file_type'] not in {'file','symlink'} or not HEX64.fullmatch(r['sha256']):errors.append(f'ninth baseline {p}: invalid row')
  baseline[p]=(r['file_type'],r['sha256'],r['link_target'])
 current=scan_current();expected={}
 for p in sorted(set(baseline)|set(current)):
  a,b=baseline.get(p),current.get(p)
  if a==b:continue
  if a is None:expected[p]=('added','n/a',b[1])
  elif b is None:expected[p]=('deleted',a[1],'n/a')
  else:expected[p]=('modified',a[1],b[1])
 delta={}
 for r in delta_rows:
  p=r.get('path','').strip()
  if not p or p in delta:errors.append(f'duplicate/empty ninth delta path {p!r}');continue
  delta[p]=r;exp=expected.get(p)
  if exp is None:errors.append(f'ninth delta {p}: not changed');continue
  got=(r.get('change_type'),r.get('eighth_order_sha256'),r.get('current_sha256'))
  if got!=exp:errors.append(f'ninth delta {p}: hash/change mismatch got={got} expected={exp}')
  for rid in refs(r.get('ninth_order_record_ids')):
   if rid not in records:errors.append(f'ninth delta {p}: unknown accountability {rid}')
  if not r.get('accountability_class','').strip() or not r.get('reason','').strip() or not r.get('verification_node','').strip():errors.append(f'ninth delta {p}: incomplete accountability')
  if r.get('verification_node')!='n/a' and not anchor_exists(r.get('verification_node')):errors.append(f"ninth delta {p}: missing verification anchor {r.get('verification_node')}")
 missing=sorted(set(expected)-set(delta)); extra=sorted(set(delta)-set(expected))
 if missing:errors.append(f'ninth target delta missing {len(missing)} paths: {missing[:30]}')
 if extra:errors.append(f'ninth target delta extra {len(extra)} paths: {extra[:30]}')

 def text(rel):return (ROOT/rel).read_text(encoding='utf-8',errors='replace')
 # Config generation transaction/CAS.
 caddy=text('src/apps/daemon/internal/platform/system/caddy.go');ct=text('src/apps/daemon/internal/platform/system/caddy_test.go')
 for m in ['reloadMu','cleanupStagedError','HotReloadIfHash','ErrConfigConflict','deepCopyDaemonConfig','canonicalJSON']:
  if m not in caddy:errors.append(f'config transaction invariant missing {m}')
 for m in ['TestConfigManagerFailedStagingRollsBackNewPluginsAndKeepsOldState','TestConfigManagerHotReloadIfHashRejectsStaleWriter','TestConfigManagerReadersAreNotBlockedByPluginStart']:
  if m not in ct:errors.append(f'config transaction test missing {m}')
 # WARP quality/bounds.
 warp=text('src/apps/daemon/internal/runtime/warp/warp_scanner.go'); wt=text('src/apps/daemon/internal/runtime/warp/warp_scanner_test.go'); noise=text('src/apps/daemon/internal/runtime/warp/noise.go'); wh=text('src/apps/daemon/internal/adapters/api/handlers_warp_geosite.go')
 for m in ['AttemptsPerEndpoint','SuccessfulAttempts','summarizeWarpAttempts','ValidateScanLimits','maxWarpCandidates','maxWarpConcurrency']:
  if m not in warp:errors.append(f'WARP convergence missing {m}')
 if 'ValidateNoiseCount(count)' not in noise:errors.append('standalone WARP noise bypasses shared bound')
 if 'warp.ValidateScanLimits' not in wh:errors.append('WARP API does not fail fast on operator oversubscription')
 for m in ['TestWarpScannerRanksLossBeforeLatency','TestInjectNoiseRejectsUnboundedCount','TestValidateScanLimitsRejectsOperatorOversubscription']:
  if m not in wt:errors.append(f'WARP regression test missing {m}')
 # Speed diagnostics and second-order body/redirect bound.
 runner=text('src/apps/daemon/internal/adapters/api/speedtest_runner.go'); metrics=text('src/apps/daemon/internal/adapters/api/speedtest_metrics.go'); rt=text('src/apps/daemon/internal/adapters/api/speedtest_runner_test.go')
 for m in ['LatencySamples','PacketLossPercent','JitterMilliseconds','QualityStable','maxSpeedtestBytes','maxSpeedtestRedirects','io.LimitReader']:
  if m not in runner and m not in metrics:errors.append(f'speed diagnostic invariant missing {m}')
 for m in ['TestRunSpeedtestRejectsOriginThatIgnoresDownloadBudget','TestRunSpeedtestBoundsRedirectChain','TestRunSpeedtestMeasuresLatencyLossAndDownload']:
  if m not in rt:errors.append(f'speed diagnostic regression missing {m}')
 # Advisory entitlement with overflow guard.
 ent=text('src/apps/daemon/internal/integrations/sub/profile_entitlement.go'); et=text('src/apps/daemon/internal/integrations/sub/profile_entitlement_test.go'); contracts=text('src/packages/control-ui/src/api/contracts.ts'); profiles=text('src/packages/control-ui/src/pages/Profiles.tsx')
 for m in ['ProfileEntitlement','EvaluateProfileEntitlement','saturatingProviderUsage','math.MaxInt64','Status: "unknown"']:
  if m not in ent:errors.append(f'entitlement invariant missing {m}')
 if 'TestEvaluateProfileEntitlementSaturatesMalformedProviderCounters' not in et:errors.append('entitlement overflow regression missing')
 if 'parseSubscriptionEntitlement' not in contracts:errors.append('control UI contract lacks entitlement parser')
 if 'Advisory provider metadata only' not in profiles:errors.append('control UI fails to disclose advisory entitlement authority')
 # Retired unsafe parallel shaper.
 if (ROOT/'src/apps/daemon/internal/platform/system/traffic_shaper.go').exists():errors.append('dormant unsafe traffic_shaper.go survived ninth-order retirement')
 if not (ROOT/'src/apps/daemon/internal/platform/system/host_network.go').is_file():errors.append('host-network authoritative owner missing after traffic shaper retirement')
 # Historical layering and canonical entrypoint.
 eighth=text('scripts/checks/check_eighth_order_convergence.py'); make=text('Makefile')
 if "SUCCESSOR_BASELINE=G/'ninth-order-baseline-files.csv'" not in eighth:errors.append('eighth-order checker lacks ninth-order successor baseline layering')
 if 'check_ninth_order_convergence.py' not in make:errors.append('canonical verify-repo does not execute ninth-order gate')
 # x-ui no-license donor must not masquerade as completed bootstrap.
 xui=text('deploy/server-bootstrap/x-ui-pro.sh')
 if 'placeholder' not in xui.lower():errors.append('x-ui-pro deployment surface no longer truthfully identifies placeholder status')
 # Archive overlap truth: exact duplicate AutoTor SHA must be explicit.
 auto=next((d for d in donors if d['donor']=='Auto_Tor_IP_changer-master(2)'),None)
 if not auto or auto['archive_sha256']!='2b14f6d735fa3932c25f779ebe5bb11f08294251ea14c709786484853e4080f3':errors.append('AutoTor duplicate source identity mismatch')

 if errors:
  print(f'ninth-order convergence: errors={len(errors)}')
  for e in errors[:260]:print('ERROR:',e)
  return 1
 print(f'ninth-order convergence: donors={len(donors)} members={EXPECTED["members"]} directories={len(dirs)} surfaces={len(surfaces)} modules={len(modules)} symbols={len(symbols)} records={len(ledger)} supersession={len(sups)} baseline={len(baseline_rows)} changes={len(delta_rows)} repairs={len(repairs)} errors=0')
 return 0
if __name__=='__main__':raise SystemExit(main())
