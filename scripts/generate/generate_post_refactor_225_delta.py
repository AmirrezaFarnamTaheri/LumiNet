#!/usr/bin/env python3
from __future__ import annotations
import csv, hashlib, os, stat
from pathlib import Path

TARGET=Path(os.environ.get('LUMINET_225_TARGET_ROOT','/mnt/data/work225_full/LumiNet')).resolve()
BASELINE=Path(os.environ.get('LUMINET_225_BASELINE_ROOT','/mnt/data/verify225/baseline224_full')).resolve()
OUT=TARGET/'governance/convergence'
BASELINE_CSV=OUT/'post-refactor-225-baseline-files.csv'
DELTA_CSV=OUT/'post-refactor-225-target-delta.csv'
EXCLUDE={DELTA_CSV.relative_to(TARGET).as_posix()}

def sha_file(p:Path)->str:
 h=hashlib.sha256()
 with p.open('rb') as f:
  for c in iter(lambda:f.read(1<<20),b''):h.update(c)
 return h.hexdigest()

def inventory(root:Path, exclude:set[str]|None=None):
 exclude=exclude or set(); rows={}
 for p in sorted(root.rglob('*')):
  rel=p.relative_to(root).as_posix()
  if rel in exclude: continue
  if p.is_symlink():
   rows[rel]={'path':rel,'type':'symlink','sha256':hashlib.sha256(os.readlink(p).encode()).hexdigest(),'size_bytes':len(os.readlink(p).encode()),'mode':oct(stat.S_IMODE(p.lstat().st_mode))}
  elif p.is_file():
   rows[rel]={'path':rel,'type':'file','sha256':sha_file(p),'size_bytes':p.stat().st_size,'mode':oct(stat.S_IMODE(p.stat().st_mode))}
 return rows

def read_baseline_csv():
 if not BASELINE_CSV.exists(): return None
 with BASELINE_CSV.open(newline='',encoding='utf-8') as h:return {r['path']:r for r in csv.DictReader(h)}

def write_csv(path:Path, fields, rows):
 with path.open('w',newline='',encoding='utf-8') as h:
  w=csv.DictWriter(h,fieldnames=fields);w.writeheader();w.writerows(rows)

def reason(path:str, change:str)->str:
 if path.startswith('src/apps/daemon/internal/analysis/diagnostics/'):
  return '225 donor convergence: bounded read-only policy/planning, SNI/TLS/incident/queue/WireGuard/workflow evidence, or focused tests'
 if path.startswith('src/apps/daemon/internal/networking/'):
  return '225 transport/network hardening: DNS/CDN/TLS/proxy/TUIC bounds and single-owner runtime policy'
 if path.startswith('src/apps/daemon/internal/platform/system/'):
  return '225 platform hardening: Wintun/TUN admission and duplicate-authority consolidation'
 if path.startswith('src/apps/daemon/internal/runtime/proxy/'):
  return '225 runtime truth hardening: TUIC/TLS/TUN/proxy semantics and false-capability retirement'
 if path.startswith('src/packages/lumicore/'):
  return '225 authority cleanup/hardening in legacy Rust transport/TUN surfaces'
 if path.startswith('src/packages/control-ui/'):
  return '225 frontend/UI/UX convergence and natural product placement with non-authoritative planner surfaces'
 if path.startswith('governance/convergence/post-refactor-225'):
  return '225 reproducible convergence evidence, all-history audit, validation, or source delta'
 if path.startswith('scripts/checks/') or path.startswith('scripts/generate/'):
  return '225 deterministic verification/evidence tooling'
 if path=='Makefile': return '225 verification/evidence targets wired into canonical repository workflow'
 if path.startswith('governance/topology/') or path.endswith('/.context') or path=='.context':
  return '225 topology/context ownership reconciliation'
 return f'225 successor {change} accounted against immutable 224 baseline'

if BASELINE.is_dir():
 baseline=inventory(BASELINE)
 write_csv(BASELINE_CSV,['path','type','sha256','size_bytes','mode'],[baseline[k] for k in sorted(baseline)])
else:
 baseline=read_baseline_csv()
 if baseline is None: raise SystemExit(f'baseline root unavailable and no embedded baseline inventory: {BASELINE}')
current=inventory(TARGET,EXCLUDE)
paths=sorted(set(baseline)|set(current))
delta=[]
for path in paths:
 b=baseline.get(path); c=current.get(path)
 if b is None:
  delta.append({'path':path,'change_type':'added','baseline_sha256':'','current_sha256':c['sha256'],'baseline_type':'','current_type':c['type'],'reason':reason(path,'addition')})
 elif c is None:
  delta.append({'path':path,'change_type':'deleted','baseline_sha256':b['sha256'],'current_sha256':'','baseline_type':b.get('type','file'),'current_type':'','reason':reason(path,'deletion')})
 elif b['sha256']!=c['sha256'] or b.get('type','file')!=c['type'] or b.get('mode')!=c.get('mode'):
  delta.append({'path':path,'change_type':'modified','baseline_sha256':b['sha256'],'current_sha256':c['sha256'],'baseline_type':b.get('type','file'),'current_type':c['type'],'reason':reason(path,'modification')})
write_csv(DELTA_CSV,['path','change_type','baseline_sha256','current_sha256','baseline_type','current_type','reason'],delta)
counts={k:sum(r['change_type']==k for r in delta) for k in ('added','modified','deleted')}
print(f"post-refactor-225 delta: {len(delta)} paths ({counts['added']} added / {counts['modified']} modified / {counts['deleted']} deleted); baseline={len(baseline)} current={len(current)}")
