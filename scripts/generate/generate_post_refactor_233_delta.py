#!/usr/bin/env python3
from __future__ import annotations
import csv,hashlib,os,stat
from pathlib import Path
from collections import Counter
ROOT=Path(os.environ.get('LUMINET_233_TARGET_ROOT',Path(__file__).resolve().parents[2]))
BASE=Path(os.environ.get('LUMINET_233_BASELINE_INVENTORY','/mnt/data/LumiNet-post-refactor-232-source-inventory.csv'))
OUT=ROOT/'governance/convergence/post-refactor-233-target-delta.csv'
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1<<20),b''):h.update(b)
 return h.hexdigest()
with BASE.open(newline='',encoding='utf-8') as f:b={r['path']:r for r in csv.DictReader(f)}
c={}
for p in sorted(ROOT.rglob('*')):
 if p.is_symlink() or not p.is_file():continue
 rel=p.relative_to(ROOT).as_posix()
 if rel=='governance/convergence/post-refactor-233-target-delta.csv' or '/node_modules/' in '/'+rel or '__pycache__' in rel or rel.startswith('.git/'):continue
 c[rel]={'path':rel,'size_bytes':str(p.stat().st_size),'mode':oct(stat.S_IMODE(p.stat().st_mode)),'sha256':sha(p)}
rows=[]
for p in sorted(set(b)|set(c)):
 br,cr=b.get(p),c.get(p)
 if br is None:typ='added'
 elif cr is None:typ='deleted'
 elif (br['sha256'],br['size_bytes'],br['mode'])!=(cr['sha256'],cr['size_bytes'],cr['mode']):typ='modified'
 else:continue
 rows.append({'change_type':typ,'path':p,'baseline_sha256':br['sha256'] if br else 'n/a','baseline_size_bytes':br['size_bytes'] if br else 'n/a','baseline_mode':br['mode'] if br else 'n/a','current_sha256':cr['sha256'] if cr else 'n/a','current_size_bytes':cr['size_bytes'] if cr else 'n/a','current_mode':cr['mode'] if cr else 'n/a'})
fields=['change_type','path','baseline_sha256','baseline_size_bytes','baseline_mode','current_sha256','current_size_bytes','current_mode']
OUT.parent.mkdir(parents=True,exist_ok=True)
with OUT.open('w',newline='',encoding='utf-8') as f:w=csv.DictWriter(f,fieldnames=fields,lineterminator='\n');w.writeheader();w.writerows(rows)
print('post-refactor-233 delta',len(rows),dict(Counter(r['change_type'] for r in rows)))
