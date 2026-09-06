#!/usr/bin/env python3
from __future__ import annotations
import csv,hashlib,json,os,stat
from pathlib import Path
ROOT=Path(os.environ.get('LUMINET_226_TARGET_ROOT',Path(__file__).resolve().parents[2]))
BASE=ROOT/'governance/convergence/post-refactor-226-baseline-files.csv'
OUT=ROOT/'governance/convergence/post-refactor-226-target-delta.csv'
SELF=OUT.relative_to(ROOT).as_posix()
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for c in iter(lambda:f.read(1<<20),b''):h.update(c)
 return h.hexdigest()
def mode(p):return oct(stat.S_IMODE(p.stat().st_mode))
with BASE.open(newline='',encoding='utf-8') as f:base={r['path']:r for r in csv.DictReader(f)}
cur={}
for p in sorted(ROOT.rglob('*')):
 if not p.is_file() or p.is_symlink():continue
 rel=p.relative_to(ROOT).as_posix()
 if rel==SELF or rel.startswith('.git/'):continue
 cur[rel]={'path':rel,'size_bytes':str(p.stat().st_size),'mode':mode(p),'sha256':sha(p)}
rows=[]
for path in sorted(set(base)|set(cur)):
 b=base.get(path);c=cur.get(path)
 if b is None: typ='added'
 elif c is None:typ='deleted'
 elif (b['sha256'],b['size_bytes'],b['mode'])!=(c['sha256'],c['size_bytes'],c['mode']):typ='modified'
 else:continue
 rows.append({'change_type':typ,'path':path,'baseline_sha256':b['sha256'] if b else 'n/a','current_sha256':c['sha256'] if c else 'n/a','baseline_size_bytes':b['size_bytes'] if b else 'n/a','current_size_bytes':c['size_bytes'] if c else 'n/a','baseline_mode':b['mode'] if b else 'n/a','current_mode':c['mode'] if c else 'n/a'})
with OUT.open('w',newline='',encoding='utf-8') as f:
 w=csv.DictWriter(f,fieldnames=list(rows[0]) if rows else ['change_type','path','baseline_sha256','current_sha256','baseline_size_bytes','current_size_bytes','baseline_mode','current_mode']);w.writeheader();w.writerows(rows)
from collections import Counter
counts=Counter(r['change_type'] for r in rows)
print(json.dumps({'delta_paths':len(rows),**counts},sort_keys=True))
