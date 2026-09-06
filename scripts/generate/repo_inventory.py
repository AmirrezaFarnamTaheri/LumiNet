#!/usr/bin/env python3
from __future__ import annotations
import argparse, csv, hashlib, json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--root', default='.')
parser.add_argument('--output', required=True)
args = parser.parse_args()
root = Path(args.root).resolve()
out = Path(args.output)
if not out.is_absolute(): out = root / out
out.mkdir(parents=True, exist_ok=True)
rows = []
for p in sorted(root.rglob('*')):
    if not p.is_file() or out in p.parents:
        continue
    rel_path = p.relative_to(root)
    if rel_path.parts and rel_path.parts[0] == '.git':
        continue
    rel = rel_path.as_posix()
    h = hashlib.sha256(p.read_bytes()).hexdigest()
    rows.append({'path': rel, 'size_bytes': p.stat().st_size, 'depth': len(Path(rel).parts), 'sha256': h})
with (out/'files.csv').open('w', newline='', encoding='utf-8') as f:
    w = csv.DictWriter(f, fieldnames=rows[0].keys() if rows else ['path','size_bytes','depth','sha256'], lineterminator='\n')
    w.writeheader(); w.writerows(rows)
(out/'summary.json').write_text(json.dumps({'files': len(rows), 'bytes': sum(r['size_bytes'] for r in rows), 'max_depth': max((r['depth'] for r in rows), default=0)}, indent=2)+'\n', encoding='utf-8')
print(f'wrote {len(rows)} files to {out}')
