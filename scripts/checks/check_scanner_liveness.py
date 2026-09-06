#!/usr/bin/env python3
from pathlib import Path
import hashlib, json, re

ROOT=Path(__file__).resolve().parents[2]
manifest=json.loads((ROOT/'governance/topology/wave15-scanner-liveness.json').read_text())
errors=[]
active=ROOT/'src/apps/daemon/internal/analysis/scanner'

for item in manifest['items']:
    source=ROOT/item['source']
    target=ROOT/item['target']
    if source.exists():
        errors.append(f"retired scanner island reappeared active: {item['source']}")
    if not target.exists():
        errors.append(f"preserved scanner island missing: {item['target']}")
        continue
    data=target.read_bytes()
    if hashlib.sha256(data).hexdigest()!=item['sha256'] or len(data)!=item['size']:
        errors.append(f"preserved scanner island changed bytes: {item['target']}")

    # Recheck same-package references and qualified external scanner imports.
    for symbol in item['exports']:
        same_package_pattern=re.compile(r'\b'+re.escape(symbol)+r'\b')
        for path in active.glob('*.go'):
            text=path.read_text(errors='ignore')
            if same_package_pattern.search(text):
                errors.append(f"retired scanner symbol gained package reference: {symbol} in {path.relative_to(ROOT)}")
                break
        else:
            for path in (ROOT/'src/apps').rglob('*.go'):
                if active in path.parents:
                    continue
                text=path.read_text(errors='ignore')
                match=re.search(r'(?m)^\s*(?:(\w+)\s+)?"github\.com/maybeknott/luminet/internal/analysis/scanner"', text)
                if not match:
                    continue
                alias=match.group(1) or 'scanner'
                if re.search(r'\b'+re.escape(alias)+r'\.'+re.escape(symbol)+r'\b', text):
                    errors.append(f"retired scanner symbol gained external reference: {symbol} in {path.relative_to(ROOT)}")
                    break

print(f"scanner-liveness retired={len(manifest['items'])} errors={len(errors)}")
for error in errors:
    print(f"ERROR: {error}")
raise SystemExit(1 if errors else 0)
