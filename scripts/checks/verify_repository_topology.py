#!/usr/bin/env python3
from __future__ import annotations
import csv, hashlib, json, sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
BASELINE=ROOT/'governance/topology/original-baseline.tsv'
RULES=ROOT/'governance/topology/relocations.json'
REVIEWED_TRANSFORMS=ROOT/'governance/topology/pr3-reviewed-transforms.json'

def digest(path: Path) -> str:
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024), b''):
            h.update(chunk)
    return h.hexdigest()

def mapped_path(old: str, rules: dict) -> str:
    exact=rules.get('exact_relocations', {})
    if old in exact:
        return exact[old]
    matches=[]
    for item in rules.get('prefix_relocations', []):
        src=item['from'].rstrip('/')+'/'
        if old.startswith(src):
            matches.append((len(src), item['to'].rstrip('/')+'/'+old[len(src):]))
        elif old == item['from'].rstrip('/'):
            matches.append((len(src), item['to'].rstrip('/')))
    if matches:
        return max(matches)[1]
    return old

def load_reviewed_transforms() -> dict[str, str]:
    if not REVIEWED_TRANSFORMS.is_file():
        return {}
    payload=json.loads(REVIEWED_TRANSFORMS.read_text(encoding='utf-8'))
    if payload.get('schema') != 'v1':
        raise ValueError(f'unsupported reviewed-transform schema: {payload.get("schema")!r}')
    transforms=payload.get('allowed_transforms', {})
    if not isinstance(transforms, dict):
        raise ValueError('reviewed-transform allowed_transforms must be an object')
    return transforms

def main() -> int:
    rules=json.loads(RULES.read_text(encoding='utf-8'))
    transforms=dict(rules.get('allowed_transforms', {}))
    try:
        reviewed=load_reviewed_transforms()
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f'ERROR: invalid reviewed transform evidence: {exc}')
        return 1
    duplicate=set(transforms).intersection(reviewed)
    if duplicate:
        for path in sorted(duplicate):
            print(f'ERROR: duplicate transform attestation: {path}')
        return 1
    transforms.update(reviewed)
    retired=rules.get('retired', {})
    rows=list(csv.DictReader(BASELINE.open(encoding='utf-8'), delimiter='\t'))
    errors=[]; same=0; transformed=0; retired_count=0
    baseline_paths={row['path'] for row in rows}
    for path, reason in reviewed.items():
        if path not in baseline_paths:
            errors.append(f'reviewed transform is not a baseline path: {path}')
        elif not isinstance(reason, str) or not reason.strip():
            errors.append(f'reviewed transform lacks rationale: {path}')
    for row in rows:
        old=row['path']; expected=mapped_path(old,rules)
        if old in retired:
            retired_count += 1
            if not retired[old].strip():
                errors.append(f'retired path lacks rationale: {old}')
            continue
        target=ROOT/expected
        if not target.is_file():
            errors.append(f'missing baseline path: {old} -> {expected}')
            continue
        got=digest(target)
        if got == row['sha256']:
            same += 1
            continue
        reason=transforms.get(old)
        if reason and reason.strip():
            transformed += 1
        else:
            errors.append(f'unreviewed content change: {old} -> {expected}')
    expected_count=rules.get('baseline_count')
    if expected_count != len(rows):
        errors.append(f'baseline count metadata mismatch: {expected_count} != {len(rows)}')
    accounted=same+transformed+retired_count
    print(f'baseline_accounted={accounted}/{len(rows)} byte_identical={same} transformed={transformed} retired={retired_count} errors={len(errors)}')
    for e in errors[:100]: print('ERROR:',e)
    if len(errors)>100: print(f'ERROR: ... {len(errors)-100} more')
    return 1 if errors else 0

if __name__=='__main__':
    sys.exit(main())
