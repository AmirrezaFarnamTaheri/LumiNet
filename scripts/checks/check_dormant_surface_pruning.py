#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
errors = []

retired = {
    'src/apps/daemon/internal/runtime/proxy/verification_final.go': 'labs/daemon/proxy-alternates/verification_final.go',
    'src/apps/daemon/internal/runtime/proxy/dns_truth_table.go': 'labs/daemon/proxy-alternates/dns_truth_table.go',
    'src/apps/daemon/internal/analysis/scanner/truth_table.go': 'labs/daemon/scanner-alternates/truth_table.go',
}

for live, preserved in retired.items():
    if (ROOT / live).exists():
        errors.append(f'dormant surface still live: {live}')
    if not (ROOT / preserved).is_file():
        errors.append(f'dormant surface is not preserved: {preserved}')

# These names had no production consumers when the retirement was reviewed.
# Keep the guard narrow so a future reintroduction must be deliberate.
for symbol in ('VerificationFinalSuite', 'NewVerificationFinalSuite', 'DnsTruthTable', 'NewDnsTruthTable', 'TruthTable', 'NewTruthTable'):
    pat = re.compile(rf'\b{re.escape(symbol)}\b')
    for path in (ROOT / 'src/apps/daemon').rglob('*.go'):
        if path.name.endswith('_test.go'):
            continue
        text = path.read_text(encoding='utf-8', errors='replace')
        if pat.search(text):
            errors.append(f'retired dormant symbol {symbol} referenced by {path.relative_to(ROOT)}')

print(f'dormant-surface-pruning retired={len(retired)} errors={len(errors)}')
for error in errors:
    print(f'ERROR: {error}')
raise SystemExit(1 if errors else 0)
