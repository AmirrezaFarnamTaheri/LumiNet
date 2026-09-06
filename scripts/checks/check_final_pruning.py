#!/usr/bin/env python3
from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[2]
errors=[]
retired=['src/apps/daemon/internal/foundation/store/retention.go','src/apps/daemon/internal/platform/system/shortlink_server.go','src/apps/daemon/internal/runtime/proxy/state/node_creds.json']
manifest=json.loads((ROOT/'governance/topology/final-prune-liveness.json').read_text())
retired += [entry['path'] for entry in manifest['retired_whole_files']]
deep_prune=json.loads((ROOT/'governance/topology/deep-module-prune.json').read_text())
retired += [entry['path'] for entry in deep_prune['retired']]
for entry in deep_prune.get('preserved_corpus', []):
    source=ROOT/entry['source']
    target=ROOT/entry['target']
    if source.exists(): errors.append(f"preserved corpus returned to active source: {entry['source']}")
    if not target.is_file():
        errors.append(f"preserved corpus missing: {entry['target']}")
    else:
        import hashlib
        if hashlib.sha256(target.read_bytes()).hexdigest() != entry['sha256']:
            errors.append(f"preserved corpus hash drift: {entry['target']}")
for rel in retired:
    if (ROOT/rel).exists(): errors.append(f'retired file returned: {rel}')
checks={
    'src/apps/daemon/internal/adapters/api/security_gates.go': ['PublicToolsConfig','DefaultPublicToolsConfig'],
    'src/apps/daemon/internal/foundation/store/evidence.go': ['DeleteOlderThan(', 'DeleteByJob('],
}
for rel,tokens in checks.items():
    text=(ROOT/rel).read_text(errors='replace')
    for token in tokens:
        if token in text: errors.append(f'{rel}: stale symbol returned: {token}')
# Historical migrations are append-only compatibility evidence. Pruning live code must not erase old schema steps.
migrations=(ROOT/'src/apps/daemon/internal/foundation/store/migrations.go').read_text(errors='replace')
for token in ('CREATE TABLE IF NOT EXISTS covert_visits', 'DROP TABLE IF EXISTS covert_visits'):
    if token not in migrations: errors.append(f'historical migration unexpectedly removed: {token}')

# Retired control surfaces must not remain advertised after their implementations are gone.
control_files = {
    'src/apps/daemon/cmd/system.go': ('Flags().Bool("brutal"', 'Flags().Uint64("brutal-rate"', 'Flags().Uint32("brutal-cwnd"', 'brutal_enabled', 'brutal_rate_bps', 'brutal_cwnd_gain'),
    'src/apps/daemon/internal/foundation/config/config.go': ('TCPBrutalConfig', 'tcp_brutal'),
    'src/apps/daemon/internal/foundation/config/defaults.go': ('TCPBrutalConfig', 'TCPBrutal:'),
    'docs/guides/cli-reference.md': ('system covert-tracker',),
    'docs/guides/development.md': ('stores configuration states, dynamic DNS tasks, system backups, and covert tracker visits',),
}
for rel, tokens in control_files.items():
    text=(ROOT/rel).read_text(errors='replace')
    for token in tokens:
        if token in text: errors.append(f'{rel}: retired capability token returned: {token}')

print(f'final-pruning errors={len(errors)}')
for e in errors: print(f'ERROR: {e}')
raise SystemExit(1 if errors else 0)
