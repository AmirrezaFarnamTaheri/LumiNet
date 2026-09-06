#!/usr/bin/env python3
from pathlib import Path
import sys

root = Path(__file__).resolve().parents[2]
errors = []
active_forbidden = [
    'src/apps/daemon/internal/runtime/proxy/master_architecture_orchestrator.go',
    'src/apps/daemon/internal/runtime/proxy/sni_spoofing.go',
    'src/apps/daemon/internal/runtime/proxy/dpi_desync.go',
    'src/apps/daemon/internal/runtime/proxy/gdrive_tunnel.go',
    'src/apps/daemon/internal/runtime/proxy/device_profile_emulator.go',
    'src/apps/daemon/internal/vpnstate/vpn_service_bridge.go',
    'src/apps/daemon/internal/runtime/proxy/unimplemented_stubs.go',
]
for rel in active_forbidden:
    if (root / rel).exists():
        errors.append(f'active retired runtime surface still exists: {rel}')

preserved = [
    'labs/daemon/proxy-alternates/master_architecture_orchestrator.go',
    'labs/daemon/proxy-alternates/sni_spoofing.go',
    'labs/daemon/proxy-alternates/dpi_desync.go',
    'labs/daemon/proxy-alternates/gdrive_tunnel.go',
    'labs/daemon/proxy-alternates/device_profile_emulator.go',
    'labs/daemon/vpnstate-alternates/vpn_service_bridge.go',
    'labs/daemon/vpnstate-alternates/vpn_service_bridge_test.go',
]
for rel in preserved:
    if not (root / rel).exists():
        errors.append(f'preserved retired surface missing: {rel}')

for error in errors:
    print('ERROR', error)
print(f'advanced-runtime-pruning preserved={len(preserved)} errors={len(errors)}')
sys.exit(bool(errors))
