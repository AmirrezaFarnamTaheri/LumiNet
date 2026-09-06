#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
DAEMON = ROOT / 'src' / 'apps' / 'daemon'
SYSTEM = DAEMON / 'internal' / 'platform' / 'system'
errors = []

forbidden_calls = re.compile(r'\bsystem\.(?:SetDNS|ResetDNS|ClearDNS|SetNCSIConfig|ResetNCSIConfig|SetSystemProxy|DisableSystemProxy)\s*\(')
for path in DAEMON.rglob('*.go'):
    if SYSTEM in path.parents:
        continue
    text = path.read_text(encoding='utf-8')
    if forbidden_calls.search(text):
        errors.append(f'{path.relative_to(ROOT)}: bypasses ApplyHostNetwork')
    if 'GetRouteCoordinator(' in text or 'TransitionToMode(' in text:
        errors.append(f'{path.relative_to(ROOT)}: uses retired route coordinator seam')
    if 'github.com/maybeknott/luminet/internal/platform"' in text or 'platform.GetAdapter(' in text:
        errors.append(f'{path.relative_to(ROOT)}: uses retired platform adapter seam')

for rel in [
    'src/apps/daemon/internal/platform/system/route_coordinator.go',
    'src/apps/daemon/internal/platform/system/platform_adapter.go',
    'src/apps/daemon/internal/platform/system/transaction.go',
]:
    if (ROOT / rel).exists():
        errors.append(f'{rel}: obsolete host-network authority remains active')

watchdog = (ROOT / 'src/apps/daemon/cmd/watchdog/main.go').read_text(encoding='utf-8')
if 'RecoverHostNetworkInDir' not in watchdog:
    errors.append('src/apps/daemon/cmd/watchdog/main.go: watchdog does not use durable host-network recovery')
if 'resetSystemDnsAndProxy' in watchdog or 'resetLinuxNetwork' in watchdog or 'resetDarwinNetwork' in watchdog:
    errors.append('src/apps/daemon/cmd/watchdog/main.go: watchdog still carries a second generic reset algorithm')

serve = (ROOT / 'src/apps/daemon/cmd/serve.go').read_text(encoding='utf-8')
if 'launchHostNetworkWatchdog' not in serve:
    errors.append('src/apps/daemon/cmd/serve.go: daemon does not launch the host-network watchdog')
if serve.find('RecoverHostNetworkInDir') > serve.find('launchHostNetworkWatchdog') >= 0:
    errors.append('src/apps/daemon/cmd/serve.go: stale host-network recovery must run before watchdog launch')

# Private TUN mutation implementation must never escape the system package.
for path in DAEMON.rglob('*.go'):
    if SYSTEM in path.parents:
        continue
    text = path.read_text(encoding='utf-8')
    if re.search(r'\.(?:startWithLease|stopWithLease)\s*\(', text):
        errors.append(f'{path.relative_to(ROOT)}: calls private TUN mutation seam')

print(f'host-network-ownership errors={len(errors)}')
for err in errors:
    print(f'ERROR: {err}')
raise SystemExit(1 if errors else 0)
