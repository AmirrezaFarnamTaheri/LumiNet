#!/usr/bin/env python3
from pathlib import Path
import re
import sys

root = Path(__file__).resolve().parents[2]
handler = (root / 'src/apps/daemon/internal/adapters/api/handlers_warp_geosite.go').read_text()
truth = (root / 'src/apps/daemon/internal/adapters/api/advanced_route_truth.go').read_text()
errors = []

for symbol in [
    'globalDomainRouter', 'globalSmartDNSRouter', 'globalCleanIPProber', 'globalCDNBuilder',
    'globalIPAnalyzer', 'globalSNISpoofer', 'globalDPIDesync', 'globalDoHBlocklist',
    'globalCDNDiscover', 'globalAntiBot', 'globalGDriveRelay', 'globalSubParser',
    'globalVPNBridge', 'globalOrchestrator', 'GetDeviceProfileEmulator',
    'NewMasterArchitectureOrchestrator', 'NewGDriveTunnelRelay', 'NewSNISpoofingInjector',
    'NewDPIDesyncEngine', 'NewVPNServiceBridge',
]:
    if re.search(r'\b' + re.escape(symbol) + r'\b', handler):
        errors.append(f'advanced handler still owns/reaches disconnected runtime symbol: {symbol}')

entries = re.findall(r'^\s*"(?:GET|POST) /[^\"]+":\s*\{Mode:', truth, re.M)
if len(entries) != 20:
    errors.append(f'advanced route truth entries={len(entries)}, want 20')

for key in [
    'POST /sni-spoofing', 'POST /dpi-desync', 'POST /gdrive-tunnel',
    'GET /master-telemetry', 'GET /vpn-state', 'GET /device-profile', 'POST /device-profile',
]:
    pattern = re.escape('"' + key + '"') + r':\s*\{Mode:\s*advancedRouteUnavailable'
    if not re.search(pattern, truth):
        errors.append(f'{key}: disconnected capability must be explicitly unavailable')
    if f'unavailableAdvancedCapability(c, "{key}")' not in handler:
        errors.append(f'{key}: handler does not fail closed through route truth')

for error in errors:
    print('ERROR', error)
print(f'advanced-capability-truth routes={len(entries)} errors={len(errors)}')
sys.exit(bool(errors))
