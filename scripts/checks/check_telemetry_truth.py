#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
errors = []

def read(rel: str) -> str:
    p = ROOT / rel
    if not p.is_file():
        errors.append(f'missing telemetry truth surface: {rel}')
        return ''
    return p.read_text(encoding='utf-8', errors='replace')

ws = read('src/apps/daemon/internal/adapters/api/websocket.go')
contracts = read('src/packages/control-ui/src/api/contracts.ts')
service = read('src/packages/control-ui/src/api/TelemetryService.ts')
store = read('src/packages/control-ui/src/store/systemStore.ts')

if 'METRICS_UPDATE' not in ws or 'trafficstats' not in ws:
    errors.append('WebSocket hub has no authoritative METRICS_UPDATE producer from trafficstats')
for token in ('RX: rates.RXBytesPerSecond', 'TX: rates.TXBytesPerSecond', 'Latency: nil'):
    if token not in ws:
        errors.append(f'WebSocket metrics producer lost truthful field mapping: {token}')
if not (ROOT / 'src/apps/daemon/internal/foundation/trafficstats/rate_sampler.go').is_file():
    errors.append('traffic rate sampler owner is missing')
if 'latency: number | null' not in contracts or 'metrics.latency === null' not in contracts:
    errors.append('frontend telemetry contract does not preserve unavailable latency as null')
if 'DIAGNOSTIC_LOG' in contracts or 'DIAGNOSTIC_LOG' in service:
    errors.append('dead DIAGNOSTIC_LOG telemetry contract remains without a daemon producer')
if 'runbookStatus' in store:
    errors.append('unused runbook telemetry state remains after diagnostic polling became authoritative')
if 'len(c.send)' in ws or "[]byte{'\\n'}" in ws or '[]byte("\\n")' in ws:
    errors.append('WebSocket writer still batches multiple JSON envelopes into one frame')
if (ROOT / 'src/apps/daemon/internal/platform/system/telemetry_server.go').exists():
    errors.append('duplicate standalone telemetry WebSocket server remains active')
if not (ROOT / 'labs/daemon/system-alternates/telemetry_server.go').is_file():
    errors.append('retired standalone telemetry server is not preserved under labs')

print(f'telemetry-truth errors={len(errors)}')
for err in errors:
    print(f'ERROR: {err}')
raise SystemExit(1 if errors else 0)
