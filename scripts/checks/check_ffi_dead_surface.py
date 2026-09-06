#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
errors = []

def text(rel: str) -> str:
    p = ROOT / rel
    return p.read_text(encoding='utf-8', errors='replace') if p.is_file() else ''

if (ROOT / 'src/apps/daemon/internal/native/bridge/binary_scan.go').exists():
    errors.append('unused Go ExecScan compatibility surface remains active')
if 'lumicore_scan_execution' in text('src/packages/lumicore/src/ffi/binary_scan.rs'):
    errors.append('mock Rust lumicore_scan_execution export remains active')
header = text('src/apps/daemon/internal/native/bridge/lumicore_abi.h')
if 'lumicore_scan_execution' in header:
    errors.append('private host ABI still declares retired mock scan execution')
for name in ('PackedScanConfig', 'PackedTarget', 'PackedResult'):
    if name in header:
        errors.append(f'private host ABI still exposes Rust-internal scan type {name}')
if not (ROOT / 'labs/daemon/ffi-alternates/binary_scan_mock.go').is_file():
    errors.append('historical Go binary scan mock is not preserved under labs')
if not (ROOT / 'labs/lumicore/ffi-alternates/binary_scan_mock.rs').is_file():
    errors.append('historical Rust binary scan mock is not preserved under labs')
if 'C.lumicore_call' not in text('src/apps/daemon/internal/native/bridge/ffi.go'):
    errors.append('canonical generic binary FFI call seam is missing from Go')
if 'pub unsafe extern "C" fn lumicore_call' not in text('src/packages/lumicore/src/ffi/binary_bridge.rs'):
    errors.append('canonical generic binary FFI call seam is missing from Rust')

print(f'ffi-dead-surface errors={len(errors)}')
for error in errors:
    print(f'ERROR: {error}')
raise SystemExit(1 if errors else 0)
