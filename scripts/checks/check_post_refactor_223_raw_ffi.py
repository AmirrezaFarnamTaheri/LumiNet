#!/usr/bin/env python3
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
exports=(ROOT/'src/packages/lumicore/src/ffi/exports.rs').read_text()
version=(ROOT/'src/packages/lumicore/src/ffi/version.rs').read_text()
shm=(ROOT/'src/packages/lumicore/src/shm.rs').read_text()
errors=[]
def req(c,m):
    if not c: errors.append(m)
req('if len != 0 && data.is_null()' in exports, 'push_packet_ffi can form slice from null input')
req('if max_len == 0 || buf.is_null()' in exports, 'pop_packet_ffi can copy into null/zero output')
req('crate::shm::SLOT_SIZE' in exports, 'packet FFI does not bind size to shared slot capacity')
req('if buf.is_null() || buf_len == 0' in version, 'version string can form slice from null/zero buffer')
req('fn checked_capacity' in shm, 'shared ring capacity is not validated before modulo')
req('capacity == 0 || capacity > RING_CAPACITY' in shm, 'shared ring does not reject zero/oversized capacity')
req('head.checked_sub(tail)' in shm, 'shared ring sequence underflow is not checked')
if errors:
    print(f'post-refactor-223 raw FFI: FAIL ({len(errors)} errors)')
    for e in errors: print('ERROR:',e)
    raise SystemExit(1)
print('post-refactor-223 raw FFI: PASS')
