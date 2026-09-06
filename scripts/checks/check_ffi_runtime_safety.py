#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
errors=[]

def read(rel):
    p=ROOT/rel
    if not p.is_file():
        errors.append(f'missing FFI runtime safety surface: {rel}')
        return ''
    return p.read_text(encoding='utf-8', errors='replace')

runtime=read('src/packages/lumicore/src/runtime.rs')
exports=read('src/packages/lumicore/src/ffi/exports.rs')
streaming=read('src/packages/lumicore/src/ffi/streaming.rs')
lib=read('src/packages/lumicore/src/lib.rs')
ios_ffi=read('src/packages/lumicore/src/ffi/ios_ffi.rs')
go_stream=read('src/apps/daemon/internal/native/bridge/streaming.go')
header=read('src/apps/daemon/internal/native/bridge/lumicore_abi.h')

if 'TOKIO_RT' in runtime or '.expect(' in runtime:
    errors.append('canonical Rust runtime still has panic-initialized TOKIO_RT authority')
if 'OnceLock<Result<Runtime, String>>' not in runtime or 'pub fn get() -> Result<&\'static Runtime, String>' not in runtime:
    errors.append('Rust runtime is not a fallible one-owner OnceLock interface')
if 'static RUNTIME:' in exports or 'crate::runtime::get()' not in exports:
    errors.append('FFI exports still own a second Tokio runtime instead of canonical runtime::get')
if 'Result<R, String>' not in exports or '.expect("Failed to build Compio runtime")' in exports:
    errors.append('Compio FFI runtime is still panic-initialized instead of returning initialization failure')
if 'crate::runtime::get()' not in streaming or 'stream_id: 0' not in streaming:
    errors.append('streaming FFI does not fail closed with a zero handle when runtime initialization fails')
if 'TOKIO_RT' in lib or 'crate::runtime::get()' not in lib:
    errors.append('lumicore_init still forces panic-initialized TOKIO_RT instead of fallible runtime owner')
if 'session_map().lock().unwrap()' in ios_ffi or 'fn lock_sessions() -> Result<' not in ios_ffi:
    errors.append('iOS FFI session state still panics on a poisoned mutex instead of returning an ABI-safe failure')
if 'panic!("allocate stream callback context")' in go_stream or 'handle.stream_id == 0' not in go_stream:
    errors.append('Go streaming bridge does not fail closed on callback allocation/runtime-start failure')
if 'STREAM_MAP.remove(&stream_id)' not in streaming or 'STREAM_EVT_SCAN_DONE' not in streaming:
    errors.append('Rust stream task does not publish terminal completion and release stream ownership')
if 'AssertUnwindSafe' not in streaming or not re.search(r'\.catch_unwind\(\)\s*\.await', streaming):
    errors.append('Rust stream task can panic before terminal cleanup')
if (
    'eventType == C.uint16_t(C.LUMICORE_STREAM_EVT_SCAN_DONE)' not in go_stream
    or 'C.free(userData)' not in go_stream
):
    errors.append('Go callback does not own terminal context/channel cleanup')
# cancel must only signal Rust; freeing callback memory before the task reaches its
# terminal callback would permit a late callback to dereference freed memory.
cancel_rust_start = streaming.find('pub unsafe extern \"C\" fn lumicore_stream_cancel')
if cancel_rust_start >= 0 and 'STREAM_MAP.remove' in streaming[cancel_rust_start:]:
    errors.append('Rust cancel removes stream ownership before terminal completion')
cancel_start = go_stream.find('cancel := func()')
cancel_end = go_stream.find('return ch, cancel, nil', cancel_start)
if cancel_start >= 0 and cancel_end >= 0 and 'C.free(callbackContext)' in go_stream[cancel_start:cancel_end]:
    errors.append('Go cancel still frees callback context before Rust task termination')
if 'uint64_t stream_id;' not in header:
    errors.append('StreamHandle ABI layout changed unexpectedly')

print(f'ffi-runtime-safety errors={len(errors)}')
for e in errors: print(f'ERROR: {e}')
raise SystemExit(1 if errors else 0)
