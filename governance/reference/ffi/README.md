# Retired generated FFI header evidence

This directory preserves the former cbindgen configuration and generated
repository-root header byte-for-byte as historical/reference evidence.

They are intentionally not part of the active build. The supported Go host
bridge owns one private declaration surface at
`apps/daemon/internal/bridge/lumicore_abi.h`, while the Rust `#[repr(C)]` types
and exported `extern "C"` functions remain the implementation authority.
`scripts/checks/check_lumicore_abi.py` prevents those two sides from drifting.
