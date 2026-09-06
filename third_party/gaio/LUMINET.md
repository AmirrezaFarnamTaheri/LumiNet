# gaio Local Fork

This directory contains a local fork of `github.com/xtaci/gaio`, mapped via a `replace` directive in `src/apps/daemon/go.mod`.

## Purpose of the Fork

`gaio` is an asynchronous proactor-pattern I/O networking framework used in the SOCKS5 proxy engine. This local fork introduces critical enhancements for high-concurrency, high-throughput execution on Windows target systems:

1. **Win32 IOCP Stability**: Patched `aio_windows.go` to handle raw socket file descriptor multiplexing safely, preventing memory leaks and descriptors from hanging under high-concurrency port sweeps.
2. **CPU Affinity Optimization**: Enhanced `affinity_windows.go` and `affinity_linux.go` to pin network processing worker goroutines to specific CPU cores, minimizing expensive context switches and context-switching jitter.
3. **Graceful Resource Recovery**: Fixed socket allocation and error propagation loops inside `watcher.go` to prevent socket leaks during sudden connection drops.

## Upstream Compatibility

These optimizations are target-locked and isolated to internal proxy mechanics. Upstream synchronization should only be performed after verifying compatible behavior on MinGW/Windows architectures.
