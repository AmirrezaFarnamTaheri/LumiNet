//
// Rust-based WebAssembly Transport Module (WATM) host. Loads `.wasm` files
// implementing client pluggable transports (WATER-style) and runs them
// against host-provided TCP socket hooks.
//
// ponytail: gated behind the `wasm-transport` cargo feature because the
// `wasmtime` dep tree is heavy (~50 MB build artifacts) and pulls network
// access on first build. Without the feature the module compiles to thin
// stubs so `cargo build` stays green offline. Flip the feature on when
// the project needs real .wasm transport modules.
//
// Ceiling: single-Wasm instance per host; concurrent transports require
// one Engine per transport (wasmtime Engine is cheap to clone via Arc).
// Upgrade path: pool Engines under a `DashMap<TransportId, Engine>`.

#[cfg(feature = "wasm-transport")]
use std::path::Path;
#[cfg(feature = "wasm-transport")]
use std::sync::Arc;

#[cfg(feature = "wasm-transport")]
use wasmtime::{Engine, Instance, Linker, Module, Store};

/// Errors surfaced by the WATM host.
#[derive(Debug, thiserror::Error)]
pub enum WasmTransportError {
    #[cfg(feature = "wasm-transport")]
    #[error("wasm engine init failed: {0}")]
    EngineInit(String),
    #[cfg(feature = "wasm-transport")]
    #[error("wasm module load failed: {0}")]
    ModuleLoad(String),
    #[cfg(feature = "wasm-transport")]
    #[error("wasm instantiation failed: {0}")]
    Instantiate(String),
    #[cfg(feature = "wasm-transport")]
    #[error("host hook binding failed: {0}")]
    HookBind(String),
    #[error("feature disabled: rebuild with --features wasm-transport")]
    FeatureDisabled,
}

/// A running WATM host: holds the wasmtime Engine and the loaded module.
#[cfg(feature = "wasm-transport")]
pub struct WasmTransport {
    engine: Engine,
    module: Module,
    linker: Linker<HostState>,
}

/// Host-side state passed into every guest call: a TCP dial helper callback
/// (host function imported into guest memory) and a buffer of bytes most
/// recently handed by the guest to `host_send_tcp`.
#[cfg(feature = "wasm-transport")]
pub struct HostState {
    /// Last chunk the guest asked us to push onto a TCP socket.
    pub last_send: Vec<u8>,
    /// Bytes captured from the upstream TCP socket for the guest to read.
    pub last_recv: Vec<u8>,
}

#[cfg(feature = "wasm-transport")]
fn guest_range(ptr: i32, len: i32) -> Option<std::ops::Range<usize>> {
    let start = usize::try_from(ptr).ok()?;
    let len = usize::try_from(len).ok()?;
    Some(start..start.checked_add(len)?)
}

#[cfg(feature = "wasm-transport")]
impl WasmTransport {
    /// Create a new host by compiling the `.wasm` file at `path`.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, WasmTransportError> {
        let engine = Engine::default();
        let module = Module::from_file(&engine, path.as_ref())
            .map_err(|e| WasmTransportError::ModuleLoad(e.to_string()))?;
        let mut linker: Linker<HostState> = Linker::new(&engine);

        // host_tcp_dial(addr_ptr: i32, addr_len: i32) -> i32 (fd or -1)
        linker
            .func_wrap(
                "host",
                "host_tcp_dial",
                |mut _caller: wasmtime::Caller<'_, HostState>,
                 _addr_ptr: i32,
                 _addr_len: i32|
                 -> i32 {
                    // ponytail: real implementation reads the guest memory slice,
                    // dials TcpStream, stores the FD in HostState. Returning a
                    // synthetic fd (3) — already connected — to keep guests that
                    // inspect the fd happy until real dial wiring is plugged in.
                    3
                },
            )
            .map_err(|e| WasmTransportError::HookBind(e.to_string()))?;

        // host_send_tcp(fd: i32, buf_ptr: i32, buf_len: i32) -> i32 (bytes written)
        linker
            .func_wrap(
                "host",
                "host_send_tcp",
                |mut caller: wasmtime::Caller<'_, HostState>,
                 _fd: i32,
                 buf_ptr: i32,
                 buf_len: i32|
                 -> i32 {
                    let Some(range) = guest_range(buf_ptr, buf_len) else {
                        return 0;
                    };
                    let Some(mem) = caller.get_export("memory").and_then(|e| e.into_memory())
                    else {
                        return 0;
                    };
                    let Some(data) = mem.data(&caller).get(range).map(<[u8]>::to_vec) else {
                        return 0;
                    };
                    caller.data_mut().last_send.extend_from_slice(&data);
                    buf_len
                },
            )
            .map_err(|e| WasmTransportError::HookBind(e.to_string()))?;

        // host_recv_tcp(fd: i32, buf_ptr: i32, buf_len: i32) -> i32 (bytes read)
        linker
            .func_wrap(
                "host",
                "host_recv_tcp",
                |mut caller: wasmtime::Caller<'_, HostState>,
                 _fd: i32,
                 buf_ptr: i32,
                 buf_len: i32|
                 -> i32 {
                    let state_len = caller.data().last_recv.len();
                    if state_len == 0 {
                        return 0;
                    }
                    let Some(range) = guest_range(buf_ptr, buf_len) else {
                        return 0;
                    };
                    let take = state_len.min(range.len());
                    let Some(mem) = caller.get_export("memory").and_then(|e| e.into_memory())
                    else {
                        return 0;
                    };
                    let data = caller.data().last_recv[..take].to_vec();
                    // ponytail: try lifting the slice into guest memory directly.
                    // Partial write only — drain step is handled by caller invoking
                    // `host_commit_recv` in a real implementation.
                    if mem.write(&mut caller, range.start, &data).is_ok() {
                        take as i32
                    } else {
                        0
                    }
                },
            )
            .map_err(|e| WasmTransportError::HookBind(e.to_string()))?;

        Ok(Self {
            engine,
            module,
            linker,
        })
    }

    /// Instantiate the module and return a ready-to-run session handle.
    pub fn instantiate(&self) -> Result<WasmTransportSession, WasmTransportError> {
        let mut store = Store::new(
            &self.engine,
            HostState {
                last_send: Vec::new(),
                last_recv: Vec::new(),
            },
        );
        let instance = self
            .linker
            .instantiate(&mut store, &self.module)
            .map_err(|e| WasmTransportError::Instantiate(e.to_string()))?;
        Ok(WasmTransportSession {
            store,
            instance,
            engine: Arc::new(self.engine.clone()),
        })
    }
}

#[cfg(feature = "wasm-transport")]
pub struct WasmTransportSession {
    store: Store<HostState>,
    instance: Instance,
    #[allow(dead_code)]
    engine: Arc<Engine>,
}

#[cfg(feature = "wasm-transport")]
impl WasmTransportSession {
    /// Call the guest's `transport_connect(dest, dest_len) -> i32` entry.
    pub fn connect(&mut self, dest: &str) -> Result<i32, WasmTransportError> {
        let func = self
            .instance
            .get_typed_func::<(i32, i32), i32>(&mut self.store, "transport_connect")
            .map_err(|e| WasmTransportError::Instantiate(e.to_string()))?;
        let dest_bytes = dest.as_bytes();
        let mem = self
            .instance
            .get_memory(&mut self.store, "memory")
            .ok_or_else(|| WasmTransportError::Instantiate("no exported memory".into()))?;
        let off = 0usize;
        mem.write(&mut self.store, off, dest_bytes)
            .map_err(|e| WasmTransportError::HookBind(e.to_string()))?;
        let rc = func
            .call(&mut self.store, (off as i32, dest_bytes.len() as i32))
            .map_err(|e| WasmTransportError::Instantiate(e.to_string()))?;
        Ok(rc)
    }

    /// Most recent bytes the guest asked the host to send on TCP. Useful for
    /// tests that want to assert what the wrapped transport emitted.
    pub fn drain_guest_send(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.store.data_mut().last_send)
    }

    /// Feed upstream bytes back into the guest so the next `host_recv_tcp`
    /// call returns them.
    pub fn feed_guest_recv(&mut self, bytes: &[u8]) {
        self.store.data_mut().last_recv.extend_from_slice(bytes);
    }
}

/// Server-side WATM listener. Accepts incoming connections, hands each
/// new socket to the guest via `host_tcp_accept`, and lets the guest
/// decode the obfuscated payload. Mirrors water-rs `runtime/listener.rs`.
#[cfg(feature = "wasm-transport")]
pub struct WasmListener {
    engine: Engine,
    module: Module,
    linker: Linker<HostState>,
}

#[cfg(feature = "wasm-transport")]
impl WasmListener {
    /// Load a WATM listener module from `path`. The guest must export
    /// `transport_listen` (returns listen fd) and handle `host_tcp_accept`
    /// callbacks for each new connection.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, WasmTransportError> {
        let engine = Engine::default();
        let module = Module::from_file(&engine, path.as_ref())
            .map_err(|e| WasmTransportError::ModuleLoad(e.to_string()))?;
        let mut linker: Linker<HostState> = Linker::new(&engine);

        // host_tcp_dial — reused from client mode.
        linker
            .func_wrap(
                "host",
                "host_tcp_dial",
                |mut _caller: wasmtime::Caller<'_, HostState>,
                 _addr_ptr: i32,
                 _addr_len: i32|
                 -> i32 { 3 },
            )
            .map_err(|e| WasmTransportError::HookBind(e.to_string()))?;

        // host_tcp_accept(listen_fd: i32) -> i32 (accepted fd or -1)
        // Guest calls this to accept the next incoming connection on the
        // listen socket the host bound.
        linker
            .func_wrap(
                "host",
                "host_tcp_accept",
                |_caller: wasmtime::Caller<'_, HostState>, listen_fd: i32| -> i32 {
                    // ponytail: real implementation calls accept(listen_fd)
                    // and stores the new fd in HostState. Synthetic accept
                    // returns 4 for guests that inspect the fd.
                    let _ = listen_fd; // real impl: accept on this fd
                    4
                },
            )
            .map_err(|e| WasmTransportError::HookBind(e.to_string()))?;

        // host_send_tcp / host_recv_tcp — identical to client mode.
        linker
            .func_wrap(
                "host",
                "host_send_tcp",
                |mut caller: wasmtime::Caller<'_, HostState>,
                 _fd: i32,
                 buf_ptr: i32,
                 buf_len: i32|
                 -> i32 {
                    let Some(range) = guest_range(buf_ptr, buf_len) else {
                        return 0;
                    };
                    let Some(mem) = caller.get_export("memory").and_then(|e| e.into_memory())
                    else {
                        return 0;
                    };
                    let Some(data) = mem.data(&caller).get(range).map(<[u8]>::to_vec) else {
                        return 0;
                    };
                    caller.data_mut().last_send.extend_from_slice(&data);
                    buf_len
                },
            )
            .map_err(|e| WasmTransportError::HookBind(e.to_string()))?;

        linker
            .func_wrap(
                "host",
                "host_recv_tcp",
                |mut caller: wasmtime::Caller<'_, HostState>,
                 _fd: i32,
                 buf_ptr: i32,
                 buf_len: i32|
                 -> i32 {
                    let state_len = caller.data().last_recv.len();
                    if state_len == 0 {
                        return 0;
                    }
                    let Some(range) = guest_range(buf_ptr, buf_len) else {
                        return 0;
                    };
                    let take = state_len.min(range.len());
                    let Some(mem) = caller.get_export("memory").and_then(|e| e.into_memory())
                    else {
                        return 0;
                    };
                    let data = caller.data().last_recv[..take].to_vec();
                    if mem.write(&mut caller, range.start, &data).is_ok() {
                        take as i32
                    } else {
                        0
                    }
                },
            )
            .map_err(|e| WasmTransportError::HookBind(e.to_string()))?;

        Ok(Self {
            engine,
            module,
            linker,
        })
    }

    /// Instantiate and start listening. Returns a session handle that
    /// the caller drives by polling `accept()` / `feed_guest_recv()`.
    pub fn instantiate(&self) -> Result<WasmListenerSession, WasmTransportError> {
        let mut store = Store::new(
            &self.engine,
            HostState {
                last_send: Vec::new(),
                last_recv: Vec::new(),
            },
        );
        let instance = self
            .linker
            .instantiate(&mut store, &self.module)
            .map_err(|e| WasmTransportError::Instantiate(e.to_string()))?;
        // Kick off the guest's listen entry point if present.
        if let Ok(func) = instance.get_typed_func::<(), i32>(&mut store, "transport_listen") {
            let _ = func.call(&mut store, ());
        }
        Ok(WasmListenerSession {
            store,
            instance,
            engine: Arc::new(self.engine.clone()),
        })
    }
}

/// Server-side WASM session handle produced by [`WasmListener::instantiate`].
#[cfg(feature = "wasm-transport")]
pub struct WasmListenerSession {
    store: Store<HostState>,
    instance: Instance,
    #[allow(dead_code)]
    engine: Arc<Engine>,
}

#[cfg(feature = "wasm-transport")]
impl WasmListenerSession {
    /// Accept the next inbound connection via the guest's `host_tcp_accept`.
    /// Returns a synthetic accepted fd (real impl: kernel accept result).
    pub fn accept(&mut self) -> Result<i32, WasmTransportError> {
        let func = self
            .instance
            .get_typed_func::<(i32,), i32>(&mut self.store, "host_tcp_accept")
            .map_err(|e| WasmTransportError::Instantiate(e.to_string()))?;
        func.call(&mut self.store, (4,)) // 4 = synthetic listen fd
            .map_err(|e| WasmTransportError::Instantiate(e.to_string()))
    }

    /// Feed decrypted bytes from the guest back to the host network stack.
    pub fn drain_guest_send(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.store.data_mut().last_send)
    }

    /// Push inbound plaintext into the guest for encoding/sending.
    pub fn feed_guest_recv(&mut self, bytes: &[u8]) {
        self.store.data_mut().last_recv.extend_from_slice(bytes);
    }
}

#[cfg(not(feature = "wasm-transport"))]
#[derive(Debug)]
pub struct WasmTransport;

#[cfg(not(feature = "wasm-transport"))]
impl WasmTransport {
    pub fn load(_path: impl AsRef<std::path::Path>) -> Result<Self, WasmTransportError> {
        Err(WasmTransportError::FeatureDisabled)
    }
    pub fn instantiate(&self) -> Result<(), WasmTransportError> {
        Err(WasmTransportError::FeatureDisabled)
    }
}

#[cfg(not(feature = "wasm-transport"))]
#[derive(Debug)]
pub struct WasmListener;

#[cfg(not(feature = "wasm-transport"))]
impl WasmListener {
    pub fn load(_path: impl AsRef<std::path::Path>) -> Result<Self, WasmTransportError> {
        Err(WasmTransportError::FeatureDisabled)
    }
    pub fn instantiate(&self) -> Result<(), WasmTransportError> {
        Err(WasmTransportError::FeatureDisabled)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "wasm-transport"))]
    use super::*;

    #[cfg(not(feature = "wasm-transport"))]
    #[test]
    fn load_returns_feature_disabled_without_feature() {
        let err = WasmTransport::load("nonexistent.wasm").unwrap_err();
        assert!(matches!(err, WasmTransportError::FeatureDisabled));
    }

    #[cfg(feature = "wasm-transport")]
    #[test]
    fn guest_range_rejects_negative_and_overflowing_inputs() {
        assert_eq!(super::guest_range(4, 8), Some(4..12));
        assert_eq!(super::guest_range(-1, 8), None);
        assert_eq!(super::guest_range(4, -1), None);
    }
}
