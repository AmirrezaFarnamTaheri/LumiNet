use std::sync::OnceLock;
use tokio::runtime::Runtime;

static RUNTIME: OnceLock<Result<Runtime, String>> = OnceLock::new();

fn build_runtime() -> Result<Runtime, String> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(num_cpus::get().min(8))
        .thread_name("lumicore-worker")
        .thread_stack_size(2 * 1024 * 1024)
        .enable_all()
        .build()
        .map_err(|err| format!("failed to build lumicore tokio runtime: {err}"))
}

/// Returns the shared Tokio runtime used by general host FFI and streaming work.
/// Initialization failure is retained and returned to every caller rather than
/// panicking across an extern-C path.
pub fn get() -> Result<&'static Runtime, String> {
    match RUNTIME.get_or_init(build_runtime) {
        Ok(runtime) => Ok(runtime),
        Err(err) => Err(err.clone()),
    }
}

/// Runtime shutdown remains process-owned. Tokio's Runtime cannot be moved out
/// of a shared OnceLock safely during normal process teardown.
pub fn shutdown() {}
