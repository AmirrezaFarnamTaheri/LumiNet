use serde::{Deserialize, Serialize};
use std::process::Stdio;
use tokio::process::{Child, Command};
use tokio::task::JoinHandle;
use tracing::info;

/// Defines the configuration for spawning a SIP003 plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sip003PluginConfig {
    pub plugin_path: String,
    pub plugin_opts: String,
    pub local_host: String,
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
}

/// Represents an actively running SIP003 plugin instance
pub struct Sip003PluginInstance {
    pub config: Sip003PluginConfig,
    child: Child,
    monitor_task: Option<JoinHandle<()>>,
}

impl Sip003PluginInstance {
    /// Spawns the SIP003 plugin process and starts a monitor task
    pub fn start(config: Sip003PluginConfig) -> std::io::Result<Self> {
        info!("Spawning SIP003 plugin at {}", config.plugin_path);

        let child = Command::new(&config.plugin_path)
            .env("SS_PLUGIN_OPTIONS", &config.plugin_opts)
            .env("SS_LOCAL_HOST", &config.local_host)
            .env("SS_LOCAL_PORT", config.local_port.to_string())
            .env("SS_REMOTE_HOST", &config.remote_host)
            .env("SS_REMOTE_PORT", config.remote_port.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true) // Ensure it dies if we drop it
            .spawn()?;

        // Example logic: in a real implementation we would notify Go
        // via `crate::ffi::async_exports::dispatch_async_cgo_callback` if it dies unexpectedly.

        Ok(Self {
            config,
            child,
            monitor_task: None, // We would assign a monitor task here
        })
    }

    /// Kills the running plugin process
    pub async fn stop(&mut self) -> std::io::Result<()> {
        info!("Stopping SIP003 plugin...");
        self.child.kill().await?;
        if let Some(task) = self.monitor_task.take() {
            task.abort();
        }
        Ok(())
    }
}
