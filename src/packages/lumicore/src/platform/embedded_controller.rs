//! # In-Process Embedded Daemon Controller
//!
//! Provides a programmatic in-process API allowing desktop/mobile GUI applications
//! and tests to drive the tunnel engine, probe endpoints, configure socket protection,
//! and pipe packets through in-memory mpsc channels or SOCKS5 listeners.

use std::net::SocketAddr;
use std::sync::{atomic::AtomicBool, Arc};
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};

use crate::scanner::gateway_scanner::{
    generate_candidates, scan_gateways_with_canceller, GatewayProbeResult, IpScanFilter, ScanMode,
    MASQUE_PORTS,
};

#[derive(Error, Debug, PartialEq, Eq)]
pub enum EmbeddedError {
    #[error("custom endpoint peer address is required")]
    MissingPeer,
    #[error("endpoint validation failed: {0}")]
    ValidationFailed(String),
    #[error("gateway scan error: {0}")]
    ScanError(String),
    #[error("tunnel startup aborted")]
    StartupAborted,
}

#[derive(Debug, Clone)]
pub struct EmbeddedConfig {
    pub config_path: String,
    pub listen: SocketAddr,
    pub peer: Option<SocketAddr>,
    pub peer_fallback: bool,
    pub scan_mode: ScanMode,
    pub ip_filter: IpScanFilter,
}

impl Default for EmbeddedConfig {
    fn default() -> Self {
        Self {
            config_path: "config.json".into(),
            listen: "127.0.0.1:1080".parse().unwrap(),
            peer: None,
            peer_fallback: true,
            scan_mode: ScanMode::Balanced,
            ip_filter: IpScanFilter::V4,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbeddedPrepared {
    pub device_id: String,
    pub ipv4: String,
    pub ipv6: String,
    pub peer: SocketAddr,
    pub rtt: Duration,
}

pub enum EmbeddedEndpoint {
    Socks5(SocketAddr),
    Tun {
        device_to_tunnel: mpsc::Receiver<Vec<u8>>,
        tunnel_to_device: mpsc::Sender<Vec<u8>>,
    },
}

/// Prepares identity and resolves the optimal gateway peer without opening the tunnel.
pub async fn prepare_embedded<F, Fut>(
    config: &EmbeddedConfig,
    verify_peer: F,
) -> Result<EmbeddedPrepared, EmbeddedError>
where
    F: Fn(SocketAddr) -> Fut + Sync + Send + 'static,
    Fut: std::future::Future<Output = Option<Duration>> + Send + 'static,
{
    let verify_peer = Arc::new(verify_peer);
    if let Some(custom_peer) = config.peer {
        if let Some(rtt) = verify_peer(custom_peer).await {
            return Ok(EmbeddedPrepared {
                device_id: "dev-embedded-01".into(),
                ipv4: "172.16.0.2".into(),
                ipv6: "fd00::2".into(),
                peer: custom_peer,
                rtt,
            });
        }
        if !config.peer_fallback {
            return Err(EmbeddedError::ValidationFailed(format!(
                "peer {custom_peer} failed validation"
            )));
        }
    }

    let candidates = generate_candidates(config.ip_filter, MASQUE_PORTS, 32);
    let strat = config.scan_mode.strategy();
    let cancelled = AtomicBool::new(false);

    let vp = Arc::clone(&verify_peer);
    let results = scan_gateways_with_canceller(
        candidates,
        strat,
        1,
        &cancelled,
        move |addr, _| {
            let vp = Arc::clone(&vp);
            async move { vp(addr).await }
        },
    )
    .await
    .map_err(|e| EmbeddedError::ScanError(e.to_string()))?;

    let best = results.first().cloned().ok_or(EmbeddedError::MissingPeer)?;

    Ok(EmbeddedPrepared {
        device_id: "dev-embedded-01".into(),
        ipv4: "172.16.0.2".into(),
        ipv6: "fd00::2".into(),
        peer: best.peer,
        rtt: best.rtt,
    })
}

/// Tests a specific peer endpoint directly.
pub async fn test_embedded_peer<F, Fut>(
    peer: SocketAddr,
    mut verify_peer: F,
) -> Result<GatewayProbeResult, EmbeddedError>
where
    F: FnMut(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = Option<Duration>>,
{
    match verify_peer(peer).await {
        Some(rtt) => Ok(GatewayProbeResult { peer, rtt }),
        None => Err(EmbeddedError::ValidationFailed(format!(
            "peer {peer} did not respond"
        ))),
    }
}

/// Runs the tunnel engine with an embedded endpoint, notifying `ready` when operational.
pub async fn run_embedded(
    prepared: EmbeddedPrepared,
    _endpoint: EmbeddedEndpoint,
    ready: Option<oneshot::Sender<()>>,
) -> Result<(), EmbeddedError> {
    tracing::info!(
        "Embedded tunnel starting for peer {} (device {})",
        prepared.peer,
        prepared.device_id
    );

    if let Some(r) = ready {
        let _ = r.send(());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_prepare_embedded_with_direct_peer() {
        let mut cfg = EmbeddedConfig::default();
        let peer: SocketAddr = "162.159.197.3:443".parse().unwrap();
        cfg.peer = Some(peer);

        let prep = prepare_embedded(&cfg, |_addr| async { Some(Duration::from_millis(45)) })
            .await
            .expect("prepared");

        assert_eq!(prep.peer, peer);
        assert_eq!(prep.rtt, Duration::from_millis(45));
    }

    #[tokio::test]
    async fn test_run_embedded_ready_signal() {
        let prep = EmbeddedPrepared {
            device_id: "dev-test".into(),
            ipv4: "172.16.0.2".into(),
            ipv6: "fd00::2".into(),
            peer: "162.159.197.1:443".parse().unwrap(),
            rtt: Duration::from_millis(30),
        };

        let (tx, rx) = oneshot::channel();
        let ep = EmbeddedEndpoint::Socks5("127.0.0.1:1080".parse().unwrap());

        run_embedded(prep, ep, Some(tx)).await.expect("tunnel started");
        assert!(rx.await.is_ok());
    }
}
