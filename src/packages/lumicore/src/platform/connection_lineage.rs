use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Connection states representing the full lifecycle of a tunnel/proxy lineage.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "state", content = "data")]
pub enum ConnectionState {
    Idle,
    Launching,
    Connecting,
    Connected {
        socks_addr: String,
        connected_at_ms: u64,
    },
    Reconnecting {
        attempt: u32,
        max_attempts: u32,
    },
    Disconnecting,
    Error {
        message: String,
        phase: String,
    },
}

/// Action determined by the lineage manager when an unexpected disconnect occurs.
#[derive(Debug, PartialEq, Eq)]
pub enum LineageAction {
    /// Retry should proceed with the given attempt counter and backoff sleep.
    Retry { attempt: u32, backoff: Duration },
    /// Retry budget exhausted, transition to Error.
    Exhausted { message: String },
}

/// Manages connection lineage, state transitions, and auto-retry budgets.
pub struct LineageManager {
    state: ConnectionState,
    max_retries: u32,
    retry_backoffs: Vec<Duration>,
    retry_count: u32,
    user_requested_stop: bool,
}

impl LineageManager {
    /// Constructs a new LineageManager with configurable retry policies.
    pub fn new(max_retries: u32, retry_backoffs: Vec<Duration>) -> Self {
        Self {
            state: ConnectionState::Idle,
            max_retries,
            retry_backoffs,
            retry_count: 0,
            user_requested_stop: false,
        }
    }

    /// Constructs standard default manager (3 retries: 2s, 5s, 10s).
    pub fn default_policy() -> Self {
        Self::new(
            3,
            vec![
                Duration::from_secs(2),
                Duration::from_secs(5),
                Duration::from_secs(10),
            ],
        )
    }

    pub fn state(&self) -> &ConnectionState {
        &self.state
    }

    pub fn is_user_stopping(&self) -> bool {
        self.user_requested_stop
    }

    /// Invoked when user requests a new connection.
    pub fn on_user_connect(&mut self) -> Result<(), &'static str> {
        if !matches!(self.state, ConnectionState::Idle | ConnectionState::Error { .. }) {
            return Err("already running or transitioning");
        }
        self.user_requested_stop = false;
        self.retry_count = 0;
        self.state = ConnectionState::Launching;
        Ok(())
    }

    /// Invoked when route scan / handshake begins.
    pub fn on_connecting(&mut self) {
        if self.state == ConnectionState::Launching {
            self.state = ConnectionState::Connecting;
        }
    }

    /// Invoked when socket becomes live and connection is established.
    pub fn on_connected(&mut self, socks_addr: String) {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        self.retry_count = 0;
        self.state = ConnectionState::Connected {
            socks_addr,
            connected_at_ms: now_ms,
        };
    }

    /// Handles unexpected drop or timeout.
    pub fn on_unexpected_drop(&mut self, reason: &str) -> LineageAction {
        if self.user_requested_stop {
            self.state = ConnectionState::Idle;
            return LineageAction::Exhausted {
                message: "stopped by user".into(),
            };
        }

        self.retry_count += 1;
        if self.retry_count > self.max_retries {
            let msg = format!("{reason} (exhausted {} retries)", self.max_retries);
            self.state = ConnectionState::Error {
                message: msg.clone(),
                phase: "exhausted".into(),
            };
            return LineageAction::Exhausted { message: msg };
        }

        let backoff_idx = (self.retry_count - 1) as usize;
        let backoff = self
            .retry_backoffs
            .get(backoff_idx)
            .cloned()
            .unwrap_or(Duration::from_secs(5));

        self.state = ConnectionState::Reconnecting {
            attempt: self.retry_count,
            max_attempts: self.max_retries,
        };

        LineageAction::Retry {
            attempt: self.retry_count,
            backoff,
        }
    }

    /// Prepares for next retry attempt after backoff sleep.
    pub fn on_retry_launch(&mut self) {
        if !self.user_requested_stop {
            self.state = ConnectionState::Launching;
        }
    }

    /// Invoked when user requests disconnection.
    pub fn on_user_disconnect(&mut self) {
        self.user_requested_stop = true;
        self.retry_count = 0;
        self.state = ConnectionState::Disconnecting;
    }

    /// Invoked when shutdown process finishes.
    pub fn on_disconnected(&mut self) {
        self.user_requested_stop = false;
        self.state = ConnectionState::Idle;
    }
}

/// Normalizes a bind address so 0.0.0.0 is probed on loopback 127.0.0.1.
pub fn normalize_probe_addr(listen: &SocketAddr) -> SocketAddr {
    if listen.ip().is_unspecified() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen.port())
    } else {
        *listen
    }
}

/// Probes TCP socket liveness with a short timeout.
pub fn port_is_live(addr: &SocketAddr, timeout: Duration) -> bool {
    let target = normalize_probe_addr(addr);
    TcpStream::connect_timeout(&target, timeout).is_ok()
}

/// Strips ANSI escape codes from raw PTY and terminal stream output.
pub fn strip_ansi(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for c2 in chars.by_ref() {
                if c2.is_ascii_alphabetic() {
                    break;
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

const MAX_TERMINAL_PARTIAL: usize = 16 * 1024;

/// Drains terminated lines from buffer while discarding intermediate carriage-return spinner frames.
pub fn drain_terminal_lines(buf: &mut String) -> Vec<String> {
    let mut lines = Vec::new();
    while let Some(pos) = buf.find(['\r', '\n']) {
        let end = if buf.as_bytes()[pos] == b'\n' {
            pos
        } else {
            let mut run_end = pos;
            while run_end < buf.len() && buf.as_bytes()[run_end] == b'\r' {
                run_end += 1;
            }
            if run_end == buf.len() {
                break; // Possible split \r\n across reads
            }
            if buf.as_bytes()[run_end] != b'\n' {
                // Carriage return overwrite: discard overwritten frame
                buf.drain(..run_end);
                continue;
            }
            run_end
        };
        let line: String = buf.drain(..=end).collect();
        lines.push(line.trim_end_matches(['\r', '\n']).to_string());
    }

    if buf.len() > MAX_TERMINAL_PARTIAL {
        let mut cut = buf.len() - MAX_TERMINAL_PARTIAL;
        while !buf.is_char_boundary(cut) {
            cut += 1;
        }
        buf.drain(..cut);
    }

    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lineage_lifecycle_success() {
        let mut mgr = LineageManager::default_policy();
        assert_eq!(*mgr.state(), ConnectionState::Idle);

        mgr.on_user_connect().unwrap();
        assert_eq!(*mgr.state(), ConnectionState::Launching);

        mgr.on_connecting();
        assert_eq!(*mgr.state(), ConnectionState::Connecting);

        mgr.on_connected("127.0.0.1:1819".into());
        match mgr.state() {
            ConnectionState::Connected { socks_addr, .. } => {
                assert_eq!(socks_addr, "127.0.0.1:1819");
            }
            other => panic!("expected Connected, got {:?}", other),
        }

        mgr.on_user_disconnect();
        assert_eq!(*mgr.state(), ConnectionState::Disconnecting);

        mgr.on_disconnected();
        assert_eq!(*mgr.state(), ConnectionState::Idle);
    }

    #[test]
    fn lineage_retry_and_exhaustion() {
        let mut mgr = LineageManager::new(2, vec![Duration::from_millis(10), Duration::from_millis(20)]);

        mgr.on_user_connect().unwrap();
        mgr.on_connecting();

        // Drop 1 -> Retry 1
        let action1 = mgr.on_unexpected_drop("handshake timeout");
        assert_eq!(
            action1,
            LineageAction::Retry {
                attempt: 1,
                backoff: Duration::from_millis(10)
            }
        );

        mgr.on_retry_launch();
        assert_eq!(*mgr.state(), ConnectionState::Launching);

        // Drop 2 -> Retry 2
        let action2 = mgr.on_unexpected_drop("peer disconnected");
        assert_eq!(
            action2,
            LineageAction::Retry {
                attempt: 2,
                backoff: Duration::from_millis(20)
            }
        );

        // Drop 3 -> Exhausted
        let action3 = mgr.on_unexpected_drop("peer disconnected");
        match action3 {
            LineageAction::Exhausted { message } => {
                assert!(message.contains("exhausted 2 retries"));
            }
            other => panic!("expected Exhausted, got {:?}", other),
        }
        match mgr.state() {
            ConnectionState::Error { message, phase } => {
                assert_eq!(phase, "exhausted");
                assert!(message.contains("exhausted 2 retries"));
            }
            other => panic!("expected Error, got {:?}", other),
        }
    }

    #[test]
    fn strip_ansi_codes() {
        let formatted = "\u{1b}[32m[INFO]\u{1b}[0m Connection \u{1b}[1mestablished\u{1b}[0m";
        assert_eq!(strip_ansi(formatted), "[INFO] Connection established");
    }

    #[test]
    fn terminal_drain_lines_with_cr_overwrites() {
        let mut buf = "scanning 10%\rscanning 50%\rscanning 100%\nroute verified\r\n".to_string();
        let lines = drain_terminal_lines(&mut buf);
        assert_eq!(lines, vec!["scanning 100%", "route verified"]);
        assert_eq!(buf, "");
    }
}
