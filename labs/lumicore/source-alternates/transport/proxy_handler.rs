// Ported from: tun2proxy proxy_handler.rs (Pass 3 Order 23)
// Target path: core/src/transport/proxy_handler.rs
//
// Async `ProxyHandler` trait — bidirectional buffered relay state machine
// lifted from tun2proxy. The C++ original is a blocking state machine; the
// Rust port uses `async_trait` (already in Cargo.toml) so each proxy
// implementation (SOCKS5, HTTP CONNECT, future pluggable transports)
// plugs in via the same surface.

use std::io;
use std::net::SocketAddr;

use async_trait::async_trait;

/// Direction of buffered outgoing data — used by `peek_data` / `consume_data`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum OutgoingDirection {
    ToClient,
    ToServer,
}

/// Event yielded by `peek_data` so callers can drain without pulling bytes
/// out of the state machine. Mirrors tun2proxy's `OutgoingDataEvent`.
pub struct OutgoingDataEvent<'a> {
    pub direction: OutgoingDirection,
    pub bytes: &'a [u8],
}

/// Where incoming data came from — drives the relay direction.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IncomingSource {
    Client,
    Server,
}

/// Immutable session info ready for the proxy to consume.
#[derive(Clone, Debug)]
pub struct SessionInfo {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub proto: &'static str,
}

/// The bidirectional buffered proxy state machine.
///
/// Each implementation drives `push_data` with bytes arriving on either
/// the client or server side; the implementation deframes, performs the
/// handshake, then populates outgoing buffers the host flushes via
/// `peek_data` / `consume_data`.
#[async_trait]
pub trait ProxyHandler: Send + Sync {
    fn server_addr(&self) -> SocketAddr;
    fn session_info(&self) -> SessionInfo;
    async fn push_data(&mut self, source: IncomingSource, data: &[u8]) -> io::Result<()>;
    fn consume_data(&mut self, direction: OutgoingDirection, size: usize);
    fn peek_data(&mut self, direction: OutgoingDirection) -> OutgoingDataEvent<'_>;
    fn connection_established(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct EchoHandler {
        info: SessionInfo,
        to_client: Vec<u8>,
        to_server: Vec<u8>,
        connected: bool,
    }

    #[async_trait]
    impl ProxyHandler for EchoHandler {
        fn server_addr(&self) -> SocketAddr { self.info.dst }
        fn session_info(&self) -> SessionInfo { self.info.clone() }
        async fn push_data(&mut self, source: IncomingSource, data: &[u8]) -> io::Result<()> {
            match source {
                IncomingSource::Client => self.to_server.extend_from_slice(data),
                IncomingSource::Server => self.to_client.extend_from_slice(data),
            }
            Ok(())
        }
        fn consume_data(&mut self, direction: OutgoingDirection, size: usize) {
            let buf = match direction {
                OutgoingDirection::ToClient => &mut self.to_client,
                OutgoingDirection::ToServer => &mut self.to_server,
            };
            let take = size.min(buf.len());
            buf.drain(..take);
        }
        fn peek_data(&mut self, direction: OutgoingDirection) -> OutgoingDataEvent<'_> {
            let buf = match direction {
                OutgoingDirection::ToClient => &self.to_client[..],
                OutgoingDirection::ToServer => &self.to_server[..],
            };
            OutgoingDataEvent { direction, bytes: buf }
        }
        fn connection_established(&self) -> bool { self.connected }
    }

    #[tokio::test]
    async fn echo_handler_pushes_and_drains() {
        let info = SessionInfo {
            src: "127.0.0.1:5555".parse().unwrap(),
            dst: "127.0.0.1:9050".parse().unwrap(),
            proto: "socks5",
        };
        let mut h = EchoHandler { info: info.clone(), to_client: Vec::new(), to_server: Vec::new(), connected: true };
        h.push_data(IncomingSource::Client, b"hello").await.unwrap();
        let ev = h.peek_data(OutgoingDirection::ToServer);
        assert_eq!(ev.bytes, b"hello");
        h.consume_data(OutgoingDirection::ToServer, 5);
        let ev2 = h.peek_data(OutgoingDirection::ToServer);
        assert!(ev2.bytes.is_empty());
        assert_eq!(h.session_info().proto, "socks5");
    }
}
