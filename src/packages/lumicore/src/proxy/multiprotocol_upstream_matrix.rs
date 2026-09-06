//! Multi-Protocol Upstream Multiplex Matrix
//!
//! Evaluates and dispatches outbound proxy flows across disparate transport mechanisms
//! (gRPC, WebSocket, HTTPUpgrade, SplitHTTP) according to network censorship conditions.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    Grpc,
    WebSocket,
    HttpUpgrade,
    SplitHttp,
}

#[derive(Debug, Clone)]
pub struct UpstreamRoute {
    pub id: String,
    pub kind: TransportKind,
    pub target_endpoint: String,
    pub path_or_service: String,
    pub priority: u32,
    pub operational: bool,
}

#[derive(Debug, Default)]
pub struct MultiprotocolUpstreamMatrix {
    routes: Vec<UpstreamRoute>,
}

impl MultiprotocolUpstreamMatrix {
    pub fn new() -> Self {
        Self { routes: Vec::new() }
    }

    pub fn add_route(
        &mut self,
        id: &str,
        kind: TransportKind,
        target_endpoint: &str,
        path_or_service: &str,
        priority: u32,
    ) {
        self.routes.push(UpstreamRoute {
            id: id.to_string(),
            kind,
            target_endpoint: target_endpoint.to_string(),
            path_or_service: path_or_service.to_string(),
            priority,
            operational: true,
        });
    }

    pub fn set_operational(&mut self, id: &str, operational: bool) {
        if let Some(r) = self.routes.iter_mut().find(|r| r.id == id) {
            r.operational = operational;
        }
    }

    pub fn select_best_route(&self) -> Option<&UpstreamRoute> {
        self.routes
            .iter()
            .filter(|r| r.operational)
            .min_by_key(|r| r.priority)
    }

    pub fn select_by_kind(&self, kind: TransportKind) -> Option<&UpstreamRoute> {
        self.routes
            .iter()
            .filter(|r| r.operational && r.kind == kind)
            .min_by_key(|r| r.priority)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multiprotocol_upstream_matrix() {
        let mut matrix = MultiprotocolUpstreamMatrix::new();
        matrix.add_route("r-grpc", TransportKind::Grpc, "edge.com:443", "TunnelService", 10);
        matrix.add_route("r-ws", TransportKind::WebSocket, "edge.com:443", "/ws", 20);
        matrix.add_route("r-splithttp", TransportKind::SplitHttp, "edge.com:443", "/split", 5);

        let best = matrix.select_best_route().unwrap();
        assert_eq!(best.id, "r-splithttp");

        matrix.set_operational("r-splithttp", false);
        let fallback = matrix.select_best_route().unwrap();
        assert_eq!(fallback.id, "r-grpc");
    }
}
