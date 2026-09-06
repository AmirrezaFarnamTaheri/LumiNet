//! Tor relay protocol layer.
//!
//! Link-layer handshake cells (CERTS, AUTH_CHALLENGE, NETINFO, VERSIONS),
//! multi-descriptor chunking with raw-SHA1 PKCS1v15 signature verification,
//! and WebSocket-bridged cell extensions. Plus TUIC v5 transport codec and
//! FPTN tls2 TLS-record-camouflaged framing.

pub mod acl_filter;
pub mod batch_frame_codec;
pub mod blob_queue_aead;
pub mod descriptor_parser;
pub mod dispersal;
pub mod link_cells;
pub mod exit_node_codec;
pub mod multi_core_supervisor;
pub mod quota_tracker;
pub mod range_parallel_streamer;
pub mod relay_stream_codec;
pub mod tls_obfuscator2;
pub mod transactional_session;
pub mod tuic_codec;
pub mod websocket_cells;

pub use acl_filter::*;
pub use batch_frame_codec::*;
pub use blob_queue_aead::*;
pub use exit_node_codec::*;
pub use multi_core_supervisor::*;
pub use range_parallel_streamer::*;
pub use transactional_session::*;


pub use dispersal::{
    DispersalError, DispersalReassembler, EdgeEndpoint, EdgeRunnerType, MicroDisperser, MicroFrame,
};

pub use descriptor_parser::{chunk_routers, verify_descriptor_signature, DescriptorError};
pub use link_cells::{
    AuthChallengeCell, CertEntry, CertsCell, LinkCellCommand, LinkCellError, NetInfoCell,
    VersionsCell,
};
pub use tls_obfuscator2::{
    DecodedFrame, SystemUnixTime, TlsObfuscator2, TlsObfuscator2Error, UnixTime,
    FPTN_TRAILER_LEN, HEADER_LEN, MAX_CONTENT_LENGTH, MAX_INPUT_BUFFER, MAX_PAYLOAD,
    PADDING_MAX, PADDING_MIN, RECORD_MAJOR, RECORD_MINOR, RECORD_TYPE, TIME_SHIFT_SECONDS,
};
pub use tuic_codec::{
    AuthChallengeFrame, AuthResponseFrame, ConnectFrame, DisconnectFrame, HeartbeatFrame,
    PingFrame, TuicCodec, TuicCodecError, TuicCommandKind, TuicFrame, UdpPacketFrame,
    TUIC_VERSION,
};
pub use websocket_cells::{WsCell, WsCellCommand, WsCellError};

pub mod identity_tunnel;
pub use identity_tunnel::{IdentityTunnelHeader, IDENTITY_TUNNEL_MAGIC, IDENTITY_TUNNEL_VERSION};

pub mod mesh_peer_route;
pub use mesh_peer_route::{MeshPeerTable, MeshRouteEntry, PeerLinkMetric};

pub mod zero_trust_route;

pub mod weighted_egress_router;
pub mod zero_copy_network_relay;
