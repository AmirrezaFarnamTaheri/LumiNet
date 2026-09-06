//! # Transport Module
//!
//! Networking and protocol-specific transport overrides.
//! Includes ICMP covert tunnels, TUIC (QUIC),
//! eBPF redirectors, Exodus L3 virtual router, and port hoppers.

pub mod circuit_shift;
pub mod dns_tunnel;
pub mod domain_fronter;
pub mod ebpf_interceptor;
pub mod ebpf_redirector;
pub mod exodus;
pub mod fte_obfuscator;
pub mod http_steg;
pub mod http_tunnel;
pub mod icmp;
pub mod ip_packet;
pub mod overlay_vpn;
pub mod packet_composer;
pub mod covert_envelope;
pub mod covert_dead_drop;
pub mod dns_fragment_store;
pub mod multi_level_queue;
pub mod packed_control_block;
pub mod paqet_proto;
pub mod port_hopper;
pub mod proxy_server;
pub mod socks5_client;
pub mod slip_codec;
pub mod steg_transport;
pub mod stegotorus_http;
pub mod tls_override;
pub mod masque_capsule;
pub mod tor_cells;
pub mod tor_crypto;
pub mod tor_kdf;
pub mod tuic_quic;
pub mod tunnel_client;
pub mod virtual_dns;
pub mod wasm_transport;

pub use circuit_shift::*;
pub use dns_tunnel::{
    base32_decode, base32_encode, DNSTunnel, DnsTunnelConfig, DnsTunnelError, DnsTunnelPreset,
    DNS_CLASS_IN, DNS_TYPE_A, DNS_TYPE_NULL, DNS_TYPE_TXT, MAX_DNS_LABEL_LEN, MAX_DNS_NAME_LEN,
};
pub use ebpf_interceptor::EBPFInterceptor;
pub use ebpf_redirector::EbpfRedirector;
pub use exodus::ExodusTransport;
pub use fte_obfuscator::FteObfuscator;
pub use http_steg::{HttpStegConfig, HttpStegSession, PayloadCorpus, StaticCorpus};
pub use http_tunnel::HTTPTunnel;
pub use icmp::ICMPTunnel;
pub use ip_packet::{IpPacket, IpProto, Ipv4Header, Ipv6Header};
pub use masque_capsule::{
    build_dns_probe_packet, decode_ip_datagram, decode_varint, encode_address_request,
    encode_capsule, encode_datagram_capsule, encode_ip_datagram, encode_varint,
    looks_like_ip_packet, strip_datagram_context, varint_len, AssignedAddress, Capsule,
    CapsuleParser, MasqueError, RouteAdvertisement, CAPSULE_ADDRESS_ASSIGN,
    CAPSULE_ADDRESS_REQUEST, CAPSULE_DATAGRAM, CAPSULE_ROUTE_ADVERTISEMENT,
    CONNECT_IP_CONTEXT_ID,
};
pub use overlay_vpn::OverlayVPN;
pub use packet_composer::PacketComposer;
pub use port_hopper::PortHopper;
pub use socks5_client::{Socks5Client, Socks5Error};
pub use steg_transport::{StegConfig, StegRegistry, StegSession};
pub use tls_override::TLSOverride;
pub use tor_cells::{CellCommand, FixedTorCell, FIXED_CELL_LEN};
pub use tuic_quic::TuicQuic;
pub use virtual_dns::VirtualDns;
pub use covert_dead_drop::{
    decode_sid_b32, encode_sid_b32, CovertCryptoError, CovertCryptoSession,
    CovertDeadDropFilename, CovertWireError, CovertWireFrame, Direction as DeadDropDirection,
    FilenameKind as DeadDropFilenameKind, FrameKind as DeadDropFrameKind, ReplayWindow,
    SessionId as DeadDropSessionId, HEADER_LEN as DEADDROP_HEADER_LEN,
    MAX_PAYLOAD as DEADDROP_MAX_PAYLOAD, WIRE_VERSION as DEADDROP_WIRE_VERSION,
};
pub use covert_envelope::*;
pub use dns_fragment_store::{CollectResult, DnsFragmentStore};
pub use multi_level_queue::MultiLevelQueue;
pub use packed_control_block::{
    pack_control_blocks, parse_packed_control_blocks, ControlBlock, PACKED_CONTROL_BLOCK_SIZE,
};



pub mod sni_fragmenter;
pub use sni_fragmenter::{FragmentSlice, SniFragmentConfig, SniFragmentPlan, SniFragmenter};

pub mod edge_relay_router;
pub use edge_relay_router::{
    EdgeCidr, EdgeRelayConfig, EdgeRelayRouter, EdgeRoutingDecision, RelayNetwork as EdgeRelayNetwork,
    RouteTarget as EdgeRouteTarget,
};

pub mod decoy_http_tunnel;
pub use decoy_http_tunnel::{
    DecoyAction, DecoyEnvelope, DecoyHttpCodec, DecoyHttpRequest, DecoyHttpResponse,
    DecoyTunnelConfig, DecoyTunnelError, DecoyTunnelSession, DECOY_DEFAULT_BUFFER_SIZE,
    DECOY_DEFAULT_PULL_TIMEOUT_MS, DECOY_DEFAULT_TIMEOUT_SEC,
};

pub mod raw_packet_codec;
pub use raw_packet_codec::{
    InternetChecksum, KcpTransportProfile, RawPacketCodec, RawPacketError, RawPacketHasher,
    RawPacketMessage, RawTcpFlags, TargetEndpoint, FLAG_ACK, FLAG_CWR, FLAG_ECE, FLAG_FIN,
    FLAG_NS, FLAG_PSH, FLAG_RST, FLAG_SYN, FLAG_URG, MSG_PING, MSG_PONG, MSG_TCP, MSG_TCPF,
    MSG_UDP, RAW_PACKET_MAGIC, RAW_PACKET_VERSION,
};

pub mod mixed_protocol_proxy;
pub use mixed_protocol_proxy::{
    detect_proxy_protocol, HttpProxyRequest, MixedProtocolCodec, MixedProxyError,
    ProxyDemuxRequest, ProxyProtocolKind, Socks4ReplyStatus, Socks4Request, Socks5Greeting,
    Socks5Request, SOCKS4_CMD_BIND, SOCKS4_CMD_CONNECT, SOCKS4_VERSION, SOCKS5_ATYP_DOMAIN,
    SOCKS5_ATYP_IPV4, SOCKS5_ATYP_IPV6, SOCKS5_AUTH_NO_ACCEPTABLE, SOCKS5_AUTH_NONE,
    SOCKS5_CMD_BIND, SOCKS5_CMD_CONNECT, SOCKS5_CMD_UDP_ASSOCIATE, SOCKS5_REP_ADDR_NOT_SUPPORTED,
    SOCKS5_REP_CMD_NOT_SUPPORTED, SOCKS5_REP_CONNECTION_NOT_ALLOWED, SOCKS5_REP_CONNECTION_REFUSED,
    SOCKS5_REP_GENERAL_FAILURE, SOCKS5_REP_HOST_UNREACHABLE, SOCKS5_REP_NETWORK_UNREACHABLE,
    SOCKS5_REP_SUCCESS, SOCKS5_REP_TTL_EXPIRED, SOCKS5_VERSION,
};

pub mod tls_session_obfuscator;
pub use tls_session_obfuscator::{
    EchCipher, EchConfig, EchConfigParser, ObfuscatedClientSessionState, TicketPadder,
    TlsObfuscatorError, TlsPassthroughDeflector, CANONICAL_PADDED_TICKET_SIZES,
};

pub mod tactical_tunnel_session;
pub use tactical_tunnel_session::{
    derive_obfuscation_key, StreamCipher as TacticalStreamCipher, TacticalSessionError,
    TacticalSessionObfuscator, TacticsEngine, TacticsFilter, TacticsProfile,
    OBFUSCATE_CLIENT_TO_SERVER_IV, OBFUSCATE_HASH_ITERATIONS, OBFUSCATE_KEY_LENGTH,
    OBFUSCATE_MAGIC_VALUE, OBFUSCATE_MAX_PADDING, OBFUSCATE_SEED_LENGTH,
    OBFUSCATE_SERVER_TO_CLIENT_IV, PREAMBLE_HEADER_LENGTH as TACTICAL_PREAMBLE_HEADER_LENGTH,
};

pub mod tun2socks_router;
pub use tun2socks_router::{
    FlowKey as Tun2SocksFlowKey, NatSession as Tun2SocksNatSession,
    TransportProto as Tun2SocksProto, Tun2SocksError, Tun2SocksRouter, UdpGwFrame,
    DEFAULT_IDLE_TIMEOUT_SECS, MAX_FRAME_SIZE as UDPGW_MAX_FRAME_SIZE,
    UDPGW_CLIENT_FLAG_DNS, UDPGW_CLIENT_FLAG_IPV6,
};

pub mod webrtc_datachannel;
pub use webrtc_datachannel::{
    DataChannelError, DataChannelFrame, CHANNEL_TYPE_PARTIAL_RELIABLE_REXMIT,
    CHANNEL_TYPE_PARTIAL_RELIABLE_REXMIT_UNORDERED, CHANNEL_TYPE_PARTIAL_RELIABLE_TIMED,
    CHANNEL_TYPE_PARTIAL_RELIABLE_TIMED_UNORDERED, CHANNEL_TYPE_RELIABLE,
    CHANNEL_TYPE_RELIABLE_UNORDERED, DCEP_MSG_ACK, DCEP_MSG_OPEN, PPID_BINARY, PPID_BINARY_EMPTY,
    PPID_DCEP, PPID_STRING, PPID_STRING_EMPTY,
};




pub mod brutal_pacer;
pub use brutal_pacer::{BrutalPacer, SalamanderObfuscator};

pub mod virtual_ethernet_switch;
pub use virtual_ethernet_switch::{NodeAddress, SwitchPacketFrame};

pub mod ssl_vpn_stream;
pub use ssl_vpn_stream::{NatTuple, SslVpnFrame, VirtualNatTable};

pub mod transparent_channel_mux;
pub use transparent_channel_mux::ChannelMuxFrame;


pub mod socket_pool_supervisor;

pub mod packet_fec_encoder;
pub mod tcp_rendezvous_bridge;
pub mod http2_serverless_carrier;
pub mod raw_packet_carrier;
pub mod ssl_vpn_virtual_adapter;

pub mod dual_backend_controller;
pub mod over_tls_stream;
pub mod adaptive_protocol_matrix;

pub mod multipath_udp_tunnel;
pub mod embedded_probe_server;
pub mod multipath_evasion_pipeline;
pub mod camouflage_stream_masquerader;
pub mod edge_cdn_pool_sorter;

pub mod ssrot_stream_obfuscator;
pub mod replay_resistant_tunnel;
pub mod quic_stream_multiplexer;
pub mod quic_connection_controller;
pub mod quic_packet_codec;
pub mod quic_evasion_tunnel_coordinator;

pub mod tls_session_tunnel_adapter;
pub mod reverse_tunnel_relay;
pub mod ppp_tls_tunnel_codec;
pub mod masque_datagram_tunnel;
pub mod masque_amnezia_hybrid_tunnel;

pub mod multiprotocol_traffic_inspector;
pub mod nat_traversal_tunnel;
