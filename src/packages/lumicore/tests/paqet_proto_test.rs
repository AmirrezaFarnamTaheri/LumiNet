use lumicore::transport::paqet_proto::{
    PaqetAddress, PaqetMessage, PaqetProto, TcpFlags,
    PAQET_MAGIC, PAQET_VERSION, TYPE_PING, TYPE_TCP,
};

#[test]
fn test_paqet_ping_wire_format() {
    let wire = PaqetProto::encode(&PaqetMessage::Ping).expect("encode ping");
    assert_eq!(wire, vec![PAQET_MAGIC, PAQET_VERSION, TYPE_PING, 0x00, 0x00]);

    let (msg, consumed) = PaqetProto::decode(&wire).expect("decode ping");
    assert_eq!(consumed, 5);
    assert_eq!(msg, PaqetMessage::Ping);
}

#[test]
fn test_paqet_tcp_stream_initiation() {
    let addr = PaqetAddress {
        host: "tunnel.ingress.cloudflare.com".into(),
        port: 7844,
    };
    let wire = PaqetProto::encode(&PaqetMessage::Tcp(addr.clone())).expect("encode tcp");
    assert_eq!(wire[0], PAQET_MAGIC);
    assert_eq!(wire[1], PAQET_VERSION);
    assert_eq!(wire[2], TYPE_TCP);

    let (msg, consumed) = PaqetProto::decode(&wire).expect("decode tcp");
    assert_eq!(consumed, wire.len());
    assert_eq!(msg, PaqetMessage::Tcp(addr));
}

#[test]
fn test_paqet_evasion_tcp_flags() {
    let flags = vec![
        TcpFlags { syn: true, ..Default::default() },
        TcpFlags { rst: true, ack: true, ..Default::default() },
    ];
    let wire = PaqetProto::encode(&PaqetMessage::Tcpf(flags.clone())).expect("encode tcpf");

    let (msg, consumed) = PaqetProto::decode(&wire).expect("decode tcpf");
    assert_eq!(consumed, wire.len());
    assert_eq!(msg, PaqetMessage::Tcpf(flags));
}
