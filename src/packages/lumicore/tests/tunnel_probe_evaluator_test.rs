use lumicore::scanner::tunnel_probe_evaluator::{
    AttemptMetric, DnsProbeResult, HttpProbe, HttpProbeResult, ProbeMetrics, QuicProbeResult,
    ScoreResult, TcpProbeResult, TlsProbeResult, TunnelProbeEvaluator, TunnelScanReport,
    UdpProbeResult, WsProbeResult,
};

#[test]
fn test_compute_metrics_jitter_and_stability() {
    let tcp = TcpProbeResult {
        success: true,
        attempts: vec![
            AttemptMetric::ok(50),
            AttemptMetric::ok(70),
            AttemptMetric::ok(90),
        ],
        median_rtt_ms: 70,
        consistency: 1.0,
        error_category: None,
    };
    let udp = UdpProbeResult {
        reachable: true,
        attempts: vec![AttemptMetric::ok(60)],
        error_category: None,
    };
    let dns = DnsProbeResult {
        udp_responsive: true,
        tcp_responsive: true,
        answers: vec!["1.1.1.1".to_string()],
        attempts: vec![AttemptMetric::ok(80)],
        error_category: None,
    };

    let metrics = TunnelProbeEvaluator::compute_metrics(&tcp, &udp, &dns);
    assert_eq!(metrics.rtt_ms, 70);
    // 5 successful attempts: 50, 70, 90, 60, 80. Mean = 70.0.
    // Variances: (50-70)^2=400, (70-70)^2=0, (90-70)^2=400, (60-70)^2=100, (80-70)^2=100.
    // Sum = 1000 / 5 = 200. sqrt(200) ~= 14.14 -> 14.
    assert_eq!(metrics.jitter_ms, 14);
    assert_eq!(metrics.packet_loss_estimate, 0.0);
    assert_eq!(metrics.stability_percent, 100.0);
    assert_eq!(metrics.timeout_frequency, 0.0);
}

#[test]
fn test_score_probe_tunnel_ready() {
    let tcp = TcpProbeResult {
        success: true,
        attempts: vec![AttemptMetric::ok(40), AttemptMetric::ok(45)],
        median_rtt_ms: 42,
        consistency: 1.0,
        error_category: None,
    };
    let tls = TlsProbeResult {
        success: true,
        handshake_ms: 80,
        version: Some("TLS 1.3".to_string()),
        cipher_suite: Some("TLS_AES_128_GCM_SHA256".to_string()),
        alpn: Some("h2".to_string()),
        verified: true,
        error_category: None,
    };
    let http = HttpProbeResult {
        success: true,
        probes: vec![HttpProbe {
            method: "GET".to_string(),
            url: "https://example.com/".to_string(),
            status_code: 200,
            duration_ms: 60,
            redirected: false,
            error_category: None,
        }],
    };
    let ws = WsProbeResult {
        success: true,
        status_code: 101,
        duration_ms: 70,
        error_category: None,
    };
    let quic = QuicProbeResult {
        success: true,
        handshake_ms: 65,
        alpn: Some("h3".to_string()),
        error_category: None,
    };
    let dns = DnsProbeResult {
        udp_responsive: true,
        tcp_responsive: true,
        answers: vec!["1.1.1.1".to_string()],
        attempts: vec![AttemptMetric::ok(30)],
        error_category: None,
    };
    let metrics = ProbeMetrics {
        rtt_ms: 42,
        jitter_ms: 10,
        packet_loss_estimate: 0.0,
        stability_percent: 98.0,
        timeout_frequency: 0.0,
    };

    let score = TunnelProbeEvaluator::score_probe(
        &tcp, &tls, &http, &ws, &quic, &dns, &metrics,
    );

    assert_eq!(score.classification, "Tunnel Ready");
    assert_eq!(score.grade, "A+");
    assert!(!score.false_positive);
    assert!(score.numeric >= 94);
    assert!(score.confidence > 90.0);
}

#[test]
fn test_middlebox_spoofing_false_positive_detection() {
    // Middlebox returns TCP SYN-ACK, but drops/resets all actual application payload
    let tcp = TcpProbeResult {
        success: true,
        attempts: vec![AttemptMetric::ok(20), AttemptMetric::ok(22), AttemptMetric::ok(21)],
        median_rtt_ms: 21,
        consistency: 1.0,
        error_category: None,
    };
    let tls = TlsProbeResult { success: false, ..Default::default() };
    let http = HttpProbeResult { success: false, probes: vec![] };
    let ws = WsProbeResult { success: false, ..Default::default() };
    let quic = QuicProbeResult { success: false, ..Default::default() };
    let dns = DnsProbeResult { udp_responsive: false, tcp_responsive: false, ..Default::default() };

    let metrics = ProbeMetrics {
        rtt_ms: 21,
        jitter_ms: 1,
        packet_loss_estimate: 0.0,
        stability_percent: 100.0,
        timeout_frequency: 0.0,
    };

    let score = TunnelProbeEvaluator::score_probe(
        &tcp, &tls, &http, &ws, &quic, &dns, &metrics,
    );

    assert!(score.false_positive);
    assert_eq!(score.classification, "False Positive");
}

#[test]
fn test_low_consistency_false_positive() {
    // Inconsistent TCP (consistency < 0.67) indicates erratic RST/ACK injection
    let tcp = TcpProbeResult {
        success: true,
        attempts: vec![
            AttemptMetric::ok(30),
            AttemptMetric::fail(1000, "timeout"),
            AttemptMetric::fail(1000, "connection_refused"),
        ],
        median_rtt_ms: 30,
        consistency: 0.33,
        error_category: None,
    };
    let tls = TlsProbeResult { success: true, ..Default::default() };
    let http = HttpProbeResult::default();
    let ws = WsProbeResult::default();
    let quic = QuicProbeResult::default();
    let dns = DnsProbeResult::default();
    let metrics = ProbeMetrics::default();

    let score = TunnelProbeEvaluator::score_probe(
        &tcp, &tls, &http, &ws, &quic, &dns, &metrics,
    );

    assert!(score.false_positive);
    assert_eq!(score.classification, "False Positive");
}

#[test]
fn test_cloudflare_trace_parsing() {
    let trace_raw = "fl=123f45\nh=www.cloudflare.com\nip=198.51.100.42\nts=1690000000\nvisit_scheme=https\nuag=WhiteDNS-Desktop\ncolo=FRA\nsliver=none\nhttp=http/2\nloc=de\ntls=TLSv1.3\nsni=plaintext\nwarp=off\ngateway=off\nrbi=off\nkex=X25519\n";

    let (ip, loc) = TunnelProbeEvaluator::parse_cloudflare_trace(trace_raw);
    assert_eq!(ip, Some("198.51.100.42".to_string()));
    assert_eq!(loc, Some("DE".to_string()));
}

#[test]
fn test_report_evaluation() {
    let mut report = TunnelScanReport {
        endpoint: "1.1.1.1:443".to_string(),
        host: "1.1.1.1".to_string(),
        port: 443,
        tcp: TcpProbeResult {
            success: true,
            attempts: vec![AttemptMetric::ok(50)],
            median_rtt_ms: 50,
            consistency: 1.0,
            error_category: None,
        },
        tls: TlsProbeResult {
            success: true,
            handshake_ms: 80,
            ..Default::default()
        },
        http: HttpProbeResult { success: true, probes: vec![] },
        websocket: WsProbeResult { success: true, ..Default::default() },
        udp: UdpProbeResult::default(),
        quic: QuicProbeResult::default(),
        dns: DnsProbeResult::default(),
        metrics: ProbeMetrics::default(),
        score: None,
    };

    TunnelProbeEvaluator::evaluate_report(&mut report);
    assert!(report.score.is_some());
    let score = report.score.unwrap();
    assert!(!score.false_positive);
    assert!(score.numeric > 50);
}
