package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"
)

// MitmDecryptionConfig defines the inbound configuration parameters for MITM Decryption (Items 1-25)
type MitmDecryptionConfig struct {
	TlsDecryptH11Port    int    `json:"tls_decrypt_h11_port"`
	TlsDecryptH2Port     int    `json:"tls_decrypt_h2_port"`
	ListenAddress        string `json:"listen_address"`
	CertificateDir       string `json:"certificate_dir"`
	PrivateKeyDir        string `json:"private_key_dir"`
	AutoGenerateCerts    bool   `json:"auto_generate_certs"`
	ValidityDays         int    `json:"validity_days"`
	Organization         string `json:"organization"`
	OrganizationalUnit   string `json:"organizational_unit"`
	Country              string `json:"country"`
	State                string `json:"state"`
	Locality             string `json:"locality"`
	CaPassphrase         string `json:"ca_passphrase"`
	SniffDomains         bool   `json:"sniff_domains"`
	SniffOverride        bool   `json:"sniff_override"`
	AlpnFromMitm         string `json:"alpn_from_mitm"` // Normally "fromMitM"
	FallbackPort         int    `json:"fallback_port"`
	MaxHeaderSize        int    `json:"max_header_size"`
	EnableBbr            bool   `json:"enable_bbr"`
	TcpNoDelay           bool   `json:"tcp_no_delay"`
	SoLinger             int    `json:"so_linger"`
	SoSndBuf             int    `json:"so_sndbuf"`
	SoRcvBuf             int    `json:"so_rcvbuf"`
	SoKeepAlive          bool   `json:"so_keepalive"`
	KeepAliveIntervalSec int    `json:"keepalive_interval_sec"`
}

// DomainFrontingRepackerConfig defines the outbound TLS repacking configuration options (Items 26-55)
type DomainFrontingRepackerConfig struct {
	CdnEndpointIp     string            `json:"cdn_endpoint_ip"`
	CdnEndpointPort   int               `json:"cdn_endpoint_port"`
	FakeSniHost       string            `json:"fake_sni_host"`
	RealHost          string            `json:"real_host"`
	Alpn              []string          `json:"alpn"`
	Fingerprint       string            `json:"fingerprint"`
	AllowInsecure     bool              `json:"allow_insecure"`
	ServerName        string            `json:"server_name"`
	HeaderHost        string            `json:"header_host"`
	Path              string            `json:"path"`
	RepackMode        string            `json:"repack_mode"` // ws, grpc, h2, tcp
	GrpcService       string            `json:"grpc_service"`
	WsEarlyData       bool              `json:"ws_early_data"`
	HttpHeaders       map[string]string `json:"http_headers"`
	TcpFastOpen       bool              `json:"tcp_fast_open"`
	CongestionAlgo    string            `json:"congestion_algo"`
	SockoptMark       int               `json:"sockopt_mark"`
	ProxyProtocol     bool              `json:"proxy_protocol"`
	ProxyVersion      int               `json:"proxy_version"`
	DialAddress       string            `json:"dial_address"`
	MaxRetryAttempts  int               `json:"max_retry_attempts"`
	RetryBackoffMs    int               `json:"retry_backoff_ms"`
	MultiplexEnabled  bool              `json:"multiplex_enabled"`
	MuxConcurrency    int               `json:"mux_concurrency"`
	MuxIdleTimeout    time.Duration     `json:"mux_idle_timeout"`
	V2rayConfigFile   string            `json:"v2ray_config_file"`
	SingboxConfigFile string            `json:"singbox_config_file"`
	XrayConfigFile    string            `json:"xray_config_file"`
	OutboundTag       string            `json:"outbound_tag"`
	InboundTag        string            `json:"inbound_tag"`
}

// MitmRepackHandler drives the cert verification and Dynamic SAN generation (Items 56-80)
type MitmRepackHandler struct {
	Config   *MitmDecryptionConfig
	CACert   *x509.Certificate
	CAPriv   *ecdsa.PrivateKey
	CertMap  map[string]*tls.Certificate
	dnsNames []string
	ipAddrs  []net.IP
}

// NewMitmRepackHandler creates an active MITM cert generation handler.
func NewMitmRepackHandler(config *MitmDecryptionConfig, caCertPEM, caKeyPEM []byte) (*MitmRepackHandler, error) {
	if config == nil {
		return nil, errors.New("nil mitm configuration")
	}

	block, _ := pem.Decode(caCertPEM)
	if block == nil {
		return nil, errors.New("failed to parse CA certificate PEM")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA cert: %w", err)
	}

	keyBlock, _ := pem.Decode(caKeyPEM)
	if keyBlock == nil {
		return nil, errors.New("failed to parse CA private key PEM")
	}
	caKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		// Fallback to general PKCS8 or PKCS1 if needed
		parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CA private key: %w", err)
		}
		var ok bool
		caKey, ok = parsedKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("CA private key must be ECDSA")
		}
	}

	return &MitmRepackHandler{
		Config:   config,
		CACert:   caCert,
		CAPriv:   caKey,
		CertMap:  make(map[string]*tls.Certificate),
		dnsNames: make([]string, 0),
		ipAddrs:  make([]net.IP, 0),
	}, nil
}

// GenerateDynamicCert generates dynamic domain-level TLS certs (Items 71-77)
func (m *MitmRepackHandler) GenerateDynamicCert(domain string) (*tls.Certificate, error) {
	if cert, ok := m.CertMap[domain]; ok {
		return cert, nil
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	validityDays := m.Config.ValidityDays
	if validityDays <= 0 {
		validityDays = 365
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         domain,
			Organization:       []string{m.Config.Organization},
			OrganizationalUnit: []string{m.Config.OrganizationalUnit},
			Country:            []string{m.Config.Country},
			Province:           []string{m.Config.State},
			Locality:           []string{m.Config.Locality},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().AddDate(0, 0, validityDays),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	if ip := net.ParseIP(domain); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, domain)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, m.CACert, &priv.PublicKey, m.CAPriv)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	m.CertMap[domain] = &tlsCert
	return &tlsCert, nil
}

// MuxRepackDialer handles dial outbounds, SNI modifications, and custom headers injection (Items 81-100)
type MuxRepackDialer struct {
	Config *DomainFrontingRepackerConfig
}

// NewMuxRepackDialer creates a new MuxRepackDialer.
func NewMuxRepackDialer(config *DomainFrontingRepackerConfig) *MuxRepackDialer {
	return &MuxRepackDialer{Config: config}
}

// DialOutbound connects to CDN edge IP, repacks SNI, and sends configured headers
func (m *MuxRepackDialer) DialOutbound(ctx context.Context, network string) (net.Conn, error) {
	targetAddr := net.JoinHostPort(m.Config.CdnEndpointIp, fmt.Sprintf("%d", m.Config.CdnEndpointPort))
	if m.Config.DialAddress != "" {
		targetAddr = m.Config.DialAddress
	}

	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	rawConn, err := dialer.DialContext(ctx, network, targetAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial CDN edge IP: %w", err)
	}

	// Apply socket options
	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetKeepAlive(true)
	}

	tlsConfig := &tls.Config{
		ServerName:         m.Config.FakeSniHost,
		InsecureSkipVerify: m.Config.AllowInsecure,
		NextProtos:         m.Config.Alpn,
	}

	if m.Config.ServerName != "" {
		tlsConfig.ServerName = m.Config.ServerName
	}

	tlsConn := tls.Client(rawConn, tlsConfig)
	err = tlsConn.HandshakeContext(ctx)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	return tlsConn, nil
}

// InjectHeaders creates an HTTP request block containing configured real hosts and header mappings
func (m *MuxRepackDialer) InjectHeaders(req *http.Request) {
	if req == nil {
		return
	}
	if m.Config.RealHost != "" {
		req.Host = m.Config.RealHost
		req.Header.Set("Host", m.Config.RealHost)
	}
	if m.Config.HeaderHost != "" {
		req.Header.Set("X-Forwarded-Host", m.Config.HeaderHost)
	}
	for k, v := range m.Config.HttpHeaders {
		req.Header.Set(k, v)
	}
	if m.Config.Fingerprint != "" {
		req.Header.Set("User-Agent", fmt.Sprintf("Mozilla/5.0 (Windows NT 10.0; Win64; x64) %s", strings.Title(m.Config.Fingerprint)))
	}
}
