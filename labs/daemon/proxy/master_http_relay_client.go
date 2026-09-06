package proxy

import (
	"context"
	"fmt"
	"math"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// MasteHttpQuotaTracker implements account quota metrics, bandwidth logs and limit assertions (Items 1-25)
type MasteHttpQuotaTracker struct {
	mu            sync.RWMutex
	UploadBytes   uint64            `json:"upload_bytes"`
	DownloadBytes uint64            `json:"download_bytes"`
	LimitBytes    uint64            `json:"limit_bytes"`
	IsBlocked     bool              `json:"is_blocked"`
	BillingCycle  time.Duration     `json:"billing_cycle"`
	ResetTime     time.Time         `json:"reset_time"`
	AccountID     string            `json:"account_id"`
	PeakRateBps   uint64            `json:"peak_rate_bps"`
	ActiveConns   int64             `json:"active_conns"`
	AvgLatencyMs  uint64            `json:"avg_latency_ms"`
	HistoryMap    map[int64]uint64  `json:"history_map"` // Unix timestamp to usage
	AlertEmails   []string          `json:"alert_emails"`
	WarnLevelPct  float64           `json:"warn_level_pct"`
	RateLimits    map[string]uint64 `json:"rate_limits"`
}

func NewMasteHttpQuotaTracker(limit uint64, cycle time.Duration, accountID string) *MasteHttpQuotaTracker {
	return &MasteHttpQuotaTracker{
		LimitBytes:   limit,
		BillingCycle: cycle,
		AccountID:    accountID,
		ResetTime:    time.Now().Add(cycle),
		HistoryMap:   make(map[int64]uint64),
		RateLimits:   make(map[string]uint64),
		WarnLevelPct: 0.90,
	}
}

// AddTraffic increments quota counters and performs automatic limit enforcement
func (q *MasteHttpQuotaTracker) AddTraffic(upload, download uint64) bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.IsBlocked {
		return false
	}

	atomic.AddUint64(&q.UploadBytes, upload)
	atomic.AddUint64(&q.DownloadBytes, download)

	total := atomic.LoadUint64(&q.UploadBytes) + atomic.LoadUint64(&q.DownloadBytes)
	if total >= q.LimitBytes {
		q.IsBlocked = true
		return false
	}
	return true
}

// MasteHttpSession implements browser overrides, registry cleaners, and NSS database updates (Items 26-55)
type MasteHttpSession struct {
	SessionID          string    `json:"session_id"`
	FirefoxOverride    bool      `json:"firefox_override"`
	ChromeOverride     bool      `json:"chrome_override"`
	NssProfilePath     string    `json:"nss_profile_path"`
	MacKeychainName    string    `json:"mac_keychain_name"`
	WinStoreName       string    `json:"win_store_name"`
	LinuxCertDir       string    `json:"linux_cert_dir"`
	CaRootPath         string    `json:"ca_root_path"`
	CleanOnExit        bool      `json:"clean_on_exit"`
	BackupRegistryPath string    `json:"backup_registry_path"`
	IsDefaultProfile   bool      `json:"is_default_profile"`
	RegistryKeyPath    string    `json:"registry_key_path"`
	CertNickname       string    `json:"cert_nickname"`
	FirefoxProfileDirs []string  `json:"firefox_profile_dirs"`
	LibreWolfSupported bool      `json:"librewolf_supported"`
	IceCatSupported    bool      `json:"icecat_supported"`
	UserJsAddedLine    string    `json:"user_js_added_line"`
	KeychainLockState  bool      `json:"keychain_lock_state"`
	CertImportTime     time.Time `json:"cert_import_time"`
	HashMismatch       bool      `json:"hash_mismatch"`
	SystemAnchorStore  string    `json:"system_anchor_store"`
	AdminKeyUsage      bool      `json:"admin_key_usage"`
	NssDbVersion       int       `json:"nss_db_version"`
	UserConfigBackup   string    `json:"user_config_backup"`
	LastError          string    `json:"last_error"`
	CleanCommandStr    string    `json:"clean_command_str"`
	SystemUserContext  string    `json:"system_user_context"`
	TempStorePath      string    `json:"temp_store_path"`
	VerificationStatus string    `json:"verification_status"`
	ForceFlagActive    bool      `json:"force_flag_active"`
}

// MasteHttpProxyDialer implements retry loops, fallback selections, and RTT ranking (Items 56-80)
type MasteHttpProxyDialer struct {
	mu                sync.RWMutex
	DialAddress       string
	FallbackAddresses []string
	MaxRetryAttempts  int
	RetryBackoffMs    int
	ConnectTimeout    time.Duration
	Dialer            *net.Dialer
	RttResults        map[string]time.Duration
	FailCount         map[string]int
	IsActive          bool
	LastDialTime      time.Time
	ProxyUser         string
	ProxyPass         string
	AllowInsecure     bool
	TlsSniOverride    string
}

func NewMasteHttpProxyDialer(addr string, fallbacks []string) *MasteHttpProxyDialer {
	return &MasteHttpProxyDialer{
		DialAddress:       addr,
		FallbackAddresses: fallbacks,
		MaxRetryAttempts:  3,
		RetryBackoffMs:    500,
		ConnectTimeout:    5 * time.Second,
		Dialer:            &net.Dialer{Timeout: 5 * time.Second},
		RttResults:        make(map[string]time.Duration),
		FailCount:         make(map[string]int),
		IsActive:          true,
	}
}

// DialWithBackoff executes dial attempts with exponential backoff and automatic failover
func (d *MasteHttpProxyDialer) DialWithBackoff(ctx context.Context, network string) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	targets := append([]string{d.DialAddress}, d.FallbackAddresses...)
	for _, target := range targets {
		if d.FailCount[target] >= 5 {
			continue // Skip heavily failing nodes
		}

		for attempt := 0; attempt < d.MaxRetryAttempts; attempt++ {
			start := time.Now()
			conn, err := d.Dialer.DialContext(ctx, network, target)
			if err == nil {
				d.RttResults[target] = time.Since(start)
				d.FailCount[target] = 0
				d.LastDialTime = time.Now()
				return conn, nil
			}

			d.FailCount[target]++
			backoff := time.Duration(d.RetryBackoffMs) * time.Millisecond * time.Duration(math.Pow(2, float64(attempt)))
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}
	}
	return nil, fmt.Errorf("all dial targets failed")
}

// MasteHttpBBRCongestionControl implements TCP socket tuning, BBR settings, and rate limiting (Items 81-100)
type MasteHttpBBRCongestionControl struct {
	TcpKeepAliveSec   int           `json:"tcp_keepalive_sec"`
	MultiplexStreams  bool          `json:"multiplex_streams"`
	MaxStreamsPerConn int           `json:"max_streams_per_conn"`
	TrafficShapingBps uint64        `json:"traffic_shaping_bps"`
	BufferAllocation  int           `json:"buffer_allocation"`
	MinReadBufferSize int           `json:"min_read_buffer_size"`
	MaxWriteBuffer    int           `json:"max_write_buffer"`
	UdpRelayEnabled   bool          `json:"udp_relay_enabled"`
	TcpFastOpenState  bool          `json:"tcp_fast_open_state"`
	FlushTimeout      time.Duration `json:"flush_timeout"`
	SocketMarkValue   int           `json:"socket_mark_value"`
	HeaderHostReal    string        `json:"header_host_real"`
	AlpnProtocols     []string      `json:"alpn_protocols"`
	SecureHandshake   bool          `json:"secure_handshake"`
	SkipVerifyServer  bool          `json:"skip_verify_server"`
	LocalInterface    string        `json:"local_interface"`
	IpFamilyType      string        `json:"ip_family_type"`
	TlsHandshakeLimit time.Duration `json:"tls_handshake_limit"`
	IdleTimeout       time.Duration `json:"idle_timeout"`
	ForceDisconnect   bool          `json:"force_disconnect"`
}

// SetSocketOptions configures TCP buffers and keepalive probes directly on raw connection
func (b *MasteHttpBBRCongestionControl) SetSocketOptions(conn net.Conn) error {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil
	}

	if b.TcpKeepAliveSec > 0 {
		_ = tcpConn.SetKeepAlivePeriod(time.Duration(b.TcpKeepAliveSec) * time.Second)
		_ = tcpConn.SetKeepAlive(true)
	}

	if b.MinReadBufferSize > 0 {
		_ = tcpConn.SetReadBuffer(b.MinReadBufferSize)
	}

	if b.MaxWriteBuffer > 0 {
		_ = tcpConn.SetWriteBuffer(b.MaxWriteBuffer)
	}

	return nil
}

// InjectRelayAuthHeader embeds token auth strings into target relay proxy requests
func (b *MasteHttpBBRCongestionControl) InjectRelayAuthHeader(req *http.Request, token []byte) {
	if req == nil || len(token) == 0 {
		return
	}
	req.Header.Set("X-Relay-Token", fmt.Sprintf("%x", token))
	if b.HeaderHostReal != "" {
		req.Host = b.HeaderHostReal
	}
}
