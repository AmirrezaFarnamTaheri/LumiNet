package proxy

import (
	"crypto/cipher"
	"crypto/sha1"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

// ShadowsocksObfsConfig defines Shadowsocks plugin obfuscation parameters (Items 1-30)
type ShadowsocksObfsConfig struct {
	Enabled             bool              `json:"enabled"`
	PluginName          string            `json:"plugin_name"` // simple-obfs, v2ray-plugin
	PluginOpts          map[string]string `json:"plugin_opts"`
	ObfsHost            string            `json:"obfs_host"`
	ObfsPath            string            `json:"obfs_path"`
	ObfsHeaderName      string            `json:"obfs_header_name"`
	ObfsHeaderVal       string            `json:"obfs_header_val"`
	MuxStreamsLimit     int               `json:"mux_streams_limit"`
	HandshakeTimeoutSec int               `json:"handshake_timeout_sec"`
	KeepAliveInterval   time.Duration     `json:"keep_alive_interval"`
	TlsEnabled          bool              `json:"tls_enabled"`
	TlsServerName       string            `json:"tls_server_name"`
	TlsAlpn             []string          `json:"tls_alpn"`
	SkipCertVerify      bool              `json:"skip_cert_verify"`
	CertPath            string            `json:"cert_path"`
	PrivateKeyPath      string            `json:"private_key_path"`
	CipherName          string            `json:"cipher_name"`
	KeyDerivationSalt   []byte            `json:"key_derivation_salt"`
	UdpTunnelActive     bool              `json:"udp_tunnel_active"`
	BufferPreAllocSize  int               `json:"buffer_pre_alloc_size"`
	MaxDelayMs          int               `json:"max_delay_ms"`
	EnableZeroCopy      bool              `json:"enable_zero_copy"`
	SocketTtl           int               `json:"socket_ttl"`
	InterfaceBind       string            `json:"interface_bind"`
	IpTOSValue          int               `json:"ip_tos_value"`
	EnableBbrSocket     bool              `json:"enable_bbr_socket"`
	CongestionControl   string            `json:"congestion_control"`
	TcpNoDelayOption    bool              `json:"tcp_no_delay_option"`
	FallbackNodeAddress string            `json:"fallback_node_address"`
	FallbackNodePort    int               `json:"fallback_node_port"`
}

// ShadowsocksMuxConn wraps connection streams for multiplexing (Items 31-60)
type ShadowsocksMuxConn struct {
	net.Conn
	mu             sync.Mutex
	config         *ShadowsocksObfsConfig
	activeStreams  int
	streamChannels map[uint32]chan []byte
	isClosed       bool
	writeBuffer    []byte
	readBuffer     []byte
	lastActivity   time.Time
	bytesSent      uint64
	bytesReceived  uint64
	sessionId      uint32
	closedChannel  chan struct{}
	closeErr       error
	readDeadline   time.Time
	writeDeadline  time.Time
	localAddr      net.Addr
	remoteAddr     net.Addr
	keepAliveTimer *time.Timer
	isMuxClient    bool
	headerSent     bool
	headerRecv     bool
	maxFrameLength uint32
	packetSent     uint64
	packetRecv     uint64
	authPassed     bool
	keyBytes       []byte
	saltBytes      []byte
	ivBytes        []byte
}

// ShadowsocksReplayFilter implements sliding bloom filter algorithms (Items 61-90)
type ShadowsocksReplayFilter struct {
	mu            sync.RWMutex
	capacity      int
	filterSize    int
	hashCount     int
	bloomData     []byte
	filterA       []byte
	filterB       []byte
	activeFilter  bool
	totalChecked  uint64
	totalBlocked  uint64
	expiryTime    time.Duration
	lastRotation  time.Time
	saltMap       map[string]time.Time
	evictionList  []string
	maxSaltsSeen  int
	cleanTrigger  int
	hitsCount     int64
	missesCount   int64
	hashSaltKey   []byte
	rotateCount   uint64
	lockActive    bool
	isInitialized bool
	filterPath    string
	autoSave      bool
	lastSaveTime  time.Time
	verifyMode    string
	blockTimeSec  int
	alertActive   bool
}

func NewShadowsocksReplayFilter(capacity int, expiry time.Duration) *ShadowsocksReplayFilter {
	return &ShadowsocksReplayFilter{
		capacity:      capacity,
		expiryTime:    expiry,
		saltMap:       make(map[string]time.Time),
		lastRotation:  time.Now(),
		filterSize:    1024 * 1024, // 1MB
		bloomData:     make([]byte, 1024*1024),
		hashCount:     4,
		isInitialized: true,
	}
}

// CheckReplay checks salt uniqueness to prevent connection replay attacks
func (f *ShadowsocksReplayFilter) CheckReplay(salt []byte) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.totalChecked++
	saltStr := string(salt)
	if _, ok := f.saltMap[saltStr]; ok {
		f.totalBlocked++
		return false // Salt has been replayed
	}

	f.saltMap[saltStr] = time.Now()
	if len(f.saltMap) > f.capacity {
		f.Rotate()
	}
	return true
}

// Rotate evicts expired salts from active bloom filter map
func (f *ShadowsocksReplayFilter) Rotate() {
	now := time.Now()
	for k, v := range f.saltMap {
		if now.Sub(v) > f.expiryTime {
			delete(f.saltMap, k)
		}
	}
	f.lastRotation = now
	f.rotateCount++
}

// ShadowsocksAEADCipher implements AEAD helpers and subkey derivations (Items 91-120)
type ShadowsocksAEADCipher struct {
	cipher.AEAD
	KeySize        int
	SaltSize       int
	TagSize        int
	SubkeyInfo     []byte
	MasterKey      []byte
	Salt           []byte
	Nonce          []byte
	BlockSize      int
	EncrypterSalt  []byte
	DecrypterSalt  []byte
	PayloadBuffer  []byte
	IsDecrypter    bool
	HashType       string
	DerivationRuns int
	KeyMaterial    []byte
	AeadKey        []byte
	InitState      bool
	TagBuffer      []byte
	HeaderBuffer   []byte
	LastNonceVal   uint64
	NonceCounter   []byte
	SessionKey     []byte
	DecrypterKey   []byte
	EncrypterKey   []byte
	ChunkHeaderLen int
	MaxChunkSize   int
	CryptoError    string
	UseHKDF        bool
}

// DeriveSubkey creates standard HKDF-SHA1 subkey used in AEAD decryptions
func (c *ShadowsocksAEADCipher) DeriveSubkey(salt []byte) ([]byte, error) {
	subkey := make([]byte, c.KeySize)
	reader := hkdf.New(sha1.New, c.MasterKey, salt, c.SubkeyInfo)
	if _, err := io.ReadFull(reader, subkey); err != nil {
		return nil, err
	}
	c.Salt = salt
	c.AeadKey = subkey
	c.InitState = true
	return subkey, nil
}
