package proxy

import (
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/maybeknott/luminet/internal/networking/kcppolicy"
	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"golang.org/x/crypto/pbkdf2"
)

// deriveKCPKey derives a block crypt key from a password.
func deriveKCPKey(password string, keySize int) []byte {
	return pbkdf2.Key([]byte(password), []byte("kcp-go-salt"), 1024, keySize, sha1.New)
}

// createKCPBlockCrypt selects and instantiates a KCP block cipher algorithm based on config crypt string.
func createKCPBlockCrypt(crypt, password string) (kcp.BlockCrypt, error) {
	if password == "" {
		return kcp.NewNoneBlockCrypt(nil)
	}
	switch crypt {
	case "aes":
		return kcp.NewAESBlockCrypt(deriveKCPKey(password, 32))
	case "aes-128":
		return kcp.NewAESBlockCrypt(deriveKCPKey(password, 16))
	case "aes-192":
		return kcp.NewAESBlockCrypt(deriveKCPKey(password, 24))
	case "aes-256":
		return kcp.NewAESBlockCrypt(deriveKCPKey(password, 32))
	case "aes-gcm", "aes-gcm-256":
		return kcp.NewAESGCMCrypt(deriveKCPKey(password, 32))
	case "aes-gcm-128":
		return kcp.NewAESGCMCrypt(deriveKCPKey(password, 16))
	case "aes-gcm-192":
		return kcp.NewAESGCMCrypt(deriveKCPKey(password, 24))
	case "salsa20":
		return kcp.NewSalsa20BlockCrypt(deriveKCPKey(password, 32))
	case "twofish":
		return kcp.NewTwofishBlockCrypt(deriveKCPKey(password, 32))
	case "tripledes":
		return kcp.NewTripleDESBlockCrypt(deriveKCPKey(password, 24))
	case "cast5":
		return kcp.NewCast5BlockCrypt(deriveKCPKey(password, 16))
	case "blowfish":
		return kcp.NewBlowfishBlockCrypt(deriveKCPKey(password, 32))
	case "tea":
		return kcp.NewTEABlockCrypt(deriveKCPKey(password, 16))
	case "xtea":
		return kcp.NewXTEABlockCrypt(deriveKCPKey(password, 16))
	case "none", "":
		return kcp.NewNoneBlockCrypt(nil)
	default:
		return nil, fmt.Errorf("unsupported KCP encryption cipher: %s", crypt)
	}
}

func intOverride(value int, set bool) *int {
	if !set && value == 0 {
		return nil
	}
	v := value
	return &v
}
func boolOverride(value bool, set bool) *bool {
	if !set && !value {
		return nil
	}
	v := value
	return &v
}
func int64Override(value int64, set bool) *int64 {
	if !set && value == 0 {
		return nil
	}
	v := value
	return &v
}
func floatOverride(value float64, set bool) *float64 {
	if !set && value == 0 {
		return nil
	}
	v := value
	return &v
}

func resolveKCPPolicy(cfg *proxyConfig) (kcppolicy.Policy, error) {
	if cfg == nil {
		return kcppolicy.Policy{}, fmt.Errorf("KCP config is required")
	}
	return kcppolicy.Resolve(kcppolicy.Input{
		Intent:              cfg.KCPProfile,
		ObservedLossPercent: floatOverride(cfg.KCPObservedLossPercent, cfg.KCPObservedLossSet),
		Overrides: kcppolicy.Overrides{
			DataShards:        intOverride(cfg.KCPDataShards, cfg.KCPDataShardsSet),
			ParityShards:      intOverride(cfg.KCPParityShards, cfg.KCPParityShardsSet),
			NoDelay:           intOverride(cfg.KCPNoDelay, cfg.KCPNoDelaySet),
			Interval:          intOverride(cfg.KCPInterval, cfg.KCPIntervalSet),
			Resend:            intOverride(cfg.KCPResend, cfg.KCPResendSet),
			NoCongestion:      intOverride(cfg.KCPNoCongestion, cfg.KCPNoCongestionSet),
			SendWindow:        intOverride(cfg.KCPSendWindow, cfg.KCPSendWindowSet),
			ReceiveWindow:     intOverride(cfg.KCPReceiveWindow, cfg.KCPReceiveWindowSet),
			MTU:               intOverride(cfg.KCPMTU, cfg.KCPMTUSet),
			ACKNoDelay:        boolOverride(cfg.KCPACKNoDelay, cfg.KCPACKNoDelaySet),
			WriteDelay:        boolOverride(cfg.KCPWriteDelay, cfg.KCPWriteDelaySet),
			DSCP:              intOverride(cfg.KCPDSCP, cfg.KCPDSCPSet),
			ReadBufferBytes:   intOverride(cfg.KCPReadBufferBytes, cfg.KCPReadBufferSet),
			WriteBufferBytes:  intOverride(cfg.KCPWriteBufferBytes, cfg.KCPWriteBufferSet),
			PacketDuplication: intOverride(cfg.KCPPacketDuplication, cfg.KCPPacketDuplicationSet),
			RateLimitBPS:      int64Override(cfg.KCPRateLimitBPS, cfg.KCPRateLimitSet),
		},
	})
}

func applyKCPPolicy(conn *kcp.UDPSession, policy kcppolicy.Policy) error {
	conn.SetNoDelay(policy.NoDelay, policy.Interval, policy.Resend, policy.NoCongestion)
	conn.SetWindowSize(policy.SendWindow, policy.ReceiveWindow)
	if policy.MTU != 0 && !conn.SetMtu(policy.MTU) {
		return fmt.Errorf("KCP rejected MTU %d", policy.MTU)
	}
	conn.SetACKNoDelay(policy.ACKNoDelay)
	conn.SetWriteDelay(policy.WriteDelay)
	conn.SetDUP(policy.PacketDuplication)
	if policy.DSCP != 0 {
		if err := conn.SetDSCP(policy.DSCP); err != nil {
			return fmt.Errorf("set KCP DSCP: %w", err)
		}
	}
	if policy.ReadBufferBytes != 0 {
		if err := conn.SetReadBuffer(policy.ReadBufferBytes); err != nil {
			return fmt.Errorf("set KCP read buffer: %w", err)
		}
	}
	if policy.WriteBufferBytes != 0 {
		if err := conn.SetWriteBuffer(policy.WriteBufferBytes); err != nil {
			return fmt.Errorf("set KCP write buffer: %w", err)
		}
	}
	conn.SetStreamMode(true)
	return nil
}

func kcpSessionKey(cfg *proxyConfig, policy kcppolicy.Policy) string {
	material := fmt.Sprintf("%s\x00%d\x00%s\x00%s\x00%+v\x00%s\x00%t\x00%d\x00%d", cfg.Address, cfg.Port, cfg.Method, cfg.Password, policy, cfg.KCPCompression, cfg.KCPJitter, cfg.KCPJitterMin, cfg.KCPJitterMax)
	digest := sha256.Sum256([]byte(material))
	return fmt.Sprintf("%s:%d|%x", cfg.Address, cfg.Port, digest[:12])
}

func wrapKCPTransport(conn net.Conn, cfg *proxyConfig, policy kcppolicy.Policy) net.Conn {
	var transportConn net.Conn = conn
	if policy.RateLimitBPS > 0 {
		transportConn = NewPacedConn(transportConn, policy.RateLimitBPS, policy.RateLimitBPS)
	}
	if cfg.KCPCompression != "" || cfg.KCPJitter {
		transportConn = NewNetrixConn(transportConn, cfg.KCPCompression, cfg.KCPJitter, cfg.KCPJitterMin, cfg.KCPJitterMax)
	}
	return transportConn
}

// KcpTransportManager manages client SMUX multiplexed sessions over KCP connections.
type KcpTransportManager struct {
	mu       sync.Mutex
	sessions map[string]*smux.Session
}

// NewKcpTransportManager creates a new KcpTransportManager instance.
func NewKcpTransportManager() *KcpTransportManager {
	return &KcpTransportManager{
		sessions: make(map[string]*smux.Session),
	}
}

// Dial establishes a KCP connection to the proxy server and wraps it in an SMUX multiplexed stream.
func (m *KcpTransportManager) Dial(cfg *proxyConfig) (net.Conn, error) {
	policy, err := resolveKCPPolicy(cfg)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	addr := fmt.Sprintf("%s:%d", cfg.Address, cfg.Port)
	key := kcpSessionKey(cfg, policy)
	smuxSess, ok := m.sessions[key]
	if !ok || smuxSess.IsClosed() {
		block, err := createKCPBlockCrypt(cfg.Method, cfg.Password)
		if err != nil {
			return nil, err
		}
		kcpConn, err := kcp.DialWithOptions(addr, block, policy.DataShards, policy.ParityShards)
		if err != nil {
			return nil, err
		}
		if err := applyKCPPolicy(kcpConn, policy); err != nil {
			_ = kcpConn.Close()
			return nil, err
		}
		transportConn := wrapKCPTransport(kcpConn, cfg, policy)
		smuxConfig := smux.DefaultConfig()
		smuxConfig.Version = 1
		smuxConfig.KeepAliveInterval = 10 * time.Second
		smuxConfig.KeepAliveTimeout = 30 * time.Second
		smuxConfig.MaxFrameSize = 32768
		smuxConfig.MaxReceiveBuffer = 4 << 20
		smuxConfig.MaxStreamBuffer = 64 << 10
		smuxSess, err = smux.Client(transportConn, smuxConfig)
		if err != nil {
			_ = transportConn.Close()
			return nil, err
		}
		m.sessions[key] = smuxSess
	}

	stream, err := smuxSess.OpenStream()
	if err != nil {
		_ = smuxSess.Close()
		delete(m.sessions, key)
		return nil, err
	}
	return stream, nil
}

// KcpListener wraps a KCP + SMUX listener to accept streams.
type KcpListener struct {
	kcpListener *kcp.Listener
	mu          sync.Mutex
	sessions    []*smux.Session
	accepted    chan net.Conn
	die         chan struct{}
	dieOnce     sync.Once
}

// ListenKcp creates a server KCP + SMUX listener.
func ListenKcp(laddr string, cfg *proxyConfig) (net.Listener, error) {
	policy, err := resolveKCPPolicy(cfg)
	if err != nil {
		return nil, err
	}
	block, err := createKCPBlockCrypt(cfg.Method, cfg.Password)
	if err != nil {
		return nil, err
	}
	kcpListener, err := kcp.ListenWithOptions(laddr, block, policy.DataShards, policy.ParityShards)
	if err != nil {
		return nil, err
	}
	if policy.DSCP != 0 {
		if err := kcpListener.SetDSCP(policy.DSCP); err != nil {
			_ = kcpListener.Close()
			return nil, fmt.Errorf("set KCP listener DSCP: %w", err)
		}
	}
	if policy.ReadBufferBytes != 0 {
		if err := kcpListener.SetReadBuffer(policy.ReadBufferBytes); err != nil {
			_ = kcpListener.Close()
			return nil, fmt.Errorf("set KCP listener read buffer: %w", err)
		}
	}
	if policy.WriteBufferBytes != 0 {
		if err := kcpListener.SetWriteBuffer(policy.WriteBufferBytes); err != nil {
			_ = kcpListener.Close()
			return nil, fmt.Errorf("set KCP listener write buffer: %w", err)
		}
	}
	l := &KcpListener{kcpListener: kcpListener, accepted: make(chan net.Conn, 100), die: make(chan struct{})}
	go l.acceptLoop(cfg, policy)
	return l, nil
}

func (l *KcpListener) acceptLoop(cfg *proxyConfig, policy kcppolicy.Policy) {
	for {
		kcpConn, err := l.kcpListener.AcceptKCP()
		if err != nil {
			select {
			case <-l.die:
				return
			default:
				continue
			}
		}
		if err := applyKCPPolicy(kcpConn, policy); err != nil {
			_ = kcpConn.Close()
			continue
		}
		transportConn := wrapKCPTransport(kcpConn, cfg, policy)
		smuxConfig := smux.DefaultConfig()
		smuxConfig.Version = 1
		smuxConfig.KeepAliveInterval = 10 * time.Second
		smuxConfig.KeepAliveTimeout = 30 * time.Second
		smuxConfig.MaxFrameSize = 32768
		smuxConfig.MaxReceiveBuffer = 4 << 20
		smuxConfig.MaxStreamBuffer = 64 << 10
		smuxSess, err := smux.Server(transportConn, smuxConfig)
		if err != nil {
			_ = transportConn.Close()
			continue
		}

		l.mu.Lock()
		l.sessions = append(l.sessions, smuxSess)
		l.mu.Unlock()
		go func(sess *smux.Session) {
			for {
				stream, err := sess.AcceptStream()
				if err != nil {
					return
				}
				select {
				case l.accepted <- stream:
				case <-l.die:
					_ = stream.Close()
					return
				}
			}
		}(smuxSess)
	}
}

// Accept accepts the next incoming stream connection.
func (l *KcpListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.accepted:
		return conn, nil
	case <-l.die:
		return nil, io.ErrClosedPipe
	}
}

// Close terminates KCP listener and closes all active multiplexed sessions.
func (l *KcpListener) Close() error {
	var err error
	l.dieOnce.Do(func() {
		close(l.die)
		err = l.kcpListener.Close()

		l.mu.Lock()
		for _, sess := range l.sessions {
			sess.Close()
		}
		l.mu.Unlock()
	})
	return err
}

// Addr returns the network address of the listener.
func (l *KcpListener) Addr() net.Addr {
	return l.kcpListener.Addr()
}
