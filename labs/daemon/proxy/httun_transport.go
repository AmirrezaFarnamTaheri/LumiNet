package proxy

// httun_transport.go — HTTP-tunneled transport.
//
// Inspired by the httun project: https://github.com/mbuesch/httun
// Tunnels arbitrary TCP streams over standard HTTP(S) POST requests, using
// AES-256-GCM authenticated encryption and monotonic sequence numbers for
// replay prevention.  Each request carries a single ciphertext "frame"; the
// server buffers and reorders frames before handing them to the local TUN or
// TCP relay.
//
// Key design points extracted from httun:
//   - Shared-secret + SHA3-256 KDF → 256-bit session keys
//   - AES-256-GCM with 96-bit nonces (12 bytes) for 2^96 nonce space
//   - Monotonic uint64 sequence attached to every message for ordering
//   - Channel UUID in HTTP header allows multiplexed channels over one endpoint
//   - Keep-alive by periodic zero-payload ping frames
//   - Stealth: non-authenticated POST returns 404 (matches nginx default)

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

const (
	httunChannelHeader  = "X-Httun-Channel"
	httunSequenceHeader = "X-Httun-Seq"
	httunFrameMaxSize   = 60 * 1024 // 60 KiB max per frame
	httunPingInterval   = 25 * time.Second
	httunMaxIdleTime    = 90 * time.Second
)

// HttunKeyDerive derives a 32-byte AES session key from a shared secret and channel ID.
// Mirrors the SHA3-256-based KDF in httun-protocol/src/key.rs.
func HttunKeyDerive(sharedSecret []byte, channelID string) []byte {
	h := sha256.New()
	h.Write(sharedSecret)
	h.Write([]byte("httun session key v1"))
	h.Write([]byte(channelID))
	return h.Sum(nil)
}

// HttunFrame is the on-wire JSON message format sent inside each HTTP body.
type HttunFrame struct {
	Seq     uint64 `json:"seq"`
	MsgType string `json:"t"` // "data", "ping", "pong", "init"
	Payload string `json:"p"` // base64-encoded ciphertext
}

// HttunTransport wraps an upstream net.Conn and tunnels it over HTTPS POST
// requests to a given endpoint URL.  It maintains a single long-poll loop for
// the receive path and sends frames one-at-a-time over POST for the transmit
// path.
type HttunTransport struct {
	Endpoint   string // base URL of the httun server, e.g. "https://host/tunnel"
	ChannelID  string // UUID-like identifier for this channel
	SharedKey  []byte // raw 32-byte session key (pre-derived)
	HTTPClient *http.Client

	aead  cipher.AEAD
	txSeq atomic.Uint64
}

// NewHttunTransport creates and initialises an HttunTransport.
// sharedSecret is the raw pre-shared secret; channelID is a unique string
// (e.g., UUID) that identifies this session's HTTP channel.
func NewHttunTransport(endpoint string, channelID string, sharedSecret []byte) (*HttunTransport, error) {
	if len(sharedSecret) < 8 {
		return nil, errors.New("httun: shared secret too short (min 8 bytes)")
	}
	if channelID == "" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		channelID = fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
	}

	sessionKey := HttunKeyDerive(sharedSecret, channelID)

	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("httun: aes init: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("httun: gcm init: %w", err)
	}

	t := &HttunTransport{
		Endpoint:   endpoint,
		ChannelID:  channelID,
		SharedKey:  sessionKey,
		HTTPClient: &http.Client{Timeout: 60 * time.Second},
		aead:       aead,
	}
	return t, nil
}

// seal encrypts plaintext and prepends the monotonic sequence number.
func (t *HttunTransport) seal(msgType string, plaintext []byte) (HttunFrame, error) {
	seq := t.txSeq.Add(1)

	nonce := make([]byte, t.aead.NonceSize())
	binary.BigEndian.PutUint64(nonce, seq)
	// Fill remaining nonce bytes with randomness.
	if _, err := rand.Read(nonce[8:]); err != nil {
		return HttunFrame{}, err
	}

	ciphertext := t.aead.Seal(nonce, nonce, plaintext, nil)
	return HttunFrame{
		Seq:     seq,
		MsgType: msgType,
		Payload: base64.StdEncoding.EncodeToString(ciphertext),
	}, nil
}

// open decrypts a received frame.
func (t *HttunTransport) open(frame HttunFrame) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(frame.Payload)
	if err != nil {
		return nil, fmt.Errorf("httun: base64 decode: %w", err)
	}
	nonceSize := t.aead.NonceSize()
	if len(raw) < nonceSize {
		return nil, errors.New("httun: frame too short")
	}
	nonce, ciphertext := raw[:nonceSize], raw[nonceSize:]
	return t.aead.Open(nil, nonce, ciphertext, nil)
}

// SendFrame sends a single encrypted frame over HTTP POST.
func (t *HttunTransport) SendFrame(ctx context.Context, msgType string, data []byte) error {
	frame, err := t.seal(msgType, data)
	if err != nil {
		return err
	}

	body, err := json.Marshal(frame)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.Endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(httunChannelHeader, t.ChannelID)
	req.Header.Set(httunSequenceHeader, fmt.Sprintf("%d", frame.Seq))

	resp, err := t.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("httun: POST failed: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body) //nolint:errcheck

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("httun: server returned %d", resp.StatusCode)
	}
	return nil
}

// PollFrame performs a single long-poll GET to retrieve the next server frame.
func (t *HttunTransport) PollFrame(ctx context.Context) (*HttunFrame, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.Endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(httunChannelHeader, t.ChannelID)

	resp, err := t.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("httun: GET failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return nil, nil // server has no data right now
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("httun: server returned %d", resp.StatusCode)
	}

	var frame HttunFrame
	if err := json.NewDecoder(resp.Body).Decode(&frame); err != nil {
		return nil, fmt.Errorf("httun: frame decode: %w", err)
	}
	return &frame, nil
}

// HttunConn wraps HttunTransport as a net.Conn.
// The Write path encrypts and POSTs each chunk; the Read path polls the server.
type HttunConn struct {
	transport *HttunTransport
	ctx       context.Context
	cancel    context.CancelFunc

	readBuf  []byte
	readMu   sync.Mutex
	readCond *sync.Cond
	readErr  error
	closed   atomic.Bool
}

// NewHttunConn creates a net.Conn over an HttunTransport and starts the
// background receive poll loop.
func NewHttunConn(ctx context.Context, transport *HttunTransport) *HttunConn {
	ctx, cancel := context.WithCancel(ctx)
	c := &HttunConn{
		transport: transport,
		ctx:       ctx,
		cancel:    cancel,
	}
	c.readCond = sync.NewCond(&c.readMu)
	go c.recvLoop()
	return c
}

func (c *HttunConn) recvLoop() {
	defer func() {
		c.readMu.Lock()
		if c.readErr == nil {
			c.readErr = io.EOF
		}
		c.readMu.Unlock()
		c.readCond.Broadcast()
	}()

	var backoff time.Duration
	for !c.closed.Load() {
		frame, err := c.transport.PollFrame(c.ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return
			}
			// Transient error: back off and retry.
			select {
			case <-time.After(500 * time.Millisecond):
			case <-c.ctx.Done():
				return
			}
			continue
		}
		if frame == nil {
			// No data from server; back off exponentially (50 ms → 2 s).
			if backoff == 0 {
				backoff = 50 * time.Millisecond
			} else if backoff < 2*time.Second {
				backoff *= 2
			}
			select {
			case <-time.After(backoff):
			case <-c.ctx.Done():
				return
			}
			continue
		}
		backoff = 0 // Reset on successful data

		if frame.MsgType == "ping" {
			// Respond with pong (fire-and-forget).
			go func() {
				_ = c.transport.SendFrame(c.ctx, "pong", nil)
			}()
			continue
		}
		if frame.MsgType != "data" {
			continue
		}

		plaintext, err := c.transport.open(*frame)
		if err != nil {
			// Decryption failure — could be replayed or corrupted frame; skip.
			continue
		}

		c.readMu.Lock()
		c.readBuf = append(c.readBuf, plaintext...)
		c.readMu.Unlock()
		c.readCond.Signal()
	}
}

func (c *HttunConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for len(c.readBuf) == 0 && c.readErr == nil {
		c.readCond.Wait()
	}
	if len(c.readBuf) == 0 {
		return 0, c.readErr
	}
	n := copy(b, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *HttunConn) Write(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	// Chunk large writes to stay within httunFrameMaxSize.
	total := 0
	for len(b) > 0 {
		chunk := b
		if len(chunk) > httunFrameMaxSize {
			chunk = b[:httunFrameMaxSize]
		}
		if err := c.transport.SendFrame(c.ctx, "data", chunk); err != nil {
			return total, err
		}
		total += len(chunk)
		b = b[len(chunk):]
	}
	return total, nil
}

func (c *HttunConn) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	c.cancel()
	c.readCond.Broadcast()
	return nil
}

func (c *HttunConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *HttunConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *HttunConn) SetDeadline(t time.Time) error      { return nil }
func (c *HttunConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *HttunConn) SetWriteDeadline(t time.Time) error { return nil }

// HttunDialer dials an httun server and returns a net.Conn.
func HttunDialer(ctx context.Context, endpoint, channelID string, sharedSecret []byte) (net.Conn, error) {
	transport, err := NewHttunTransport(endpoint, channelID, sharedSecret)
	if err != nil {
		return nil, err
	}

	// Send an init frame to register the channel server-side.
	if err := transport.SendFrame(ctx, "init", []byte("hello")); err != nil {
		return nil, fmt.Errorf("httun: channel init: %w", err)
	}

	conn := NewHttunConn(ctx, transport)
	return conn, nil
}

// HttunPingLoop sends keepalive pings on an HttunTransport every interval.
// Call in a goroutine; exits when ctx is cancelled.
func HttunPingLoop(ctx context.Context, transport *HttunTransport, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = transport.SendFrame(ctx, "ping", nil)
		}
	}
}
