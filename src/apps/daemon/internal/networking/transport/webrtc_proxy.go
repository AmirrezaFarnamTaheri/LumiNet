// SPDX-License-Identifier: MIT
// WebRTC ICE Proxy Dialer & DataChannel Framing Transport
// Enables WebRTC ICE/TURN candidate dialing through HTTP/SOCKS5 proxies
// and encapsulation of data streams into RFC 8831/8832 WebRTC DataChannel frames.

package transport

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// Standard WebRTC DataChannel Message Types (RFC 8832)
const (
	DCEPMessageTypeOpen = 0x03
	DCEPMessageTypeAck  = 0x02

	// WebRTC DataChannel Payload Protocol Identifiers (RFC 8831)
	WebRTCPPIDDCEP        uint32 = 50
	WebRTCPPIDString      uint32 = 51
	WebRTCPPIDBinary      uint32 = 53
	WebRTCPPIDStringEmpty uint32 = 56
	WebRTCPPIDBinaryEmpty uint32 = 57

	DefaultProxyTimeout = 15 * time.Second
)

// ICEProxyConfig holds configuration for dialing TURN/STUN servers via an HTTP/HTTPS proxy.
type ICEProxyConfig struct {
	ProxyURL       *url.URL
	Username       string
	Password       string
	TargetTurnAddr string
	CustomHeaders  map[string]string
	TLSConfig      *tls.Config
	Timeout        time.Duration
}

// ICEProxyDialer implements proxy.Dialer and proxy.ContextDialer for WebRTC ICE/TURN transports.
type ICEProxyDialer struct {
	config     ICEProxyConfig
	baseDialer net.Dialer
}

var (
	_ proxy.Dialer        = (*ICEProxyDialer)(nil)
	_ proxy.ContextDialer = (*ICEProxyDialer)(nil)
)

// NewICEProxyDialer initializes an ICE proxy dialer from configuration.
func NewICEProxyDialer(config ICEProxyConfig) (*ICEProxyDialer, error) {
	if config.ProxyURL == nil {
		return nil, errors.New("webrtc: proxy URL is required")
	}
	scheme := strings.ToLower(config.ProxyURL.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("webrtc: unsupported proxy scheme %q, only http and https are supported", config.ProxyURL.Scheme)
	}
	if config.Timeout <= 0 {
		config.Timeout = DefaultProxyTimeout
	}

	return &ICEProxyDialer{
		config: config,
		baseDialer: net.Dialer{
			Timeout: config.Timeout,
		},
	}, nil
}

// Dial connects to the address via the proxy using standard network string.
func (d *ICEProxyDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

// DialContext establishes a CONNECT tunnel to addr through the configured HTTP/HTTPS proxy.
func (d *ICEProxyDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if !strings.HasPrefix(network, "tcp") {
		return nil, fmt.Errorf("webrtc: unsupported network %q for proxy CONNECT tunnel", network)
	}

	proxyHost := d.config.ProxyURL.Host
	if !strings.Contains(proxyHost, ":") {
		if strings.ToLower(d.config.ProxyURL.Scheme) == "https" {
			proxyHost += ":443"
		} else {
			proxyHost += ":80"
		}
	}

	var conn net.Conn
	var err error

	if strings.ToLower(d.config.ProxyURL.Scheme) == "https" {
		tlsCfg := d.config.TLSConfig
		if tlsCfg == nil {
			tlsCfg = &tls.Config{
				ServerName: d.config.ProxyURL.Hostname(),
			}
		}
		tlsDialer := &tls.Dialer{
			NetDialer: &d.baseDialer,
			Config:    tlsCfg,
		}
		conn, err = tlsDialer.DialContext(ctx, network, proxyHost)
	} else {
		conn, err = d.baseDialer.DialContext(ctx, network, proxyHost)
	}
	if err != nil {
		return nil, fmt.Errorf("webrtc: dial proxy %s failed: %w", proxyHost, err)
	}

	// Prepare HTTP CONNECT request
	connectReq := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: make(http.Header),
	}
	connectReq.Header.Set("Proxy-Connection", "Keep-Alive")
	connectReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36")

	// Inject proxy authorization if credentials provided
	username := d.config.Username
	password := d.config.Password
	if username == "" && d.config.ProxyURL.User != nil {
		username = d.config.ProxyURL.User.Username()
		password, _ = d.config.ProxyURL.User.Password()
	}
	if username != "" {
		credentials := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		connectReq.Header.Set("Proxy-Authorization", "Basic "+credentials)
	}

	// Apply custom headers
	for k, v := range d.config.CustomHeaders {
		connectReq.Header.Set(k, v)
	}

	// Send CONNECT request
	if err := connectReq.Write(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("webrtc: failed writing CONNECT request: %w", err)
	}

	// Read proxy response
	resp, err := http.ReadResponse(bufio.NewReader(conn), connectReq)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("webrtc: failed reading CONNECT response: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("webrtc: proxy rejected CONNECT with status %d: %s", resp.StatusCode, resp.Status)
	}

	return conn, nil
}

// DataChannelFrame represents a framed WebRTC DataChannel payload.
type DataChannelFrame struct {
	PPID    uint32
	Payload []byte
}

// Encode serializes a DataChannel message frame with a 4-byte PPID header.
func (f *DataChannelFrame) Encode() []byte {
	buf := make([]byte, 4+len(f.Payload))
	binary.BigEndian.PutUint32(buf[0:4], f.PPID)
	copy(buf[4:], f.Payload)
	return buf
}

// Decode parses a WebRTC DataChannel message frame from binary data.
func DecodeDataChannelFrame(data []byte) (*DataChannelFrame, error) {
	if len(data) < 4 {
		return nil, errors.New("webrtc: data channel frame too short")
	}
	ppid := binary.BigEndian.Uint32(data[0:4])
	payload := make([]byte, len(data)-4)
	copy(payload, data[4:])
	return &DataChannelFrame{
		PPID:    ppid,
		Payload: payload,
	}, nil
}

// WebRTCDataChannelConn wraps a net.Conn with WebRTC DataChannel binary framing.
type WebRTCDataChannelConn struct {
	conn    net.Conn
	reader  *bufio.Reader
	writeMu sync.Mutex
	readMu  sync.Mutex
}

// WrapDataChannelConn wraps an established stream into a DataChannel-framed connection.
func WrapDataChannelConn(c net.Conn) *WebRTCDataChannelConn {
	return &WebRTCDataChannelConn{
		conn:   c,
		reader: bufio.NewReader(c),
	}
}

// Write encapsulates raw bytes into a WebRTCPPIDBinary DataChannel frame with length prefix.
func (c *WebRTCDataChannelConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	frame := DataChannelFrame{
		PPID:    WebRTCPPIDBinary,
		Payload: p,
	}
	encoded := frame.Encode()

	// Prepend 2-byte length prefix for stream demarcation
	buf := make([]byte, 2+len(encoded))
	binary.BigEndian.PutUint16(buf[0:2], uint16(len(encoded)))
	copy(buf[2:], encoded)

	_, err := c.conn.Write(buf)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// Read extracts the binary payload from the next WebRTC DataChannel frame.
func (c *WebRTCDataChannelConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	var lenBuf [2]byte
	if _, err := io.ReadFull(c.reader, lenBuf[:]); err != nil {
		return 0, err
	}
	frameLen := binary.BigEndian.Uint16(lenBuf[:])

	frameBuf := make([]byte, frameLen)
	if _, err := io.ReadFull(c.reader, frameBuf); err != nil {
		return 0, err
	}

	frame, err := DecodeDataChannelFrame(frameBuf)
	if err != nil {
		return 0, err
	}

	n := copy(p, frame.Payload)
	return n, nil
}

// Close closes the underlying transport connection.
func (c *WebRTCDataChannelConn) Close() error {
	return c.conn.Close()
}

// LocalAddr returns the local address.
func (c *WebRTCDataChannelConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr returns the remote address.
func (c *WebRTCDataChannelConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline sets deadlines.
func (c *WebRTCDataChannelConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline sets read deadline.
func (c *WebRTCDataChannelConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets write deadline.
func (c *WebRTCDataChannelConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
