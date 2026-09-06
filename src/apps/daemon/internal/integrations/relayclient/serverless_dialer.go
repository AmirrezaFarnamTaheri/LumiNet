package relayclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/maybeknott/luminet/internal/foundation/flowregistry"
	utls "github.com/refraction-networking/utls"
)

// ServerlessDialer establishes TCP connections by proxying over a WebSocket or HTTP Serverless Relay.
type ServerlessDialer struct {
	RelayURL string
}

// NewServerlessDialer creates a new dialer for serverless relays.
func NewServerlessDialer(relayURL string) *ServerlessDialer {
	return &ServerlessDialer{
		RelayURL: relayURL,
	}
}

// DialTarget establishes a virtual TCP connection to host:port via the Serverless Relay.
func (d *ServerlessDialer) DialTarget(ctx context.Context, host string, port int) (net.Conn, error) {
	if d.RelayURL == "" {
		return nil, fmt.Errorf("missing relay URL")
	}

	u, err := url.Parse(d.RelayURL)
	if err != nil {
		return nil, fmt.Errorf("invalid relay URL: %w", err)
	}

	if u.Scheme == "http" || u.Scheme == "https" {
		targetAddr := net.JoinHostPort(host, strconv.Itoa(port))
		return NewHttpServerlessConn(d.RelayURL, targetAddr), nil
	}

	dialer := &websocket.Dialer{
		HandshakeTimeout: 5 * time.Second,
		NetDialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			rawConn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			host, _, _ := net.SplitHostPort(addr)
			tlsConfig := &utls.Config{ServerName: host}
			tlsConn := utls.UClient(rawConn, tlsConfig, utls.HelloChrome_Auto)
			if err := tlsConn.Handshake(); err != nil {
				rawConn.Close()
				return nil, err
			}
			return tlsConn, nil
		},
	}

	header := http.Header{}
	header.Set("User-Agent", "LumiNet/1.0 (Serverless Dialer)")

	wsConn, _, err := dialer.DialContext(ctx, d.RelayURL, header)
	if err != nil {
		return nil, fmt.Errorf("websocket dial failed: %w", err)
	}
	configureRelayWebSocket(wsConn)

	// Send connection metadata first
	meta := map[string]interface{}{
		"host": host,
		"port": port,
	}
	metaBytes, err := json.Marshal(meta)
	if err != nil {
		wsConn.Close()
		return nil, fmt.Errorf("failed to marshal metadata: %w", err)
	}

	err = wsConn.WriteMessage(websocket.TextMessage, metaBytes)
	if err != nil {
		wsConn.Close()
		return nil, fmt.Errorf("failed to send metadata: %w", err)
	}

	// Wait for connection confirmation response from the relay server. The
	// WebSocket HTTP handshake timeout does not bound the first application
	// frame, so enforce a separate confirmation deadline.
	confirmationDeadline := time.Now().Add(relayWebSocketConfirmationTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(confirmationDeadline) {
		confirmationDeadline = ctxDeadline
	}
	if err := wsConn.SetReadDeadline(confirmationDeadline); err != nil {
		wsConn.Close()
		return nil, fmt.Errorf("failed to set relay confirmation deadline: %w", err)
	}
	_, msg, err := wsConn.ReadMessage()
	if err != nil {
		wsConn.Close()
		return nil, fmt.Errorf("failed to read relay confirmation: %w", err)
	}

	var status map[string]string
	if err := json.Unmarshal(msg, &status); err != nil || status["status"] != "connected" {
		wsConn.Close()
		return nil, fmt.Errorf("relay connection confirmation failed: %s", string(msg))
	}
	if err := wsConn.SetReadDeadline(time.Time{}); err != nil {
		wsConn.Close()
		return nil, fmt.Errorf("failed to clear relay confirmation deadline: %w", err)
	}

	return NewObservedWebSocketConn(wsConn, net.JoinHostPort(host, strconv.Itoa(port))), nil
}

type httpServerlessConn struct {
	relayURL   string
	realDst    string
	sessionID  string
	client     *http.Client
	state      *relayConnState
	seqMu      sync.Mutex
	pollCtx    context.Context
	pollCancel context.CancelFunc
	flow       *flowregistry.Handle

	// Sequence ordering variables
	writeSeq uint64
	querySeq uint64
}

// NewHttpServerlessConn creates a virtual connection executing base64 polling over HTTP POST streams.
func NewHttpServerlessConn(relayURL, realDst string) net.Conn {
	sessBytes := make([]byte, 8)
	_, _ = rand.Read(sessBytes)
	sessID := fmt.Sprintf("sess-%x", sessBytes)

	ctx, cancel := context.WithCancel(context.Background())

	c := &httpServerlessConn{
		relayURL:   relayURL,
		realDst:    realDst,
		sessionID:  sessID,
		client:     &http.Client{Timeout: 10 * time.Second},
		state:      newRelayConnState(),
		pollCtx:    ctx,
		pollCancel: cancel,
	}
	c.flow = registerRelayFlow("relay-serverless-http", "serverless-http", realDst, func(context.Context) error { return c.closeTransport() })

	go c.startPollingLoop()
	return c
}

func (c *httpServerlessConn) startPollingLoop() {
	defer closeFlowHandle(c.flow)
	runAdaptiveRelayPolling(c.pollCtx, c.state, c.sendRequest, func(n int) { addFlowUpload(c.flow, n) })
}

func (c *httpServerlessConn) sendRequest(data []byte) (bool, error) {
	c.seqMu.Lock()
	qseq := c.querySeq
	c.querySeq++
	var wseqVal *uint64
	if len(data) > 0 {
		w := c.writeSeq
		wseqVal = &w
		c.writeSeq++
	}
	c.seqMu.Unlock()

	payload := TunnelPayload{
		SessionID: c.sessionID,
		Target:    c.realDst,
		Data:      data,
		Seq:       &qseq,
		Wseq:      wseqVal,
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		if wseqVal != nil {
			c.seqMu.Lock()
			c.writeSeq--
			c.seqMu.Unlock()
		}
		return false, err
	}

	req, err := http.NewRequestWithContext(c.pollCtx, "POST", c.relayURL, bytes.NewReader(bodyBytes))
	if err != nil {
		if wseqVal != nil {
			c.seqMu.Lock()
			c.writeSeq--
			c.seqMu.Unlock()
		}
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "LumiNet/1.0 (Serverless HTTP Dialer)")

	resp, err := c.client.Do(req)
	if err != nil {
		if wseqVal != nil {
			c.seqMu.Lock()
			c.writeSeq--
			c.seqMu.Unlock()
		}
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if wseqVal != nil {
			c.seqMu.Lock()
			c.writeSeq--
			c.seqMu.Unlock()
		}
		return false, fmt.Errorf("relay returned non-200 status: %d", resp.StatusCode)
	}

	body, err := readBoundedRelayControlResponse(resp.Body)
	if err != nil {
		if wseqVal != nil {
			c.seqMu.Lock()
			c.writeSeq--
			c.seqMu.Unlock()
		}
		return false, err
	}
	var tunnelResp TunnelResponse
	if err := json.Unmarshal(body, &tunnelResp); err != nil {
		if wseqVal != nil {
			c.seqMu.Lock()
			c.writeSeq--
			c.seqMu.Unlock()
		}
		return false, relayControlDecodeError(resp.Header.Get("Content-Type"), body, err)
	}

	if err := validateRelayResponseSequence("relay", qseq, tunnelResp.Seq); err != nil {
		if wseqVal != nil {
			c.seqMu.Lock()
			c.writeSeq--
			c.seqMu.Unlock()
		}
		return false, err
	}

	if tunnelResp.Error != "" {
		if wseqVal != nil {
			c.seqMu.Lock()
			c.writeSeq--
			c.seqMu.Unlock()
		}
		return false, fmt.Errorf("tunnel error: %s", tunnelResp.Error)
	}

	received := len(tunnelResp.Data) > 0
	if received {
		if err := c.state.AppendRead(tunnelResp.Data); err != nil {
			c.pollCancel()
		} else {
			addFlowDownload(c.flow, len(tunnelResp.Data))
		}
	}

	return received, nil
}

func (c *httpServerlessConn) Read(b []byte) (int, error) { return c.state.Read(b) }

func (c *httpServerlessConn) Write(b []byte) (int, error) { return c.state.Write(b) }

func (c *httpServerlessConn) closeTransport() error {
	if c.state.Close(nil) {
		c.pollCancel()
	}
	return nil
}

func (c *httpServerlessConn) Close() error {
	err := c.closeTransport()
	closeFlowHandle(c.flow)
	return err
}

func (c *httpServerlessConn) LocalAddr() net.Addr                { return nil }
func (c *httpServerlessConn) RemoteAddr() net.Addr               { return nil }
func (c *httpServerlessConn) SetDeadline(t time.Time) error      { return c.state.SetDeadline(t) }
func (c *httpServerlessConn) SetReadDeadline(t time.Time) error  { return c.state.SetReadDeadline(t) }
func (c *httpServerlessConn) SetWriteDeadline(t time.Time) error { return c.state.SetWriteDeadline(t) }
