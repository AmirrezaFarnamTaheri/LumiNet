package relayclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/maybeknott/luminet/internal/foundation/flowregistry"
)

type GsaTunnelConn struct {
	scriptURL  string
	authKey    string
	realDst    string
	sessionID  string
	client     *http.Client
	state      *relayConnState
	seqMu      sync.Mutex
	pollCtx    context.Context
	pollCancel context.CancelFunc
	flow       *flowregistry.Handle

	writeSeq uint64
	querySeq uint64
}

func NewGsaTunnelConn(scriptURL, authKey, realDst string) *GsaTunnelConn {
	sessBytes := make([]byte, 8)
	_, _ = rand.Read(sessBytes)
	sessID := fmt.Sprintf("sess-%x", sessBytes)

	ctx, cancel := context.WithCancel(context.Background())

	c := &GsaTunnelConn{
		scriptURL:  scriptURL,
		authKey:    authKey,
		realDst:    realDst,
		sessionID:  sessID,
		client:     &http.Client{Timeout: 10 * time.Second},
		state:      newRelayConnState(),
		pollCtx:    ctx,
		pollCancel: cancel,
	}
	c.flow = registerRelayFlow("relay-gsa", "gsa-http", realDst, func(context.Context) error { return c.closeTransport() })

	go c.startPollingLoop()
	return c
}

func (c *GsaTunnelConn) startPollingLoop() {
	defer closeFlowHandle(c.flow)
	runAdaptiveRelayPolling(c.pollCtx, c.state, c.sendRequest, func(n int) { addFlowUpload(c.flow, n) })
}

func (c *GsaTunnelConn) sendRequest(data []byte) (bool, error) {
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
	rollbackWriteSeq := func() {
		if wseqVal == nil {
			return
		}
		c.seqMu.Lock()
		if c.writeSeq > 0 {
			c.writeSeq--
		}
		c.seqMu.Unlock()
	}
	payload := TunnelPayload{
		SessionID: c.sessionID,
		Target:    c.realDst,
		Data:      data,
		Wseq:      wseqVal,
		Seq:       &qseq,
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		rollbackWriteSeq()
		return false, err
	}

	req, err := http.NewRequestWithContext(c.pollCtx, "POST", c.scriptURL, bytes.NewReader(bodyBytes))
	if err != nil {
		rollbackWriteSeq()
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.authKey != "" {
		req.Header.Set("X-GSA-Auth-Key", c.authKey)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		rollbackWriteSeq()
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		rollbackWriteSeq()
		return false, fmt.Errorf("GSA returned non-200 status: %d", resp.StatusCode)
	}

	body, err := readBoundedRelayControlResponse(resp.Body)
	if err != nil {
		rollbackWriteSeq()
		return false, err
	}
	var tunnelResp TunnelResponse
	if err := json.Unmarshal(body, &tunnelResp); err != nil {
		rollbackWriteSeq()
		return false, relayControlDecodeError(resp.Header.Get("Content-Type"), body, err)
	}

	// Sequence is optional for predecessor Apps Script relays. When a relay
	// advertises it, correlation becomes fail-closed so a stale/out-of-order
	// response cannot be mistaken for the current poll.
	if err := validateRelayResponseSequence("GSA", qseq, tunnelResp.Seq); err != nil {
		rollbackWriteSeq()
		return false, err
	}

	if tunnelResp.Error != "" {
		rollbackWriteSeq()
		return false, fmt.Errorf("tunnel error: %s", tunnelResp.Error)
	}

	received := len(tunnelResp.Data) > 0
	if received {
		if err := c.state.AppendRead(tunnelResp.Data); err != nil {
			rollbackWriteSeq()
			c.pollCancel()
			return false, err
		} else {
			addFlowDownload(c.flow, len(tunnelResp.Data))
		}
	}

	return received, nil
}

func (c *GsaTunnelConn) Read(b []byte) (int, error) { return c.state.Read(b) }

func (c *GsaTunnelConn) Write(b []byte) (int, error) { return c.state.Write(b) }

func (c *GsaTunnelConn) closeTransport() error {
	if c.state.Close(nil) {
		c.pollCancel()
	}
	return nil
}

func (c *GsaTunnelConn) Close() error {
	err := c.closeTransport()
	closeFlowHandle(c.flow)
	return err
}

func (c *GsaTunnelConn) LocalAddr() net.Addr                { return nil }
func (c *GsaTunnelConn) RemoteAddr() net.Addr               { return nil }
func (c *GsaTunnelConn) SetDeadline(t time.Time) error      { return c.state.SetDeadline(t) }
func (c *GsaTunnelConn) SetReadDeadline(t time.Time) error  { return c.state.SetReadDeadline(t) }
func (c *GsaTunnelConn) SetWriteDeadline(t time.Time) error { return c.state.SetWriteDeadline(t) }
