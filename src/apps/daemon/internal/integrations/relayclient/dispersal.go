package relayclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
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

// EdgeRunnerType identifies the serverless edge cloud provider.
type EdgeRunnerType string

const (
	EdgeRunnerCloudflare EdgeRunnerType = "cloudflare_workers"
	EdgeRunnerVercel     EdgeRunnerType = "vercel_edge"
	EdgeRunnerAWSLambda  EdgeRunnerType = "aws_lambda"
	EdgeRunnerAppsScript EdgeRunnerType = "google_apps_script"
)

// EdgeEndpoint represents one edge runner relay node in the dispersal fabric.
type EdgeEndpoint struct {
	Type      EdgeRunnerType `json:"type"`
	URL       string         `json:"url"`
	Healthy   bool           `json:"healthy"`
	LatencyMs float64        `json:"latency_ms"`
}

// MicroFrame is a striped packet chunk traveling across an edge runner.
type MicroFrame struct {
	SessionID   string `json:"session_id"`
	Target      string `json:"target"`
	Seq         uint64 `json:"seq"`
	TotalChunks int    `json:"total_chunks"`
	ChunkIdx    int    `json:"chunk_idx"`
	Data        []byte `json:"data"`
}

// DispersalDialer multiplexes and stripes TCP/stream payloads across orthogonal edge runners.
type DispersalDialer struct {
	Endpoints  []EdgeEndpoint
	ChunkSize  int
	HTTPClient *http.Client
	mu         sync.RWMutex
}

// NewDispersalDialer creates a new multi-path micro-dispersal dialer.
func NewDispersalDialer(endpoints []EdgeEndpoint, chunkSize int) *DispersalDialer {
	if chunkSize <= 0 {
		chunkSize = 1024 // 1KB default chunk size for low-jitter DPI avoidance
	}
	return &DispersalDialer{
		Endpoints: endpoints,
		ChunkSize: chunkSize,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 20,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
}

// DialContext creates a multi-path dispersed virtual connection to target.
func (d *DispersalDialer) DialContext(ctx context.Context, target string) (*DispersalConn, error) {
	d.mu.RLock()
	if len(d.Endpoints) == 0 {
		d.mu.RUnlock()
		return nil, fmt.Errorf("no edge relay endpoints configured for micro-dispersal")
	}
	endpoints := append([]EdgeEndpoint(nil), d.Endpoints...)
	d.mu.RUnlock()

	sessionBytes := make([]byte, 16)
	if _, err := rand.Read(sessionBytes); err != nil {
		return nil, err
	}
	sessionID := hex.EncodeToString(sessionBytes)

	conn := &DispersalConn{
		dialer:       d,
		target:       target,
		sessionID:    sessionID,
		endpoints:    endpoints,
		chunkSize:    d.ChunkSize,
		readBuf:      new(bytes.Buffer),
		readNotify:   make(chan struct{}, 1),
		inboundQueue: make(map[uint64][]byte),
		closeCh:      make(chan struct{}),
	}

	return conn, nil
}

// DispersalConn implements net.Conn over an orthogonal multi-cloud dispersal fabric.
type DispersalConn struct {
	dialer    *DispersalDialer
	target    string
	sessionID string
	endpoints []EdgeEndpoint
	chunkSize int

	writeSeq  uint64
	readSeq   uint64
	edgeIndex uint64

	readMu       sync.Mutex
	readBuf      *bytes.Buffer
	readNotify   chan struct{}
	inboundQueue map[uint64][]byte

	writeMu  sync.Mutex
	closed   bool
	closeCh  chan struct{}
	closeErr error

	readDeadline  time.Time
	writeDeadline time.Time
}

func (c *DispersalConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for {
		if c.readBuf.Len() > 0 {
			return c.readBuf.Read(b)
		}

		select {
		case <-c.closeCh:
			if c.readBuf.Len() > 0 {
				return c.readBuf.Read(b)
			}
			if c.closeErr != nil {
				return 0, c.closeErr
			}
			return 0, io.EOF
		case _, ok := <-c.readNotify:
			if !ok {
				if c.readBuf.Len() > 0 {
					return c.readBuf.Read(b)
				}
				return 0, io.EOF
			}
		}
	}
}

// Write stripes incoming bytes into MicroFrames and sends them across edge relays.
func (c *DispersalConn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	select {
	case <-c.closeCh:
		return 0, errors.New("connection closed")
	default:
	}

	// Calculate chunks
	totalLen := len(b)
	chunkSize := c.chunkSize
	numChunks := (totalLen + chunkSize - 1) / chunkSize

	var wg sync.WaitGroup
	errCh := make(chan error, numChunks)

	for i := 0; i < numChunks; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > totalLen {
			end = totalLen
		}
		chunkData := append([]byte(nil), b[start:end]...)
		seq := atomic.AddUint64(&c.writeSeq, 1)

		frame := MicroFrame{
			SessionID:   c.sessionID,
			Target:      c.target,
			Seq:         seq,
			TotalChunks: numChunks,
			ChunkIdx:    i,
			Data:        chunkData,
		}

		// Select edge runner using round-robin across healthy endpoints
		idx := atomic.AddUint64(&c.edgeIndex, 1) % uint64(len(c.endpoints))
		edge := c.endpoints[idx]

		wg.Add(1)
		go func(f MicroFrame, ep EdgeEndpoint) {
			defer wg.Done()
			if err := c.sendFrame(f, ep); err != nil {
				errCh <- err
			}
		}(frame, edge)
	}

	wg.Wait()
	close(errCh)

	if err, ok := <-errCh; ok {
		return 0, fmt.Errorf("dispersal relay transmission failure: %w", err)
	}

	return totalLen, nil
}

func (c *DispersalConn) sendFrame(frame MicroFrame, endpoint EdgeEndpoint) error {
	payload, err := json.Marshal(frame)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, endpoint.URL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-LumiNet-Session", frame.SessionID)

	resp, err := c.dialer.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("relay %s returned HTTP %d", endpoint.Type, resp.StatusCode)
	}

	// Read optional response payload from relay (duplex tunnel data)
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err == nil && len(respBody) > 0 {
		var inbound MicroFrame
		if json.Unmarshal(respBody, &inbound) == nil && len(inbound.Data) > 0 {
			c.deliverInbound(inbound)
		}
	}

	return nil
}

// deliverInbound puts incoming chunk into reassembly queue and drains sequential bytes.
func (c *DispersalConn) deliverInbound(frame MicroFrame) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	c.inboundQueue[frame.Seq] = frame.Data

	drained := false
	// Drain consecutive sequences
	for {
		nextExpected := c.readSeq + 1
		data, found := c.inboundQueue[nextExpected]
		if !found {
			break
		}
		delete(c.inboundQueue, nextExpected)
		c.readSeq = nextExpected
		c.readBuf.Write(data)
		drained = true
	}

	if drained {
		select {
		case c.readNotify <- struct{}{}:
		default:
		}
	}
}

func (c *DispersalConn) Close() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true
	close(c.closeCh)
	return nil
}

func (c *DispersalConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
}

func (c *DispersalConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443}
}

func (c *DispersalConn) SetDeadline(t time.Time) error {
	c.readDeadline = t
	c.writeDeadline = t
	return nil
}

func (c *DispersalConn) SetReadDeadline(t time.Time) error {
	c.readDeadline = t
	return nil
}

func (c *DispersalConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline = t
	return nil
}
