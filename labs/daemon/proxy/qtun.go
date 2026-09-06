// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: qtun-master
// Target path: server/internal/proxy/qtun.go

package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"log/slog"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// Qtun manages QUIC-based tunnels for Shadowsocks SIP003 transport layer obfuscation.
type Qtun struct {
	mu         sync.Mutex
	ListenPort int
	TLSConfig  *tls.Config
	running    bool
	listener   *quic.Listener
	cancelFunc context.CancelFunc
}

// NewQtun instantiates a new Qtun instance.
func NewQtun() *Qtun {
	return &Qtun{
		ListenPort: 8443,
	}
}

// StartServer starts a QUIC listener to accept multiplexed QUIC streams.
func (q *Qtun) StartServer(ctx context.Context, listenAddr string) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.running {
		return fmt.Errorf("qtun server already running")
	}

	if q.TLSConfig == nil {
		return fmt.Errorf("TLS configuration must be set for QUIC listener")
	}

	// Listen on UDP port for QUIC
	l, err := quic.ListenAddr(listenAddr, q.TLSConfig, &quic.Config{
		KeepAlivePeriod: 30 * time.Second,
	})
	if err != nil {
		return err
	}

	procCtx, cancel := context.WithCancel(ctx)
	q.cancelFunc = cancel
	q.listener = l
	q.running = true

	log.Printf("Qtun: QUIC listener established on UDP %s", listenAddr)

	go func() {
		for {
			sess, err := l.Accept(procCtx)
			if err != nil {
				return
			}
			go q.handleSession(procCtx, sess)
		}
	}()

	return nil
}

func (q *Qtun) handleSession(ctx context.Context, sess *quic.Conn) {
	defer sess.CloseWithError(0, "session closed")

	for {
		stream, err := sess.AcceptStream(ctx)
		if err != nil {
			return
		}
		go q.handleStream(stream)
	}
}

func (q *Qtun) handleStream(stream *quic.Stream) {
	defer stream.Close()

	// Simulating packet forwarding
	buf := make([]byte, 16*1024)
	for {
		nr, err := stream.Read(buf)
		if nr > 0 {
			_, _ = stream.Write(buf[0:nr])
		}
		if err != nil {
			break
		}
	}
}

// StopServer closes the active QUIC listener.
func (q *Qtun) StopServer() error {
	q.mu.Lock()
	defer q.mu.Unlock()

	if !q.running {
		return nil
	}

	if q.cancelFunc != nil {
		q.cancelFunc()
	}
	if q.listener != nil {
		q.listener.Close()
	}
	q.running = false
	slog.Info("Qtun", "status", "QUIC listener closed")
	return nil
}

// Start is the legacy diagnostic interface trigger.
func (q *Qtun) Start() {
	// Diagnostic stub
}
