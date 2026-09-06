package tarpit

import (
	"context"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/maybeknott/luminet/internal/native/bridge"
)

var (
	globalTarpitServer *TarpitServer
	tarpitMu           sync.RWMutex
)

// GetTarpitServer returns the shared TarpitServer singleton.
func GetTarpitServer() *TarpitServer {
	tarpitMu.RLock()
	if globalTarpitServer != nil {
		defer tarpitMu.RUnlock()
		return globalTarpitServer
	}
	tarpitMu.RUnlock()

	tarpitMu.Lock()
	defer tarpitMu.Unlock()
	if globalTarpitServer == nil {
		globalTarpitServer = newTarpitServer(newLogger("tarpit"))
	}
	return globalTarpitServer
}

type TarpitServer struct {
	listener net.Listener
	logger   *logger
	running  bool
}

func newTarpitServer(logger *logger) *TarpitServer {
	return &TarpitServer{
		logger: logger,
	}
}

func (s *TarpitServer) Start(addr string) error {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(configureSocket)
		},
	}

	l, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		return err
	}

	s.listener = l
	s.running = true

	go s.acceptLoop()
	return nil
}

func (s *TarpitServer) acceptLoop() {
	for s.running {
		conn, err := s.listener.Accept()
		if err != nil {
			break
		}
		go s.handleConnection(conn)
	}
}

func (s *TarpitServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	ctx := context.Background()
	s.logger.Info(ctx, "Tarpit connection established", "remote_addr", conn.RemoteAddr().String())

	buf := make([]byte, 1)
	payload := make([]byte, 0, 512)

	for {
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := conn.Read(buf)
		if n > 0 {
			payload = append(payload, buf[0])

			if len(payload) >= 32 {
				disasm, err := bridge.DisassemblePayload(payload, "x64")
				if err == nil {
					if len(disasm) > 0 && (len(disasm) > 100 || len(payload) > 64) {
						s.logger.Warn(ctx, "Tarpit shellcode audit alert: potential exploit payload detected!",
							"remote_addr", conn.RemoteAddr().String(),
							"disassembly", disasm)
						return
					}
				}
			}
		}
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				time.Sleep(2 * time.Second)
				continue
			}
			break
		}
	}

	s.logger.Info(ctx, "Tarpit connection closed", "remote_addr", conn.RemoteAddr().String())
}

func (s *TarpitServer) Stop() {
	s.running = false
	if s.listener != nil {
		_ = s.listener.Close()
	}
}

func (s *TarpitServer) IsRunning() bool {
	return s.running
}

func (s *TarpitServer) ListenAddr() string {
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return ""
}
