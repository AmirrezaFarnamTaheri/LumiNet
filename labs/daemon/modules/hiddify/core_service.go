// Package hiddify provides bridging and orchestration for the hiddify-app FFI and Core.
// Ported from: hiddify-app
// Target path: server/internal/hiddify/core_service.go
package hiddify

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// CoreService orchestrates the local gRPC server on port 17078 to interact
// with the underlying core library through the hiddify-app FFI bridge.
type CoreService struct {
	secret string
	port   int
	mu     sync.Mutex
	active bool
}

// NewCoreService creates a new CoreService instance with a randomized secret.
func NewCoreService() *CoreService {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("Failed to generate secret: %v", err)
	}
	return &CoreService{
		secret: hex.EncodeToString(b),
		port:   17078,
	}
}

// Start initiates the core process and listens for commands.
func (s *CoreService) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.active {
		s.mu.Unlock()
		return fmt.Errorf("core service is already running")
	}
	s.active = true
	s.mu.Unlock()

	log.Printf("Starting Hiddify CoreService on 127.0.0.1:%d with secret %s", s.port, s.secret)

	// Simulate starting the gRPC server
	addr := fmt.Sprintf("127.0.0.1:%d", s.port)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to bind port %d: %w", s.port, err)
	}
	defer l.Close()

	// Handle core process start/stop and log streaming commands
	go func() {
		<-ctx.Done()
		s.Stop()
	}()

	for {
		conn, err := l.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				log.Printf("Accept error: %v", err)
				continue
			}
		}
		go s.handleConnection(conn)
	}
}

func (s *CoreService) handleConnection(conn net.Conn) {
	defer conn.Close()
	// Simulated FFI command handling
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err == nil {
		cmd := string(buf[:n])
		log.Printf("CoreService received command: %s", cmd)
		conn.Write([]byte("ACK\n"))
	}
}

// Stop terminates the core process.
func (s *CoreService) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.active {
		return
	}
	log.Printf("Stopping Hiddify CoreService")
	s.active = false
}

// StreamLogs connects to the core log stream and yields lines.
func (s *CoreService) StreamLogs(ch chan<- string) {
	if !s.active {
		return
	}
	// Simulated log stream
	ch <- "CoreService: Initializing routing rules"
	ch <- "CoreService: Listening for incoming tunneled connections"
}
