// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: CandyConnect-main
// Target path: server/internal/proxy/candy_server.go

package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"log/slog"
	"os"
	"os/exec"
	"sync"
)

// CandyServer coordinates dnstt-server process lifecycles and configuration keys.
type CandyServer struct {
	mu         sync.Mutex
	Domain     string
	UDPPort    int
	TargetPort int // E.g., 22 (SSH) or 1080 (SOCKS)
	running    bool
	cmd        *exec.Cmd
	cancelFunc context.CancelFunc
}

// NewCandyServer instantiates a new CandyServer.
func NewCandyServer() *CandyServer {
	return &CandyServer{
		Domain:     "dns.candyconnect.io",
		UDPPort:    5300,
		TargetPort: 22,
	}
}

// GenerateDNSTTKeys generates ECDSA P-256 keys compatible with dnstt.
func (c *CandyServer) GenerateDNSTTKeys(privPath, pubPath string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Generate Private Key
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	privBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return err
	}

	privBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privBytes,
	}

	err = ioutil.WriteFile(privPath, pem.EncodeToMemory(privBlock), 0600)
	if err != nil {
		return err
	}

	// Generate Public Key
	pubBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return err
	}

	pubBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}

	err = ioutil.WriteFile(pubPath, pem.EncodeToMemory(pubBlock), 0644)
	if err != nil {
		return err
	}

	log.Printf("CandyServer: Generated dnstt EC private key at %s and public key at %s", privPath, pubPath)
	return nil
}

// StartDNSTT launches the dnstt-server executable in a background process context.
func (c *CandyServer) StartDNSTT(ctx context.Context, binaryPath string, privKeyPath string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running {
		return fmt.Errorf("dnstt-server is already running")
	}

	if _, err := os.Stat(privKeyPath); os.IsNotExist(err) {
		return fmt.Errorf("dnstt private key not found: %s", privKeyPath)
	}

	// args: -udp :udpPort -privkey-file privKeyPath domain targetAddr:targetPort
	targetAddr := fmt.Sprintf("127.0.0.1:%d", c.TargetPort)
	args := []string{
		"-udp", fmt.Sprintf(":%d", c.UDPPort),
		"-privkey-file", privKeyPath,
		c.Domain,
		targetAddr,
	}

	procCtx, cancel := context.WithCancel(ctx)
	c.cancelFunc = cancel

	cmd := exec.CommandContext(procCtx, binaryPath, args...)
	err := cmd.Start()
	if err != nil {
		cancel()
		return err
	}

	c.cmd = cmd
	c.running = true
	log.Printf("CandyServer: Established dnstt-server listening on UDP :%d forwarding to %s for domain %s", c.UDPPort, targetAddr, c.Domain)

	// Monitor process termination in background
	go func() {
		_ = cmd.Wait()
		c.mu.Lock()
		c.running = false
		c.cmd = nil
		c.mu.Unlock()
		slog.Info("CandyServer", "status", "dnstt-server process stopped")
	}()

	return nil
}

// StopDNSTT gracefully stops the dnstt-server.
func (c *CandyServer) StopDNSTT() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return nil
	}

	if c.cancelFunc != nil {
		c.cancelFunc()
	}
	c.running = false
	c.cmd = nil
	return nil
}

// Connect implements the legacy entry trigger.
func (c *CandyServer) Connect() {
	// Diagnostic stub
}
