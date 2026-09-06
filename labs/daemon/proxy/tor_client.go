// Ported from: OnionHop-master
// Target path: server/internal/proxy/tor_client.go

package proxy

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// TorController connects to Tor control port and manages identity renewal / bootstrap monitoring.
type TorController struct {
	ControlAddr string
	Password    string
	conn        net.Conn
	mu          sync.Mutex
}

// NewTorController creates a new control client.
func NewTorController(addr, password string) *TorController {
	return &TorController{
		ControlAddr: addr,
		Password:    password,
	}
}

// Connect dials the control port and authenticates.
func (c *TorController) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var err error
	c.conn, err = net.DialTimeout("tcp", c.ControlAddr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("tor_client: connect control: %w", err)
	}

	// Authenticate
	authCmd := fmt.Sprintf("AUTHENTICATE \"%s\"\r\n", c.Password)
	if c.Password == "" {
		authCmd = "AUTHENTICATE\r\n"
	}

	_, err = c.conn.Write([]byte(authCmd))
	if err != nil {
		c.conn.Close()
		return err
	}

	reader := bufio.NewReader(c.conn)
	resp, err := reader.ReadString('\n')
	if err != nil {
		c.conn.Close()
		return err
	}

	if !strings.HasPrefix(resp, "250") {
		c.conn.Close()
		return fmt.Errorf("tor_client: authentication failed: %s", strings.TrimSpace(resp))
	}

	return nil
}

// SignalNewNym requests a new circuit route (cycles outgoing IP address).
func (c *TorController) SignalNewNym() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return fmt.Errorf("tor_client: control port not connected")
	}

	_, err := c.conn.Write([]byte("SIGNAL NEWNYM\r\n"))
	if err != nil {
		return err
	}

	reader := bufio.NewReader(c.conn)
	resp, err := reader.ReadString('\n')
	if err != nil {
		return err
	}

	if !strings.HasPrefix(resp, "250") {
		return fmt.Errorf("tor_client: NEWNYM signal failed: %s", strings.TrimSpace(resp))
	}

	return nil
}

// GetBootstrapProgress queries Tor bootstrap status (0 to 100).
func (c *TorController) GetBootstrapProgress() (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return 0, fmt.Errorf("tor_client: control port not connected")
	}

	_, err := c.conn.Write([]byte("GETINFO status/bootstrap-phase\r\n"))
	if err != nil {
		return 0, err
	}

	reader := bufio.NewReader(c.conn)
	// Tor returns multi-line responses ended with 250 OK
	progress := 0
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return 0, err
		}
		if strings.HasPrefix(line, "250") {
			break
		}
		if strings.Contains(line, "PROGRESS=") {
			// e.g. 250-status/bootstrap-phase=NOTICE HEARTBEAT PROGRESS=100 TAG=done SUMMARY="Done"
			parts := strings.Split(line, " ")
			for _, part := range parts {
				if strings.HasPrefix(part, "PROGRESS=") {
					fmt.Sscanf(part, "PROGRESS=%d", &progress)
				}
			}
		}
	}

	return progress, nil
}

// Close disconnects control port.
func (c *TorController) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
}
