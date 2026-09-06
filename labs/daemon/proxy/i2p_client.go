// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: i2p.i2p-master
// Target path: server/internal/proxy/i2p_client.go

package proxy

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// I2PClient manages the lifecycle and connections to the local I2P router via the SAM bridge protocol.
type I2PClient struct {
	mu          sync.RWMutex
	SAMAddress  string
	SessionName string
	running     bool
}

// NewI2PClient instantiates a new I2PClient.
func NewI2PClient() *I2PClient {
	return &I2PClient{
		SAMAddress:  "127.0.0.1:7656", // Default I2P SAM bridge port
		SessionName: "luminet-session",
	}
}

// DialSAM performs SAM handshake negotiation and returns the negotiated socket.
func (i *I2PClient) DialSAM() (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", i.SAMAddress, 5*time.Second)
	if err != nil {
		return nil, err
	}

	// 1. Send HELLO message
	_, err = fmt.Fprint(conn, "HELLO VERSION MIN=3.0 MAX=3.1\n")
	if err != nil {
		conn.Close()
		return nil, err
	}

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, err
	}

	if !strings.Contains(line, "RESULT=OK") {
		conn.Close()
		return nil, fmt.Errorf("I2P SAM negotiation failed: %s", strings.TrimSpace(line))
	}

	return conn, nil
}

// GenerateDestination creates a new I2P destination keypair.
func (i *I2PClient) GenerateDestination() (string, error) {
	conn, err := i.DialSAM()
	if err != nil {
		return "", err
	}
	defer conn.Close()

	_, err = fmt.Fprint(conn, "DEST GENERATE\n")
	if err != nil {
		return "", err
	}

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}

	parts := strings.Split(strings.TrimSpace(line), " ")
	for _, part := range parts {
		if strings.HasPrefix(part, "PUB=") {
			return part[4:], nil
		}
	}

	return "", fmt.Errorf("invalid DEST response: %s", line)
}

// Connect implements the legacy entry trigger.
func (i *I2PClient) Connect() {
	// Diagnostic stub
}
