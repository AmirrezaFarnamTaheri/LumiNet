package runtimecore

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type Ikev2Proposal struct {
	Encryption   string `json:"encryption"`
	Integrity    string `json:"integrity"`
	DhGroup      string `json:"dh_group"`
	PfsGroup     string `json:"pfs_group"`
	LifetimeSecs uint32 `json:"lifetime_secs"`
}

func DefaultIkev2Proposal() Ikev2Proposal {
	return Ikev2Proposal{
		Encryption:   "aes256gcm128",
		Integrity:    "sha256",
		DhGroup:      "modp2048",
		PfsGroup:     "modp2048",
		LifetimeSecs: 3600,
	}
}

type IpsecProfile struct {
	ServerEndpoint net.IP        `json:"server_endpoint"`
	ServerPort     uint16        `json:"server_port"`
	PskHex         string        `json:"psk_hex"`
	LeftId         string        `json:"left_id"`
	RightId        string        `json:"right_id"`
	Proposal       Ikev2Proposal `json:"proposal"`
	NatKeepaliveSec uint32       `json:"nat_keepalive_sec"`
}

func NewIpsecProfile(server net.IP, leftId, rightId string) (*IpsecProfile, error) {
	if server == nil {
		return nil, errors.New("invalid server ip")
	}
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		return nil, err
	}
	return &IpsecProfile{
		ServerEndpoint:  server,
		ServerPort:      500,
		PskHex:          hex.EncodeToString(psk),
		LeftId:          leftId,
		RightId:         rightId,
		Proposal:        DefaultIkev2Proposal(),
		NatKeepaliveSec: 20,
	}, nil
}

func (p *IpsecProfile) GenerateSwanctlConf() string {
	var b strings.Builder
	b.WriteString("connections {\n")
	b.WriteString(fmt.Sprintf("  lumi-%s {\n", p.LeftId))
	b.WriteString(fmt.Sprintf("    remote_addrs = %s\n", p.ServerEndpoint.String()))
	b.WriteString("    vips = 0.0.0.0,::\n")
	b.WriteString("    local {\n")
	b.WriteString("      auth = psk\n")
	b.WriteString(fmt.Sprintf("      id = %s\n", p.LeftId))
	b.WriteString("    }\n")
	b.WriteString("    remote {\n")
	b.WriteString("      auth = psk\n")
	b.WriteString(fmt.Sprintf("      id = %s\n", p.RightId))
	b.WriteString("    }\n")
	b.WriteString("    children {\n")
	b.WriteString("      net {\n")
	b.WriteString("        remote_ts = 0.0.0.0/0,::/0\n")
	b.WriteString(fmt.Sprintf("        esp_proposals = %s-%s-%s\n", p.Proposal.Encryption, p.Proposal.Integrity, p.Proposal.PfsGroup))
	b.WriteString("        start_action = start\n")
	b.WriteString("      }\n")
	b.WriteString("    }\n")
	b.WriteString("  }\n")
	b.WriteString("}\n")
	return b.String()
}

type NatTKeepaliveDaemon struct {
	mu       sync.Mutex
	stopCh   chan struct{}
	running  bool
	interval time.Duration
}

func NewNatTKeepaliveDaemon(intervalSec uint32) *NatTKeepaliveDaemon {
	if intervalSec == 0 {
		intervalSec = 20
	}
	return &NatTKeepaliveDaemon{
		interval: time.Duration(intervalSec) * time.Second,
	}
}

func (d *NatTKeepaliveDaemon) Start(conn *net.UDPConn) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.running {
		return errors.New("daemon already running")
	}
	d.stopCh = make(chan struct{})
	d.running = true

	go func() {
		ticker := time.NewTicker(d.interval)
		defer ticker.Stop()
		natKeepalivePayload := []byte{0xff}

		for {
			select {
			case <-d.stopCh:
				return
			case <-ticker.C:
				if conn != nil {
					_ = conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
					_, _ = conn.Write(natKeepalivePayload)
				}
			}
		}
	}()
	return nil
}

func (d *NatTKeepaliveDaemon) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.running {
		close(d.stopCh)
		d.running = false
	}
}
