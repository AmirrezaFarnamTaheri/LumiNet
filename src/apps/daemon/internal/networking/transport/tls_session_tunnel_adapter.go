package transport

import (
	"crypto/rand"
	"errors"
	"sync"
	"time"
)

// TlsSessionTicket holds cached TLS 1.3 session resumption data
type TlsSessionTicket struct {
	TicketID     string
	ServerName   string
	MasterSecret []byte
	MaxEarlyData uint32
	ExpiresAt    time.Time
}

// TlsSessionTunnelAdapter manages 0-RTT TLS session resumption and ticket caching
type TlsSessionTunnelAdapter struct {
	ticketStore map[string]TlsSessionTicket // serverName -> TlsSessionTicket
	mu          sync.RWMutex
}

// NewTlsSessionTunnelAdapter creates a new session adapter
func NewTlsSessionTunnelAdapter() *TlsSessionTunnelAdapter {
	return &TlsSessionTunnelAdapter{
		ticketStore: make(map[string]TlsSessionTicket),
	}
}

// StoreTicket saves a session ticket for a server
func (a *TlsSessionTunnelAdapter) StoreTicket(serverName string, ticketID string, masterSecret []byte, maxEarlyData uint32, ttl time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.ticketStore[serverName] = TlsSessionTicket{
		TicketID:     ticketID,
		ServerName:   serverName,
		MasterSecret: masterSecret,
		MaxEarlyData: maxEarlyData,
		ExpiresAt:    time.Now().Add(ttl),
	}
}

// RetrieveTicket fetches a valid session ticket if not expired
func (a *TlsSessionTunnelAdapter) RetrieveTicket(serverName string) (TlsSessionTicket, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	ticket, exists := a.ticketStore[serverName]
	if !exists {
		return TlsSessionTicket{}, false
	}
	if time.Now().After(ticket.ExpiresAt) {
		return TlsSessionTicket{}, false
	}
	return ticket, true
}

// FrameEarlyData wraps 0-RTT early data with ticket ID and length prefix
func (a *TlsSessionTunnelAdapter) FrameEarlyData(ticketID string, payload []byte) ([]byte, error) {
	if len(ticketID) == 0 {
		return nil, errors.New("ticket ID cannot be empty")
	}
	tBytes := []byte(ticketID)
	if len(tBytes) > 255 {
		return nil, errors.New("ticket ID exceeds max length of 255")
	}

	var frame []byte
	frame = append(frame, byte(len(tBytes)))
	frame = append(frame, tBytes...)

	pLen := len(payload)
	frame = append(frame, byte(pLen>>8), byte(pLen&0xFF))
	frame = append(frame, payload...)
	return frame, nil
}

// UnframeEarlyData extracts ticket ID and payload from 0-RTT frame
func (a *TlsSessionTunnelAdapter) UnframeEarlyData(data []byte) (string, []byte, error) {
	if len(data) < 3 {
		return "", nil, errors.New("frame too short")
	}
	tLen := int(data[0])
	if len(data) < 1+tLen+2 {
		return "", nil, errors.New("incomplete header")
	}
	ticketID := string(data[1 : 1+tLen])
	pLen := (int(data[1+tLen]) << 8) | int(data[2+tLen])
	start := 3 + tLen
	if len(data) < start+pLen {
		return "", nil, errors.New("payload length truncated")
	}
	payload := data[start : start+pLen]
	return ticketID, payload, nil
}

// GenerateRandomTicketID creates a simulated ticket identifier
func GenerateRandomTicketID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	const hexChars = "0123456789abcdef"
	res := make([]byte, 32)
	for i, v := range b {
		res[i*2] = hexChars[v>>4]
		res[i*2+1] = hexChars[v&0x0F]
	}
	return string(res)
}
