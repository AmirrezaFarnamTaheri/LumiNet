package transport

import (
	"bytes"
	"strings"
	"sync"
)

type SessionTicket struct {
	ServerName     string
	TicketBytes    []byte
	ALPN           string
	ExpiresAtUnix  int64
}

type ZeroRttSessionCache struct {
	mu             sync.Mutex
	tickets        map[string]*SessionTicket
	consumedNonces map[string]struct{}
}

func NewZeroRttSessionCache() *ZeroRttSessionCache {
	return &ZeroRttSessionCache{
		tickets:        make(map[string]*SessionTicket),
		consumedNonces: make(map[string]struct{}),
	}
}

func (c *ZeroRttSessionCache) StoreTicket(serverName string, ticket []byte, alpn string, nowUnix, ttlSecs int64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := strings.ToLower(serverName)
	c.tickets[key] = &SessionTicket{
		ServerName:    serverName,
		TicketBytes:   bytes.Clone(ticket),
		ALPN:          alpn,
		ExpiresAtUnix: nowUnix + ttlSecs,
	}
}

func (c *ZeroRttSessionCache) GetValidTicket(serverName string, nowUnix int64) *SessionTicket {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := strings.ToLower(serverName)
	t, ok := c.tickets[key]
	if !ok {
		return nil
	}

	if t.ExpiresAtUnix > nowUnix {
		cp := *t
		cp.TicketBytes = bytes.Clone(t.TicketBytes)
		return &cp
	}

	delete(c.tickets, key)
	return nil
}

func (c *ZeroRttSessionCache) CheckAndConsumeNonce(nonce []byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := string(nonce)
	if _, exists := c.consumedNonces[key]; exists {
		return false
	}
	c.consumedNonces[key] = struct{}{}
	return true
}
