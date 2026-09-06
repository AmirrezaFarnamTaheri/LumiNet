package transport

import (
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"
)

type SslVpnFrame struct {
	SessionID uint32
	Sequence  uint32
	Payload   []byte
}

func (f *SslVpnFrame) Encode(w io.Writer) error {
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint32(hdr[0:4], 0x53534C56) // 'SSLV'
	binary.BigEndian.PutUint32(hdr[4:8], f.SessionID)
	binary.BigEndian.PutUint32(hdr[8:12], uint32(len(f.Payload)))
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	if len(f.Payload) > 0 {
		_, err := w.Write(f.Payload)
		return err
	}
	return nil
}

func DecodeSslVpnFrame(r io.Reader) (*SslVpnFrame, error) {
	hdr := make([]byte, 12)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	magic := binary.BigEndian.Uint32(hdr[0:4])
	if magic != 0x53534C56 {
		return nil, errors.New("invalid ssl vpn magic header")
	}
	sessionId := binary.BigEndian.Uint32(hdr[4:8])
	payloadLen := binary.BigEndian.Uint32(hdr[8:12])
	if payloadLen > 65536 {
		return nil, errors.New("frame payload exceeds 64KB")
	}
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return &SslVpnFrame{
		SessionID: sessionId,
		Payload:   payload,
	}, nil
}

type NatSessionKey struct {
	SrcIP   [4]byte
	DstIP   [4]byte
	SrcPort uint16
	DstPort uint16
	Proto   uint8
}

type VirtualNatRouter struct {
	mu      sync.Mutex
	table   map[NatSessionKey]time.Time
	timeout time.Duration
}

func NewVirtualNatRouter(timeout time.Duration) *VirtualNatRouter {
	return &VirtualNatRouter{
		table:   make(map[NatSessionKey]time.Time),
		timeout: timeout,
	}
}

func (r *VirtualNatRouter) Touch(key NatSessionKey) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.table[key] = time.Now()
}

func (r *VirtualNatRouter) IsActive(key NatSessionKey) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	ts, exists := r.table[key]
	if !exists {
		return false
	}
	if time.Since(ts) > r.timeout {
		delete(r.table, key)
		return false
	}
	return true
}
