package security

import (
	"encoding/base32"
	"fmt"
	"strings"
	"sync"
)

// DnsArqMessage holds an sequenced chunk of DNS tunneled payload.
type DnsArqMessage struct {
	SeqID   uint16
	IsLast  bool
	Payload []byte
}

// DnsArqWindowBuffer manages sliding window assembly of DNS chunks.
type DnsArqWindowBuffer struct {
	mu       sync.Mutex
	window   map[uint16][]byte
	nextSeq  uint16
	isDone   bool
}

// NewDnsArqWindowBuffer creates an empty sliding window buffer.
func NewDnsArqWindowBuffer() *DnsArqWindowBuffer {
	return &DnsArqWindowBuffer{
		window: make(map[uint16][]byte),
	}
}

// EncodeArqQuery encodes an ARQ frame into a sub-domain label query string.
func EncodeArqQuery(rootDomain string, seq uint16, isLast bool, chunk []byte) string {
	var flag byte = 0
	if isLast {
		flag = 1
	}
	header := []byte{byte(seq >> 8), byte(seq & 0xff), flag}
	data := append(header, chunk...)
	encoded := strings.ToLower(base32.HexEncoding.WithPadding(base32.NoPadding).EncodeToString(data))
	return fmt.Sprintf("%s.%s", encoded, rootDomain)
}

// DecodeArqQuery parses a DNS query label back into an ARQ chunk.
func DecodeArqQuery(query, rootDomain string) (*DnsArqMessage, error) {
	suffix := "." + rootDomain
	if !strings.HasSuffix(query, suffix) {
		return nil, fmt.Errorf("domain does not match root: %s", query)
	}

	label := strings.TrimSuffix(query, suffix)
	data, err := base32.HexEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(label))
	if err != nil {
		return nil, fmt.Errorf("invalid base32 hex label: %w", err)
	}

	if len(data) < 3 {
		return nil, fmt.Errorf("data too short for arq header")
	}

	seq := (uint16(data[0]) << 8) | uint16(data[1])
	isLast := data[2] == 1
	payload := data[3:]

	return &DnsArqMessage{
		SeqID:   seq,
		IsLast:  isLast,
		Payload: payload,
	}, nil
}

// IngestChunk inserts a chunk into the window buffer.
func (b *DnsArqWindowBuffer) IngestChunk(msg *DnsArqMessage) ([]byte, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.window[msg.SeqID] = msg.Payload
	if msg.IsLast {
		b.isDone = true
	}

	// Try assembling in order
	var assembled []byte
	cur := b.nextSeq
	for {
		chunk, exists := b.window[cur]
		if !exists {
			break
		}
		assembled = append(assembled, chunk...)
		cur++
	}

	if b.isDone && cur > msg.SeqID {
		return assembled, true
	}
	return nil, false
}
