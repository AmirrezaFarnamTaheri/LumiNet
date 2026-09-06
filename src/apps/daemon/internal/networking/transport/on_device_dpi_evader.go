package transport

import (
	"bytes"
	"strings"
	"sync"
)

// DpiEvasionStrategy defines client-side DPI evasion method
type DpiEvasionStrategy int

const (
	StrategySniSplit DpiEvasionStrategy = iota
	StrategyHttpDesync
	StrategyOutOfOrder
	StrategyDecoyTTL
)

// OnDeviceDpiEvader performs local stream evasion
type OnDeviceDpiEvader struct {
	mu           sync.RWMutex
	EvadedCount  uint64
	DefaultSplit int
}

// NewOnDeviceDpiEvader creates a DPI evader
func NewOnDeviceDpiEvader(defaultSplit int) *OnDeviceDpiEvader {
	if defaultSplit <= 0 {
		defaultSplit = 2
	}
	return &OnDeviceDpiEvader{
		DefaultSplit: defaultSplit,
	}
}

// ApplySniSplit splits TLS ClientHello into two fragments
func (e *OnDeviceDpiEvader) ApplySniSplit(clientHello []byte, splitPos int) [][]byte {
	e.mu.Lock()
	e.EvadedCount++
	e.mu.Unlock()

	if len(clientHello) < 5 || clientHello[0] != 0x16 {
		return [][]byte{clientHello}
	}

	if splitPos <= 0 || splitPos >= len(clientHello) {
		splitPos = e.DefaultSplit
	}
	if splitPos >= len(clientHello) {
		splitPos = len(clientHello) / 2
	}

	return [][]byte{
		clientHello[:splitPos],
		clientHello[splitPos:],
	}
}

// ApplyHttpDesync applies header casing and CRLF trick
func (e *OnDeviceDpiEvader) ApplyHttpDesync(request []byte) []byte {
	e.mu.Lock()
	e.EvadedCount++
	e.mu.Unlock()

	lines := strings.Split(string(request), "\r\n")
	var result []string
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				result = append(result, "hOst: "+strings.TrimSpace(parts[1]))
				continue
			}
		}
		result = append(result, line)
	}

	return []byte(strings.Join(result, "\r\n"))
}

// GenerateOutOfOrderChunks divides payload and swaps chunk order
func (e *OnDeviceDpiEvader) GenerateOutOfOrderChunks(data []byte, chunkSize int) [][]byte {
	e.mu.Lock()
	e.EvadedCount++
	e.mu.Unlock()

	if chunkSize <= 0 {
		chunkSize = 16
	}

	var chunks [][]byte
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunks = append(chunks, data[i:end])
	}

	if len(chunks) > 1 {
		chunks[0], chunks[1] = chunks[1], chunks[0]
	}

	return chunks
}

// CraftDecoyPair creates low-TTL decoy packet with XOR mask and real packet
func (e *OnDeviceDpiEvader) CraftDecoyPair(realPayload []byte, decoyTTL byte) (byte, []byte, byte, []byte) {
	e.mu.Lock()
	e.EvadedCount++
	e.mu.Unlock()

	decoy := bytes.Clone(realPayload)
	for i := range decoy {
		decoy[i] ^= 0x55
	}

	return decoyTTL, decoy, 64, realPayload
}
