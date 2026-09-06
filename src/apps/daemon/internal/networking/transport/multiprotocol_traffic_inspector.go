package transport

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
)

// InspectedProtocol identifies the protocol detected in stream
type InspectedProtocol int

const (
	InspectedProtoUnknown InspectedProtocol = iota
	InspectedProtoRDP
	InspectedProtoSSH
	InspectedProtoTLS
	InspectedProtoHTTP
	InspectedProtoWebSocket
)

// TrafficVerdict indicates permission status
type TrafficVerdict int

const (
	VerdictPermitted TrafficVerdict = iota
	VerdictDenied
	VerdictNeedsMoreData
)

// InspectorPolicy configures permitted protocols
type InspectorPolicy struct {
	AllowRDP   bool
	AllowSSH   bool
	AllowTLS   bool
	AllowHTTP  bool
	EnforceSNI bool
}

// MultiprotocolTrafficInspector performs early stream protocol classification
type MultiprotocolTrafficInspector struct {
	mu             sync.RWMutex
	Policy         InspectorPolicy
	InspectedCount uint64
}

// NewMultiprotocolTrafficInspector creates an inspector instance
func NewMultiprotocolTrafficInspector(policy InspectorPolicy) *MultiprotocolTrafficInspector {
	return &MultiprotocolTrafficInspector{
		Policy: policy,
	}
}

// Inspect analyzes stream preamble bytes
func (ins *MultiprotocolTrafficInspector) Inspect(data []byte) (InspectedProtocol, TrafficVerdict, string) {
	ins.mu.Lock()
	ins.InspectedCount++
	ins.mu.Unlock()

	ins.mu.RLock()
	policy := ins.Policy
	ins.mu.RUnlock()

	if len(data) == 0 {
		return InspectedProtoUnknown, VerdictNeedsMoreData, ""
	}

	// 1. SSH check
	if bytes.HasPrefix(data, []byte("SSH-")) {
		banner := strings.Split(string(data), "\r\n")[0]
		if policy.AllowSSH {
			return InspectedProtoSSH, VerdictPermitted, banner
		}
		return InspectedProtoSSH, VerdictDenied, "SSH prohibited"
	}

	// 2. TLS Handshake check (0x16 0x03 0x01..0x04)
	if len(data) >= 5 && data[0] == 0x16 && data[1] == 0x03 && data[2] <= 0x04 {
		sni := extractTLSSNI(data)
		if policy.EnforceSNI && sni == "" {
			return InspectedProtoTLS, VerdictDenied, "Missing SNI"
		}
		if policy.AllowTLS {
			return InspectedProtoTLS, VerdictPermitted, sni
		}
		return InspectedProtoTLS, VerdictDenied, "TLS prohibited"
	}

	// 3. RDP TPKT header check (0x03 0x00 ...)
	if len(data) >= 4 && data[0] == 0x03 && data[1] == 0x00 {
		tpktLen := binary.BigEndian.Uint16(data[2:4])
		if policy.AllowRDP {
			return InspectedProtoRDP, VerdictPermitted, fmt.Sprintf("TPKT-%d", tpktLen)
		}
		return InspectedProtoRDP, VerdictDenied, "RDP prohibited"
	}

	// 4. HTTP / WebSocket check
	if bytes.HasPrefix(data, []byte("GET ")) ||
		bytes.HasPrefix(data, []byte("POST ")) ||
		bytes.HasPrefix(data, []byte("CONNECT ")) ||
		bytes.HasPrefix(data, []byte("HEAD ")) {
		str := string(data)
		isWS := strings.Contains(strings.ToLower(str), "upgrade: websocket")
		proto := InspectedProtoHTTP
		if isWS {
			proto = InspectedProtoWebSocket
		}

		if policy.AllowHTTP {
			return proto, VerdictPermitted, ""
		}
		return proto, VerdictDenied, "HTTP prohibited"
	}

	if len(data) < 8 {
		return InspectedProtoUnknown, VerdictNeedsMoreData, ""
	}

	return InspectedProtoUnknown, VerdictDenied, "Unknown protocol"
}

func extractTLSSNI(data []byte) string {
	if len(data) < 43 || data[5] != 0x01 {
		return ""
	}
	cursor := 43
	if cursor >= len(data) {
		return ""
	}

	// Session ID
	sessionIDLen := int(data[cursor])
	cursor += 1 + sessionIDLen
	if cursor+2 > len(data) {
		return ""
	}

	// Cipher Suites
	cipherLen := int(binary.BigEndian.Uint16(data[cursor : cursor+2]))
	cursor += 2 + cipherLen
	if cursor+1 > len(data) {
		return ""
	}

	// Compression
	compLen := int(data[cursor])
	cursor += 1 + compLen
	if cursor+2 > len(data) {
		return ""
	}

	// Extensions
	extLen := int(binary.BigEndian.Uint16(data[cursor : cursor+2]))
	cursor += 2
	extEnd := cursor + extLen
	if extEnd > len(data) {
		extEnd = len(data)
	}

	for cursor+4 <= extEnd {
		extType := binary.BigEndian.Uint16(data[cursor : cursor+2])
		extDataLen := int(binary.BigEndian.Uint16(data[cursor+2 : cursor+4]))
		cursor += 4

		if extType == 0x0000 && cursor+5 <= extEnd { // SNI
			nameType := data[cursor+2]
			nameLen := int(binary.BigEndian.Uint16(data[cursor+3 : cursor+5]))
			if nameType == 0 && cursor+5+nameLen <= extEnd {
				return string(data[cursor+5 : cursor+5+nameLen])
			}
		}
		cursor += extDataLen
	}

	return ""
}
