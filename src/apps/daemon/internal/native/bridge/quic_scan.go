//go:build cgo && !android && !ios

package bridge

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// QuicScanResult mirrors lumicore quic::scan::ScannedQuicClient over FFI.
type QuicScanResult struct {
	// Found is true when the datagram completed a ClientHello-bearing Initial.
	Found bool `json:"found"`
	// Addr is the observed client "ip:port".
	Addr string `json:"addr"`
	// NumID is the upstream NumID from the QUIC header.
	NumID uint64 `json:"num_id"`
	// HexID is the hexadecimal connection id.
	HexID string `json:"hex_id"`
	// ClientHelloHex is the reassembled TLS ClientHello, hex encoded.
	ClientHelloHex string `json:"client_hello_hex"`
}

// ClientHello decodes the hex ClientHello payload into raw bytes.
func (r *QuicScanResult) ClientHello() ([]byte, error) {
	return hex.DecodeString(r.ClientHelloHex)
}

// QuicScan performs a one-shot passive QUIC Initial fingerprint over the
// Rust core (endpoint "scan_quic"). It returns a result even when no
// ClientHello completed (Found=false); an error is returned only for
// malformed input or decrypt/parse failure.
func QuicScan(addr string, datagram []byte, serverSide bool) (*QuicScanResult, error) {
	res, err := dispatchAsync("scan_quic", map[string]interface{}{
		"addr":         addr,
		"datagram_hex": hex.EncodeToString(datagram),
		"server_side":  serverSide,
	}, 5000)
	if err != nil {
		return nil, err
	}
	var out QuicScanResult
	if err := json.Unmarshal([]byte(res), &out); err != nil {
		return nil, fmt.Errorf("scan_quic: bad payload: %w", err)
	}
	return &out, nil
}
