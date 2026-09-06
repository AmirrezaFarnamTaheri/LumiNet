// SPDX-License-Identifier: MIT
//
// QUIC Initial scanning facade (R2 roadmap wiring). Bridges the Rust
// core's quic::scan passive observer (exposed over FFI as "scan_quic",
// diagnostics pipeline: a completed QUIC ClientHello is fingerprinted
// with the same JA3/JA4 machinery used for TCP TLS handshakes, so QUIC
// and TLS observations share one fingerprint store.

package diagnostics

import (
	"fmt"

	"github.com/maybeknott/luminet/internal/native/bridge"
)

// QuicScanResult is the daemon-facing view of a completed QUIC Initial
// observation. It carries the transport identifier from the QUIC header
// plus the TLS fingerprints computed from the reassembled ClientHello.
type QuicScanResult struct {
	// Addr is the observed client "ip:port".
	Addr string `json:"addr"`
	// NumID is the upstream connection-number id from the QUIC header.
	NumID uint64 `json:"num_id"`
	// HexID is the hex connection id from the QUIC header.
	HexID string `json:"hex_id"`
	// JA3 is the MD5-based JA3 hash of the ClientHello ("" if unavailable).
	JA3 string `json:"ja3,omitempty"`
	// JA4 is the modern JA4 string of the ClientHello ("" if unavailable).
	JA4 string `json:"ja4,omitempty"`
}

// ScanQuicInitial runs a one-shot passive QUIC Initial fingerprint for a
// single UDP datagram and, when it contains a complete ClientHello,
// computes JA3/JA4 over it. serverSide selects the server-direction
// Initial keys (use true when observing a server's Initial response).
// Errors are returned for malformed input or native-core unavailability;
// a nil error with a nil result means "no complete ClientHello in this
// datagram" and is a normal outcome for non-Initial traffic.
func ScanQuicInitial(addr string, datagram []byte, serverSide bool) (*QuicScanResult, error) {
	raw, err := bridge.QuicScan(addr, datagram, serverSide)
	if err != nil {
		return nil, fmt.Errorf("quic scan: %w", err)
	}
	if !raw.Found {
		return nil, nil
	}
	ch, err := raw.ClientHello()
	if err != nil {
		return nil, fmt.Errorf("quic scan: client hello decode: %w", err)
	}
	out := &QuicScanResult{
		Addr:  raw.Addr,
		NumID: raw.NumID,
		HexID: raw.HexID,
	}
	if len(ch) > 0 {
		if ja3, err := JA3HashString(ch); err == nil {
			out.JA3 = ja3
		}
		if ja4, err := JA4HashString(ch); err == nil {
			out.JA4 = ja4
		}
	}
	return out, nil
}
