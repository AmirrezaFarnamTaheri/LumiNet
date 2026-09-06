//go:build !cgo || android || ios

package bridge

import (
	"encoding/hex"
	"fmt"
)

// QuicScanResult mirrors lumicore quic::scan::ScannedQuicClient. See the
// cgo variant for full documentation.
type QuicScanResult struct {
	Found          bool   `json:"found"`
	Addr           string `json:"addr"`
	NumID          uint64 `json:"num_id"`
	HexID          string `json:"hex_id"`
	ClientHelloHex string `json:"client_hello_hex"`
}

// ClientHello decodes the hex ClientHello payload into raw bytes.
func (r *QuicScanResult) ClientHello() ([]byte, error) {
	return hex.DecodeString(r.ClientHelloHex)
}

// QuicScan requires the native core; pure-Go degraded builds cannot decrypt
// QUIC Initial packets and must not pretend to.
func QuicScan(string, []byte, bool) (*QuicScanResult, error) {
	return nil, fmt.Errorf("%w: QUIC scan", ErrNativeCoreUnavailable)
}
