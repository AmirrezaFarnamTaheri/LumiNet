package relayclient

import (
	"bytes"
	"fmt"
)

type TunnelPayload struct {
	SessionID string  `json:"session_id"`
	Target    string  `json:"target,omitempty"`
	Data      []byte  `json:"data,omitempty"`
	Wseq      *uint64 `json:"wseq,omitempty"`
	Seq       *uint64 `json:"seq,omitempty"`
}

type TunnelResponse struct {
	Data  []byte  `json:"data,omitempty"`
	Error string  `json:"error,omitempty"`
	Seq   *uint64 `json:"seq,omitempty"`
}

// validateRelayResponseSequence keeps predecessor relays compatible when they
// omit sequence evidence, but makes correlation fail-closed once they provide
// it. HTTP serverless and GSA relays share this exact wire invariant.
func validateRelayResponseSequence(transport string, expected uint64, actual *uint64) error {
	if actual == nil {
		return nil
	}
	if *actual != expected {
		return fmt.Errorf("%s response sequence mismatch: got %d, want %d", transport, *actual, expected)
	}
	return nil
}

// prependFailedWrite restores a failed transmission ahead of bytes queued while
// it was in flight. bytes.Buffer.Bytes aliases the buffer storage, so pending
// bytes must be copied before Reset/Write can overwrite that storage.
func prependFailedWrite(buf *bytes.Buffer, failed []byte) {
	pending := append([]byte(nil), buf.Bytes()...)
	buf.Reset()
	_, _ = buf.Write(failed)
	_, _ = buf.Write(pending)
}
