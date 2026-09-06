package relayclient

import (
	"bytes"
	"fmt"
	"io"
	"strings"
)

const maxRelayControlResponseBytes int64 = 1 << 20

func readBoundedRelayControlResponse(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxRelayControlResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxRelayControlResponseBytes {
		return nil, fmt.Errorf("relay control response exceeds %d bytes", maxRelayControlResponseBytes)
	}
	return body, nil
}

// relayControlDecodeError preserves ambiguity instead of guessing why an
// upstream relay returned a non-JSON control body. HTML is a useful distinct
// signal (deployment/auth/quota/edge pages can all produce it), but it is not
// sufficient evidence to attribute a single cause.
func relayControlDecodeError(contentType string, body []byte, decodeErr error) error {
	trimmed := bytes.TrimSpace(bytes.TrimPrefix(body, []byte{0xef, 0xbb, 0xbf}))
	lower := bytes.ToLower(trimmed)
	html := strings.Contains(strings.ToLower(contentType), "text/html") || bytes.HasPrefix(lower, []byte("<!doctype html")) || bytes.HasPrefix(lower, []byte("<html"))
	if html {
		return fmt.Errorf("relay returned HTML instead of JSON control data; possible deployment, authentication, quota, or intermediary response; cause is ambiguous: %w", decodeErr)
	}
	return fmt.Errorf("relay returned invalid JSON control data: %w", decodeErr)
}
