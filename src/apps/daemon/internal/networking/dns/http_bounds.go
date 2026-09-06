package dns

import (
	"fmt"
	"io"
)

// maxDNSHTTPBodyBytes is the largest DNS wire message accepted from or sent
// through an HTTP transport. DNS-over-TCP uses a 16-bit length prefix, so a
// larger HTTP body cannot represent one DNS message and is rejected before it
// can allocate unbounded memory.
const maxDNSHTTPBodyBytes int64 = 65535

func readBoundedDNSBody(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxDNSHTTPBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxDNSHTTPBodyBytes {
		return nil, fmt.Errorf("DNS HTTP body exceeds %d bytes", maxDNSHTTPBodyBytes)
	}
	return body, nil
}
