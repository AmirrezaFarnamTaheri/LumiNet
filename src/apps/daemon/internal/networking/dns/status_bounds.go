package dns

import (
	"fmt"
	"io"
)

const maxDDNSStatusBodyBytes int64 = 8 << 10

func readBoundedDDNSStatus(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxDDNSStatusBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxDDNSStatusBodyBytes {
		return nil, fmt.Errorf("DDNS status response exceeds %d bytes", maxDDNSStatusBodyBytes)
	}
	return body, nil
}
