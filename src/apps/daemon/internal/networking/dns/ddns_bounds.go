package dns

import (
	"encoding/json"
	"fmt"
	"io"
)

const maxDDNSAPIResponseBytes int64 = 1 << 20

func decodeBoundedDDNSJSON(r io.Reader, dst any) error {
	body, err := io.ReadAll(io.LimitReader(r, maxDDNSAPIResponseBytes+1))
	if err != nil {
		return err
	}
	if int64(len(body)) > maxDDNSAPIResponseBytes {
		return fmt.Errorf("DDNS provider response exceeds %d bytes", maxDDNSAPIResponseBytes)
	}
	return json.Unmarshal(body, dst)
}
