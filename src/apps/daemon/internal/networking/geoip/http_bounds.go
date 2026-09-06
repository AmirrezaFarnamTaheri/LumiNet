package geoip

import (
	"encoding/json"
	"fmt"
	"io"
)

const maxGeoIPResponseBytes int64 = 64 << 10

func decodeBoundedGeoIPJSON(r io.Reader, dst any) error {
	body, err := io.ReadAll(io.LimitReader(r, maxGeoIPResponseBytes+1))
	if err != nil {
		return err
	}
	if int64(len(body)) > maxGeoIPResponseBytes {
		return fmt.Errorf("geoip provider response exceeds %d bytes", maxGeoIPResponseBytes)
	}
	return json.Unmarshal(body, dst)
}
