package proxy

import (
	"fmt"
	"io"
)

const (
	maxProxyDNSHTTPBodyBytes       int64 = 65535
	maxProxyControlHTTPBodyBytes   int64 = 1 << 20
	maxCovertEncodedChunkBodyBytes int64 = 16 << 20
	maxCovertRawChunkBytes               = 10 << 20
)

func readBoundedProxyHTTPBody(r io.Reader, limit int64, label string) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", label, limit)
	}
	return body, nil
}
