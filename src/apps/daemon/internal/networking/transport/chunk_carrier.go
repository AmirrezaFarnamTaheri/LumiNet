package transport

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var (
	ErrIncompleteChunk   = errors.New("incomplete chunk")
	ErrInvalidChunkFrame = errors.New("invalid chunk frame")
)

type HttpChunkCarrier struct {
	Host      string
	Path      string
	SessionID string
}

func NewHttpChunkCarrier(host, path, sessionID string) *HttpChunkCarrier {
	return &HttpChunkCarrier{
		Host:      host,
		Path:      path,
		SessionID: sessionID,
	}
}

func (c *HttpChunkCarrier) CreateUplinkHeader() []byte {
	return []byte(fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\nX-Session-ID: %s\r\nConnection: keep-alive\r\n\r\n",
		c.Path, c.Host, c.SessionID))
}

func EncodeChunk(payload []byte) []byte {
	hexLen := fmt.Sprintf("%x", len(payload))
	var buf bytes.Buffer
	buf.WriteString(hexLen)
	buf.WriteString("\r\n")
	buf.Write(payload)
	buf.WriteString("\r\n")
	return buf.Bytes()
}

func EncodeTerminalChunk() []byte {
	return []byte("0\r\n\r\n")
}

func DecodeChunk(data []byte) ([]byte, int, error) {
	crlf := []byte("\r\n")
	idx := bytes.Index(data, crlf)
	if idx < 0 {
		return nil, 0, ErrIncompleteChunk
	}

	hexStr := strings.TrimSpace(string(data[:idx]))
	chunkSize, err := strconv.ParseInt(hexStr, 16, 64)
	if err != nil {
		return nil, 0, ErrInvalidChunkFrame
	}

	dataStart := idx + 2
	dataEnd := dataStart + int(chunkSize)
	totalChunkLen := dataEnd + 2

	if len(data) < totalChunkLen {
		return nil, 0, ErrIncompleteChunk
	}

	if !bytes.Equal(data[dataEnd:totalChunkLen], crlf) {
		return nil, 0, ErrInvalidChunkFrame
	}

	payload := make([]byte, chunkSize)
	copy(payload, data[dataStart:dataEnd])
	return payload, totalChunkLen, nil
}
