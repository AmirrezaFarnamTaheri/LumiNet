package transport

import (
	"strings"
	"unicode"
)

type TcpChunkSplitter struct{}

func NewTcpChunkSplitter() *TcpChunkSplitter {
	return &TcpChunkSplitter{}
}

func (s *TcpChunkSplitter) SplitBytes(data []byte, chunkSize int) [][]byte {
	if chunkSize <= 0 || len(data) == 0 {
		return [][]byte{data}
	}
	var chunks [][]byte
	for offset := 0; offset < len(data); offset += chunkSize {
		end := offset + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunks = append(chunks, data[offset:end])
	}
	return chunks
}

func (s *TcpChunkSplitter) MutateHeaderCase(headerLine string) string {
	parts := strings.SplitN(headerLine, ":", 2)
	if len(parts) != 2 {
		return headerLine
	}
	key := parts[0]
	var mutated strings.Builder
	for i, r := range key {
		if i%2 == 0 {
			mutated.WriteRune(unicode.ToLower(r))
		} else {
			mutated.WriteRune(unicode.ToUpper(r))
		}
	}
	mutated.WriteString(":")
	mutated.WriteString(parts[1])
	return mutated.String()
}
