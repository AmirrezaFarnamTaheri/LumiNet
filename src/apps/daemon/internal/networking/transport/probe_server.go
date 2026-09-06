package transport

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
)

type ProbeResponse struct {
	StatusCode int
	Headers    map[string]string
	Body       []byte
}

type EmbeddedProbeServer struct {
	BindHost       string
	BindPort       uint16
	authUsername   string
	authPassword   string
	servedPayloads map[string][]byte
	totalProbes    uint64
	mu             sync.Mutex
}

func NewEmbeddedProbeServer(host string, port uint16) *EmbeddedProbeServer {
	return &EmbeddedProbeServer{
		BindHost:       host,
		BindPort:       port,
		servedPayloads: make(map[string][]byte),
	}
}

func (s *EmbeddedProbeServer) SetAuth(username, password string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authUsername = username
	s.authPassword = password
}

func (s *EmbeddedProbeServer) RegisterPayload(path string, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.servedPayloads[path] = data
}

func (s *EmbeddedProbeServer) HandleRequest(method, path, authHeader, rangeHeader string) ProbeResponse {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.totalProbes++

	headers := map[string]string{
		"Server": "LumiProbe/1.0",
	}

	if s.authUsername != "" {
		expected := fmt.Sprintf("Basic %s:%s", s.authUsername, s.authPassword)
		if authHeader != expected {
			headers["WWW-Authenticate"] = `Basic realm="LumiProbe"`
			return ProbeResponse{
				StatusCode: 401,
				Headers:    headers,
				Body:       []byte("Unauthorized"),
			}
		}
	}

	if path == "/health" || path == "/ping" {
		headers["Content-Type"] = "text/plain"
		return ProbeResponse{
			StatusCode: 200,
			Headers:    headers,
			Body:       []byte("OK"),
		}
	}

	if strings.HasPrefix(path, "/probe/bandwidth") {
		size := 64 * 1024
		buf := make([]byte, size)
		for i := range buf {
			buf[i] = 0x55
		}
		headers["Content-Type"] = "application/octet-stream"
		headers["Content-Length"] = strconv.Itoa(size)
		return ProbeResponse{
			StatusCode: 200,
			Headers:    headers,
			Body:       buf,
		}
	}

	if payload, ok := s.servedPayloads[path]; ok {
		headers["Content-Type"] = "application/octet-stream"
		if strings.HasPrefix(rangeHeader, "bytes=") {
			spec := strings.TrimPrefix(rangeHeader, "bytes=")
			parts := strings.Split(spec, "-")
			if len(parts) == 2 {
				start, _ := strconv.Atoi(parts[0])
				end, err := strconv.Atoi(parts[1])
				if err != nil || end >= len(payload) {
					end = len(payload) - 1
				}
				if start <= end && start < len(payload) {
					slice := payload[start : end+1]
					headers["Content-Range"] = fmt.Sprintf("bytes %d-%d/%d", start, end, len(payload))
					headers["Content-Length"] = strconv.Itoa(len(slice))
					return ProbeResponse{
						StatusCode: 206,
						Headers:    headers,
						Body:       slice,
					}
				}
			}
		}

		headers["Content-Length"] = strconv.Itoa(len(payload))
		return ProbeResponse{
			StatusCode: 200,
			Headers:    headers,
			Body:       payload,
		}
	}

	return ProbeResponse{
		StatusCode: 404,
		Headers:    headers,
		Body:       []byte("Not Found"),
	}
}
