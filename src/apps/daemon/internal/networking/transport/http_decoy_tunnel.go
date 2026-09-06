// Copyright 2024-2026 LumiNet Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package transport

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DecoyAction defines the tunnel protocol action.
type DecoyAction string

const (
	// ActionOpen requests the creation of a new target destination connection.
	ActionOpen DecoyAction = "open"
	// ActionRequest executes a single-roundtrip forwarded HTTP request.
	ActionRequest DecoyAction = "request"
	// ActionSend streams payload chunks to an established session.
	ActionSend DecoyAction = "send"
	// ActionRecv polls available returned chunks from an established session.
	ActionRecv DecoyAction = "recv"
	// ActionClose releases and terminates an established session.
	ActionClose DecoyAction = "close"
)

// ParseDecoyAction converts a string to a DecoyAction.
func ParseDecoyAction(s string) (DecoyAction, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "open":
		return ActionOpen, nil
	case "request":
		return ActionRequest, nil
	case "send":
		return ActionSend, nil
	case "recv":
		return ActionRecv, nil
	case "close":
		return ActionClose, nil
	default:
		if s == "" {
			return "", errors.New("empty decoy action")
		}
		return DecoyAction(strings.ToLower(strings.TrimSpace(s))), nil
	}
}

// DecoyTunnelConfig holds settings for HTTP decoy tunnel framing and encryption.
type DecoyTunnelConfig struct {
	Token           string        `json:"token"`
	FakeURLs        []string      `json:"fake_urls"`
	Methods         []string      `json:"methods"`
	Endpoints       []string      `json:"endpoints"`
	UserAgent       string        `json:"user_agent"`
	HTTPVersion     string        `json:"http_version"`
	BufferSize      int           `json:"buffer_size"`
	ConnectionReuse bool          `json:"connection_reuse"`
	TunnelEnable    bool          `json:"tunnel_enable"`
	Timeout         time.Duration `json:"timeout"`
	PullTimeout     time.Duration `json:"pull_timeout"`
}

// DefaultDecoyTunnelConfig returns default settings matching standard decoy tunnel behavior.
func DefaultDecoyTunnelConfig() *DecoyTunnelConfig {
	return &DecoyTunnelConfig{
		Token: "af445adb-2434-4975-9445-2c1b2231",
		FakeURLs: []string{
			"nipo.ciron.net",
			"sudoer.ir",
			"sudoer.net",
			"google.com",
			"cloudflare.com",
		},
		Methods: []string{
			"GET",
			"POST",
			"PUT",
			"DELETE",
		},
		Endpoints: []string{
			"api",
			"login",
			"user",
			"update",
		},
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
		HTTPVersion:     "1.1",
		BufferSize:      65536,
		ConnectionReuse: true,
		TunnelEnable:    false,
		Timeout:         10 * time.Second,
		PullTimeout:     1 * time.Millisecond,
	}
}

// DeriveKey produces a 32-byte AES key from the configured token.
func (c *DecoyTunnelConfig) DeriveKey() [32]byte {
	tokenBytes := []byte(c.Token)
	if len(tokenBytes) == 32 {
		var key [32]byte
		copy(key[:], tokenBytes)
		return key
	}
	return sha256.Sum256(tokenBytes)
}

// CleanHostHeader strips protocol schemes and path suffixes from a fake URL.
func (c *DecoyTunnelConfig) CleanHostHeader(fakeURL string) string {
	host := fakeURL
	if idx := strings.Index(host, "://"); idx != -1 {
		host = host[idx+3:]
	}
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}
	return host
}

// SelectFakeURL selects a fake URL deterministically using an index seed.
func (c *DecoyTunnelConfig) SelectFakeURL(seed int) string {
	if len(c.FakeURLs) == 0 {
		return "cloudflare.com"
	}
	idx := seed % len(c.FakeURLs)
	if idx < 0 {
		idx = -idx
	}
	return c.FakeURLs[idx]
}

// SelectMethod selects an HTTP method deterministically using an index seed.
func (c *DecoyTunnelConfig) SelectMethod(seed int) string {
	if len(c.Methods) == 0 {
		return "POST"
	}
	idx := seed % len(c.Methods)
	if idx < 0 {
		idx = -idx
	}
	return c.Methods[idx]
}

// SelectEndpoint selects an endpoint deterministically using an index seed.
func (c *DecoyTunnelConfig) SelectEndpoint(seed int) string {
	if len(c.Endpoints) == 0 {
		return "api"
	}
	idx := seed % len(c.Endpoints)
	if idx < 0 {
		idx = -idx
	}
	return c.Endpoints[idx]
}

// DecoyEnvelope handles AES-256-CBC encryption with PKCS#7 padding and hex/base64 transforms.
type DecoyEnvelope struct{}

// Encrypt encrypts plaintext with AES-256-CBC and PKCS#7 padding.
// Prepend 16-byte random IV: [16-byte IV][Ciphertext].
func (DecoyEnvelope) Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher creation failed: %w", err)
	}

	blockSize := block.BlockSize()
	padLen := blockSize - (len(plaintext) % blockSize)
	padded := make([]byte, len(plaintext)+padLen)
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}

	iv := make([]byte, blockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("failed to generate random IV: %w", err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(padded))
	mode.CryptBlocks(ciphertext, padded)

	output := make([]byte, 0, len(iv)+len(ciphertext))
	output = append(output, iv...)
	output = append(output, ciphertext...)
	return output, nil
}

// Decrypt decrypts [16-byte IV][Ciphertext] with AES-256-CBC and strips PKCS#7 padding.
func (DecoyEnvelope) Decrypt(dataWithIV []byte, key []byte) ([]byte, error) {
	if len(dataWithIV) < 32 {
		return nil, errors.New("ciphertext too short: minimum 32 bytes required")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher creation failed: %w", err)
	}

	blockSize := block.BlockSize()
	iv := dataWithIV[:blockSize]
	ciphertext := dataWithIV[blockSize:]

	if len(ciphertext)%blockSize != 0 {
		return nil, errors.New("ciphertext length is not a multiple of block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plainPadded := make([]byte, len(ciphertext))
	mode.CryptBlocks(plainPadded, ciphertext)

	// Validate and strip PKCS#7 padding
	padLen := int(plainPadded[len(plainPadded)-1])
	if padLen == 0 || padLen > blockSize || padLen > len(plainPadded) {
		return nil, errors.New("invalid pkcs7 padding")
	}
	for i := len(plainPadded) - padLen; i < len(plainPadded); i++ {
		if plainPadded[i] != byte(padLen) {
			return nil, errors.New("inconsistent pkcs7 padding")
		}
	}

	return plainPadded[:len(plainPadded)-padLen], nil
}

// DecoyRequest holds parsed HTTP decoy request fields.
type DecoyRequest struct {
	Method        string
	Path          string
	Version       string
	Host          string
	UserAgent     string
	SessionID     string
	Action        DecoyAction
	ContentLength int
	KeepAlive     bool
	Headers       map[string]string
	RawBody       []byte
}

// DecoyResponse holds parsed HTTP decoy response fields.
type DecoyResponse struct {
	Version       string
	StatusCode    int
	StatusText    string
	ContentLength int
	KeepAlive     bool
	Headers       map[string]string
	RawBody       []byte
}

// DecoyAgent encodes client-side decoy HTTP requests and parses server responses.
type DecoyAgent struct {
	config   *DecoyTunnelConfig
	envelope DecoyEnvelope
}

// NewDecoyAgent creates a new agent instance.
func NewDecoyAgent(config *DecoyTunnelConfig) *DecoyAgent {
	if config == nil {
		config = DefaultDecoyTunnelConfig()
	}
	return &DecoyAgent{
		config:   config,
		envelope: DecoyEnvelope{},
	}
}

// EncodeRequest packages inner payload into an obfuscated decoy HTTP request.
func (a *DecoyAgent) EncodeRequest(sessionID string, action DecoyAction, innerPayload []byte, seed int) ([]byte, error) {
	key := a.config.DeriveKey()

	// 1. Convert raw payload to hex
	hexStr := hex.EncodeToString(innerPayload)

	// 2. Encrypt hex bytes with AES-256-CBC
	encrypted, err := a.envelope.Encrypt([]byte(hexStr), key[:])
	if err != nil {
		return nil, fmt.Errorf("decoy request encryption failed: %w", err)
	}

	// 3. Base64 encode ciphertext
	b64Body := base64.StdEncoding.EncodeToString(encrypted)

	fakeURL := a.config.SelectFakeURL(seed)
	hostHeader := a.config.CleanHostHeader(fakeURL)
	method := a.config.SelectMethod(seed)
	endpoint := a.config.SelectEndpoint(seed)

	conn := "close"
	if a.config.ConnectionReuse || action == ActionOpen {
		conn = "keep-alive"
	}

	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("%s /%s HTTP/%s\r\n", method, endpoint, a.config.HTTPVersion))
	buf.WriteString(fmt.Sprintf("Host: %s\r\n", hostHeader))
	buf.WriteString(fmt.Sprintf("User-Agent: %s\r\n", a.config.UserAgent))
	buf.WriteString("Accept: */*\r\n")
	buf.WriteString("Content-Type: application/text\r\n")
	buf.WriteString(fmt.Sprintf("X-Nipo-Session: %s\r\n", sessionID))
	buf.WriteString(fmt.Sprintf("X-Nipo-Action: %s\r\n", string(action)))
	buf.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(b64Body)))
	buf.WriteString(fmt.Sprintf("Connection: %s\r\n", conn))
	buf.WriteString("\r\n")
	buf.WriteString(b64Body)

	return buf.Bytes(), nil
}

// DecodeResponse parses and decrypts an HTTP response received from the decoy server.
func (a *DecoyAgent) DecodeResponse(rawHTTP []byte) (*DecoyResponse, []byte, error) {
	headerEnd := bytes.Index(rawHTTP, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		return nil, nil, errors.New("incomplete http response: missing header terminator")
	}

	headerPart := string(rawHTTP[:headerEnd])
	bodyPart := rawHTTP[headerEnd+4:]

	lines := strings.Split(headerPart, "\r\n")
	if len(lines) == 0 {
		return nil, nil, errors.New("empty http response")
	}

	statusParts := strings.Fields(lines[0])
	if len(statusParts) < 2 {
		return nil, nil, fmt.Errorf("invalid http status line: %s", lines[0])
	}

	version := strings.TrimPrefix(statusParts[0], "HTTP/")
	statusCode, err := strconv.Atoi(statusParts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("invalid status code: %w", err)
	}
	statusText := ""
	if len(statusParts) > 2 {
		statusText = strings.Join(statusParts[2:], " ")
	}

	headers := make(map[string]string)
	contentLength := 0
	keepAlive := true

	for _, line := range lines[1:] {
		if idx := strings.Index(line, ":"); idx != -1 {
			name := strings.ToLower(strings.TrimSpace(line[:idx]))
			val := strings.TrimSpace(line[idx+1:])
			headers[name] = val

			switch name {
			case "content-length":
				if cl, err := strconv.Atoi(val); err == nil {
					contentLength = cl
				}
			case "connection":
				keepAlive = strings.Contains(strings.ToLower(val), "keep-alive")
			}
		}
	}

	actualBody := bodyPart
	if contentLength > 0 && len(bodyPart) > contentLength {
		actualBody = bodyPart[:contentLength]
	}

	var decrypted []byte
	if len(actualBody) > 0 {
		key := a.config.DeriveKey()
		dec, err := a.envelope.Decrypt(actualBody, key[:])
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decrypt response body: %w", err)
		}
		decrypted = dec
	}

	resp := &DecoyResponse{
		Version:       version,
		StatusCode:    statusCode,
		StatusText:    statusText,
		ContentLength: contentLength,
		KeepAlive:     keepAlive,
		Headers:       headers,
		RawBody:       actualBody,
	}

	return resp, decrypted, nil
}

// DecoyServer parses inbound decoy requests and encodes encrypted HTTP responses.
type DecoyServer struct {
	config   *DecoyTunnelConfig
	envelope DecoyEnvelope
}

// NewDecoyServer creates a new server instance.
func NewDecoyServer(config *DecoyTunnelConfig) *DecoyServer {
	if config == nil {
		config = DefaultDecoyTunnelConfig()
	}
	return &DecoyServer{
		config:   config,
		envelope: DecoyEnvelope{},
	}
}

// DecodeRequest parses an inbound decoy HTTP request, validates headers, and extracts the inner payload.
func (s *DecoyServer) DecodeRequest(rawHTTP []byte) (*DecoyRequest, []byte, error) {
	headerEnd := bytes.Index(rawHTTP, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		return nil, nil, errors.New("incomplete http request: missing header terminator")
	}

	headerPart := string(rawHTTP[:headerEnd])
	bodyPart := rawHTTP[headerEnd+4:]

	lines := strings.Split(headerPart, "\r\n")
	if len(lines) == 0 {
		return nil, nil, errors.New("empty http request")
	}

	reqParts := strings.Fields(lines[0])
	if len(reqParts) < 3 {
		return nil, nil, fmt.Errorf("invalid request line: %s", lines[0])
	}

	method := reqParts[0]
	path := reqParts[1]
	version := strings.TrimPrefix(reqParts[2], "HTTP/")

	headers := make(map[string]string)
	var sessionID string
	var action DecoyAction
	contentLength := 0
	keepAlive := true
	host := ""
	userAgent := ""

	for _, line := range lines[1:] {
		if idx := strings.Index(line, ":"); idx != -1 {
			name := strings.ToLower(strings.TrimSpace(line[:idx]))
			val := strings.TrimSpace(line[idx+1:])
			headers[name] = val

			switch name {
			case "host":
				host = val
			case "user-agent":
				userAgent = val
			case "x-nipo-session":
				sessionID = val
			case "x-nipo-action":
				act, err := ParseDecoyAction(val)
				if err == nil {
					action = act
				}
			case "content-length":
				if cl, err := strconv.Atoi(val); err == nil {
					contentLength = cl
				}
			case "connection":
				keepAlive = strings.Contains(strings.ToLower(val), "keep-alive")
			}
		}
	}

	if action == "" {
		return nil, nil, errors.New("missing or invalid X-Nipo-Action header")
	}

	actualBody := bodyPart
	if contentLength > 0 && len(bodyPart) > contentLength {
		actualBody = bodyPart[:contentLength]
	}

	var innerPayload []byte
	trimmedBody := strings.TrimSpace(string(actualBody))
	if len(trimmedBody) > 0 {
		ciphertext, err := base64.StdEncoding.DecodeString(trimmedBody)
		if err != nil {
			return nil, nil, fmt.Errorf("base64 decode failed: %w", err)
		}

		key := s.config.DeriveKey()
		hexBytes, err := s.envelope.Decrypt(ciphertext, key[:])
		if err != nil {
			return nil, nil, fmt.Errorf("decryption failed: %w", err)
		}

		rawBytes, err := hex.DecodeString(string(hexBytes))
		if err != nil {
			return nil, nil, fmt.Errorf("hex decode failed: %w", err)
		}
		innerPayload = rawBytes
	}

	req := &DecoyRequest{
		Method:        method,
		Path:          path,
		Version:       version,
		Host:          host,
		UserAgent:     userAgent,
		SessionID:     sessionID,
		Action:        action,
		ContentLength: contentLength,
		KeepAlive:     keepAlive,
		Headers:       headers,
		RawBody:       actualBody,
	}

	return req, innerPayload, nil
}

// EncodeResponse formats an encrypted HTTP response back to the agent.
func (s *DecoyServer) EncodeResponse(statusCode int, statusText string, plainBody []byte, keepAlive bool) ([]byte, error) {
	key := s.config.DeriveKey()

	var encryptedBody []byte
	if len(plainBody) > 0 {
		enc, err := s.envelope.Encrypt(plainBody, key[:])
		if err != nil {
			return nil, fmt.Errorf("response encryption failed: %w", err)
		}
		encryptedBody = enc
	}

	conn := "close"
	if keepAlive {
		conn = "keep-alive"
	}

	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("HTTP/1.1 %d %s\r\n", statusCode, statusText))
	buf.WriteString("Content-Type: application/text\r\n")
	buf.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(encryptedBody)))
	buf.WriteString(fmt.Sprintf("Connection: %s\r\n", conn))
	buf.WriteString("Cache-Control: no-cache\r\n")
	buf.WriteString("Pragma: no-cache\r\n")
	buf.WriteString("\r\n")
	buf.Write(encryptedBody)

	return buf.Bytes(), nil
}

// DecoySession tracks active tunnel session state.
type DecoySession struct {
	SessionID     string
	IsConnected   bool
	BytesSent     int64
	BytesReceived int64
	ActiveAction  DecoyAction
	CreatedAt     time.Time
	LastActive    time.Time
	mu            sync.RWMutex
}

// NewDecoySession instantiates a new session tracker.
func NewDecoySession(sessionID string) *DecoySession {
	now := time.Now()
	return &DecoySession{
		SessionID:    sessionID,
		IsConnected:  false,
		ActiveAction: ActionOpen,
		CreatedAt:    now,
		LastActive:   now,
	}
}

// MarkConnected marks the session as active.
func (s *DecoySession) MarkConnected() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.IsConnected = true
	s.ActiveAction = ActionSend
	s.LastActive = time.Now()
}

// RecordSent adds sent byte count.
func (s *DecoySession) RecordSent(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.BytesSent += int64(n)
	s.LastActive = time.Now()
}

// RecordReceived adds received byte count.
func (s *DecoySession) RecordReceived(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.BytesReceived += int64(n)
	s.LastActive = time.Now()
}

// MarkClosed closes the session.
func (s *DecoySession) MarkClosed() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.IsConnected = false
	s.ActiveAction = ActionClose
	s.LastActive = time.Now()
}
