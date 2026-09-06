// Package transport provides tactical tunnel session obfuscation, hot channel
// swapping, dynamic tactics filtering, and authenticated server exchange.
//
// Conforms to strict architectural isolation rules: zero vendor prefixes.
package transport

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	ObfuscateSeedLength     = 16
	ObfuscateKeyLength      = 16
	ObfuscateHashIterations = 6000
	ObfuscateMaxPadding     = 8192
	ObfuscateMagicValue     = uint32(0x0BF5CA7E)
	ObfuscateC2SIV          = "client_to_server"
	ObfuscateS2CIV          = "server_to_client"
	PreambleHeaderLength    = ObfuscateSeedLength + 8 // 16B seed + 4B magic + 4B padding len
)

var (
	ErrInvalidSeedLength    = errors.New("tactical session: seed must be 16 bytes")
	ErrInvalidMagic         = errors.New("tactical session: invalid magic preamble header")
	ErrExcessivePadding     = errors.New("tactical session: padding exceeds maximum allowed")
	ErrBufferTooShort       = errors.New("tactical session: buffer too short")
	ErrClosedTransport      = errors.New("tactical session: transport is closed")
	ErrExchangeVerification = errors.New("tactical session: exchange payload verification failed")
)

// TacticalStreamCipher implements a standard RC4 stream cipher for tactical framing.
type TacticalStreamCipher struct {
	s [256]byte
	i byte
	j byte
}

func NewTacticalStreamCipher(key []byte) *TacticalStreamCipher {
	c := &TacticalStreamCipher{}
	for k := 0; k < 256; k++ {
		c.s[k] = byte(k)
	}
	var j byte
	keyLen := len(key)
	if keyLen == 0 {
		keyLen = 1
	}
	for i := 0; i < 256; i++ {
		var keyByte byte
		if len(key) > 0 {
			keyByte = key[i%keyLen]
		}
		j = j + c.s[i] + keyByte
		c.s[i], c.s[j] = c.s[j], c.s[i]
	}
	return c
}

func (c *TacticalStreamCipher) ApplyKeyStream(buf []byte) {
	for idx := range buf {
		c.i++
		c.j += c.s[c.i]
		c.s[c.i], c.s[c.j] = c.s[c.j], c.s[c.i]
		k := c.s[(c.s[c.i]+c.s[c.j])&0xFF]
		buf[idx] ^= k
	}
}

// DeriveTacticalKey derives a 16-byte key using 6000 recursive rounds of SHA-1.
func DeriveTacticalKey(seed []byte, keyword []byte, iv string) ([]byte, error) {
	if len(seed) != ObfuscateSeedLength {
		return nil, ErrInvalidSeedLength
	}

	h := sha1.New()
	h.Write(seed)
	h.Write(keyword)
	h.Write([]byte(iv))
	digest := h.Sum(nil)

	for i := 0; i < ObfuscateHashIterations; i++ {
		h.Reset()
		h.Write(digest)
		digest = h.Sum(nil)
	}

	if len(digest) < ObfuscateKeyLength {
		return nil, ErrBufferTooShort
	}
	key := make([]byte, ObfuscateKeyLength)
	copy(key, digest[:ObfuscateKeyLength])
	return key, nil
}

// TacticalSessionObfuscator handles bidirectional RC4 obfuscation for a tactical tunnel session.
type TacticalSessionObfuscator struct {
	keyword              []byte
	seed                 [ObfuscateSeedLength]byte
	paddingLen           int
	clientToServerCipher *TacticalStreamCipher
	serverToClientCipher *TacticalStreamCipher
}

// NewClientTacticalObfuscator creates a client obfuscator session.
func NewClientTacticalObfuscator(keyword []byte, seed []byte, paddingLen int) (*TacticalSessionObfuscator, error) {
	if len(seed) != ObfuscateSeedLength {
		return nil, ErrInvalidSeedLength
	}
	if paddingLen > ObfuscateMaxPadding {
		return nil, ErrExcessivePadding
	}

	c2sKey, err := DeriveTacticalKey(seed, keyword, ObfuscateC2SIV)
	if err != nil {
		return nil, err
	}
	s2cKey, err := DeriveTacticalKey(seed, keyword, ObfuscateS2CIV)
	if err != nil {
		return nil, err
	}

	obs := &TacticalSessionObfuscator{
		keyword:              append([]byte(nil), keyword...),
		paddingLen:           paddingLen,
		clientToServerCipher: NewTacticalStreamCipher(c2sKey),
		serverToClientCipher: NewTacticalStreamCipher(s2cKey),
	}
	copy(obs.seed[:], seed)
	return obs, nil
}

// GenerateClientPreamble emits [16B seed] || encrypt_c2s([0x0BF5CA7E] || [padding_len] || [padding]).
func (o *TacticalSessionObfuscator) GenerateClientPreamble(paddingBytes []byte) ([]byte, error) {
	if len(paddingBytes) != o.paddingLen {
		return nil, ErrBufferTooShort
	}

	payload := make([]byte, 8+o.paddingLen)
	binary.BigEndian.PutUint32(payload[0:4], ObfuscateMagicValue)
	binary.BigEndian.PutUint32(payload[4:8], uint32(o.paddingLen))
	copy(payload[8:], paddingBytes)

	o.clientToServerCipher.ApplyKeyStream(payload)

	preamble := make([]byte, ObfuscateSeedLength+len(payload))
	copy(preamble[:ObfuscateSeedLength], o.seed[:])
	copy(preamble[ObfuscateSeedLength:], payload)
	return preamble, nil
}

// NewServerTacticalObfuscator parses a client preamble and initializes server ciphers.
func NewServerTacticalObfuscator(keyword []byte, preamble []byte) (*TacticalSessionObfuscator, []byte, error) {
	if len(preamble) < PreambleHeaderLength {
		return nil, nil, ErrBufferTooShort
	}

	seed := preamble[:ObfuscateSeedLength]
	c2sKey, err := DeriveTacticalKey(seed, keyword, ObfuscateC2SIV)
	if err != nil {
		return nil, nil, err
	}
	s2cKey, err := DeriveTacticalKey(seed, keyword, ObfuscateS2CIV)
	if err != nil {
		return nil, nil, err
	}

	c2sCipher := NewTacticalStreamCipher(c2sKey)
	s2cCipher := NewTacticalStreamCipher(s2cKey)

	encHeader := append([]byte(nil), preamble[ObfuscateSeedLength:PreambleHeaderLength]...)
	c2sCipher.ApplyKeyStream(encHeader)

	magic := binary.BigEndian.Uint32(encHeader[0:4])
	if magic != ObfuscateMagicValue {
		return nil, nil, fmt.Errorf("%w: received 0x%08X", ErrInvalidMagic, magic)
	}

	paddingLen := int(binary.BigEndian.Uint32(encHeader[4:8]))
	if paddingLen > ObfuscateMaxPadding {
		return nil, nil, ErrExcessivePadding
	}

	totalReq := PreambleHeaderLength + paddingLen
	if len(preamble) < totalReq {
		return nil, nil, ErrBufferTooShort
	}

	padding := append([]byte(nil), preamble[PreambleHeaderLength:totalReq]...)
	c2sCipher.ApplyKeyStream(padding)

	obs := &TacticalSessionObfuscator{
		keyword:              append([]byte(nil), keyword...),
		paddingLen:           paddingLen,
		clientToServerCipher: c2sCipher,
		serverToClientCipher: s2cCipher,
	}
	copy(obs.seed[:], seed)
	return obs, padding, nil
}

func (o *TacticalSessionObfuscator) ObfuscateClientToServer(buf []byte) {
	o.clientToServerCipher.ApplyKeyStream(buf)
}

func (o *TacticalSessionObfuscator) ObfuscateServerToClient(buf []byte) {
	o.serverToClientCipher.ApplyKeyStream(buf)
}

func (o *TacticalSessionObfuscator) Seed() [ObfuscateSeedLength]byte {
	return o.seed
}

func (o *TacticalSessionObfuscator) PaddingLen() int {
	return o.paddingLen
}

// TacticalTunnelTransport provides an io.ReadWriteCloser abstraction supporting hot channel substitution.
type TacticalTunnelTransport struct {
	mu           sync.RWMutex
	currentConn  net.Conn
	closed       atomic.Bool
	connNotifier *sync.Cond
}

func NewTacticalTunnelTransport(initialConn net.Conn) *TacticalTunnelTransport {
	t := &TacticalTunnelTransport{
		currentConn: initialConn,
	}
	t.connNotifier = sync.NewCond(&t.mu)
	return t
}

func (t *TacticalTunnelTransport) SwapChannel(newConn net.Conn) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.currentConn != nil && t.currentConn != newConn {
		_ = t.currentConn.Close()
	}
	t.currentConn = newConn
	t.connNotifier.Broadcast()
}

func (t *TacticalTunnelTransport) Read(p []byte) (int, error) {
	for {
		if t.closed.Load() {
			return 0, ErrClosedTransport
		}

		t.mu.RLock()
		conn := t.currentConn
		t.mu.RUnlock()

		if conn != nil {
			n, err := conn.Read(p)
			if err == nil {
				return n, nil
			}
			// Connection error: clear dead connection and wait for hot swap
			t.mu.Lock()
			if t.currentConn == conn {
				t.currentConn = nil
			}
			t.mu.Unlock()
		}

		t.mu.Lock()
		for t.currentConn == nil && !t.closed.Load() {
			t.connNotifier.Wait()
		}
		t.mu.Unlock()
	}
}

func (t *TacticalTunnelTransport) Write(p []byte) (int, error) {
	if t.closed.Load() {
		return 0, ErrClosedTransport
	}
	t.mu.RLock()
	conn := t.currentConn
	t.mu.RUnlock()

	if conn == nil {
		return 0, errors.New("tactical session: channel connection not ready")
	}
	return conn.Write(p)
}

func (t *TacticalTunnelTransport) Close() error {
	if t.closed.Swap(true) {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	var err error
	if t.currentConn != nil {
		err = t.currentConn.Close()
		t.currentConn = nil
	}
	t.connNotifier.Broadcast()
	return err
}

// ServerExchangeEntry encapsulates an authenticated candidate server for client-to-client exchange.
type ServerExchangeEntry struct {
	ServerID       string            `json:"server_id"`
	Endpoints      []string          `json:"endpoints"`
	Capabilities   []string          `json:"capabilities"`
	Signature      string            `json:"signature"`
	DialParameters map[string]string `json:"dial_parameters"`
	Timestamp      int64             `json:"timestamp"`
}

// ExportServerExchange encrypts and signs an exchange payload using an obfuscation key.
func ExportServerExchange(entry *ServerExchangeEntry, exchangeKey []byte) ([]byte, error) {
	plaintext, err := json.Marshal(entry)
	if err != nil {
		return nil, err
	}

	keyHash := sha256.Sum256(exchangeKey)
	stream := NewTacticalStreamCipher(keyHash[:16])

	// 16B nonce + ciphertext + 32B sha256 HMAC digest
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := append([]byte(nil), plaintext...)
	stream.ApplyKeyStream(ciphertext)

	macHasher := sha256.New()
	macHasher.Write(keyHash[:])
	macHasher.Write(nonce)
	macHasher.Write(ciphertext)
	mac := macHasher.Sum(nil)

	envelope := make([]byte, 16+len(ciphertext)+32)
	copy(envelope[0:16], nonce)
	copy(envelope[16:16+len(ciphertext)], ciphertext)
	copy(envelope[16+len(ciphertext):], mac)
	return envelope, nil
}

// ImportServerExchange verifies and decrypts an exchange payload.
func ImportServerExchange(envelope []byte, exchangeKey []byte) (*ServerExchangeEntry, error) {
	if len(envelope) < 16+32 {
		return nil, ErrBufferTooShort
	}

	nonce := envelope[:16]
	ciphertext := envelope[16 : len(envelope)-32]
	expectedMac := envelope[len(envelope)-32:]

	keyHash := sha256.Sum256(exchangeKey)

	macHasher := sha256.New()
	macHasher.Write(keyHash[:])
	macHasher.Write(nonce)
	macHasher.Write(ciphertext)
	mac := macHasher.Sum(nil)

	if subtleConstantTimeCompare(mac, expectedMac) != 1 {
		return nil, ErrExchangeVerification
	}

	stream := NewTacticalStreamCipher(keyHash[:16])
	plaintext := append([]byte(nil), ciphertext...)
	stream.ApplyKeyStream(plaintext)

	var entry ServerExchangeEntry
	if err := json.Unmarshal(plaintext, &entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

func subtleConstantTimeCompare(x, y []byte) int {
	if len(x) != len(y) {
		return 0
	}
	var v byte
	for i := 0; i < len(x); i++ {
		v |= x[i] ^ y[i]
	}
	if v == 0 {
		return 1
	}
	return 0
}

// TacticalProfile holds tactical configuration overrides and latency rules.
type TacticalProfile struct {
	TTL        time.Duration     `json:"ttl"`
	Parameters map[string]string `json:"parameters"`
	Tag        string            `json:"tag"`
}

func NewTacticalProfile(ttl time.Duration, parameters map[string]string) *TacticalProfile {
	return &TacticalProfile{
		TTL:        ttl,
		Parameters: parameters,
		Tag:        ComputeTacticalTag(parameters),
	}
}

func ComputeTacticalTag(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha1.New()
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte("="))
		h.Write([]byte(params[k]))
		h.Write([]byte(";"))
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// TacticalFilter rules for client GeoIP / ASN / latency.
type TacticalFilter struct {
	Regions      []string
	ASNs         []uint32
	MaxLatencyMs uint64
	Profile      *TacticalProfile
}

func (f *TacticalFilter) Matches(region string, asn uint32, latencyMs uint64) bool {
	if len(f.Regions) > 0 {
		matched := false
		for _, r := range f.Regions {
			if strings.EqualFold(r, region) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if len(f.ASNs) > 0 {
		matched := false
		for _, a := range f.ASNs {
			if a == asn {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if f.MaxLatencyMs > 0 && latencyMs > f.MaxLatencyMs {
		return false
	}
	return true
}

// TacticalEngine manages dynamic tactics resolution and profile caching.
type TacticalEngine struct {
	mu             sync.RWMutex
	defaultProfile *TacticalProfile
	filters        []*TacticalFilter
	cachedProfile  *TacticalProfile
	cachedAt       time.Time
}

func NewTacticalEngine(defaultProfile *TacticalProfile) *TacticalEngine {
	return &TacticalEngine{
		defaultProfile: defaultProfile,
		filters:        make([]*TacticalFilter, 0),
	}
}

func (e *TacticalEngine) AddFilter(f *TacticalFilter) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.filters = append(e.filters, f)
}

func (e *TacticalEngine) ResolveProfile(region string, asn uint32, latencyMs uint64, forceRefresh bool) *TacticalProfile {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !forceRefresh && e.cachedProfile != nil {
		if time.Since(e.cachedAt) < e.cachedProfile.TTL {
			return e.cachedProfile
		}
	}

	mergedParams := make(map[string]string)
	for k, v := range e.defaultProfile.Parameters {
		mergedParams[k] = v
	}
	appliedTTL := e.defaultProfile.TTL

	for _, filter := range e.filters {
		if filter.Matches(region, asn, latencyMs) {
			for k, v := range filter.Profile.Parameters {
				mergedParams[k] = v
			}
			appliedTTL = filter.Profile.TTL
		}
	}

	resolved := NewTacticalProfile(appliedTTL, mergedParams)
	e.cachedProfile = resolved
	e.cachedAt = time.Now()
	return resolved
}
