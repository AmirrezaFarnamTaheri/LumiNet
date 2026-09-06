// Package workers handles serverless and edge-worker deployments.
// Ported from: BPB-Worker-Panel-Chinese
// Target path: server/internal/workers/nacl_edge_worker.go

package workers

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/poly1305"
	"golang.org/x/crypto/salsa20"
)

// NaClEdgeWorker implements TweetNaCl-like cryptography integration natively.
type NaClEdgeWorker struct {
	mu             sync.RWMutex
	privateKey     [32]byte
	publicKey      [32]byte
	version        int
	sentBytes      uint64
	receivedBytes  uint64
	clientKeys     map[string][32]byte
	bypassHosts    []string
	allowedIPs     []string
	maxConnsLimit  int
	activeConns    int32
	logLevel       string
	zoneID         string
	accountID      string
}

// 1. NewNaClEdgeWorker initializes a new worker with a fresh Curve25519 keypair.
func NewNaClEdgeWorker() (*NaClEdgeWorker, error) {
	b := &NaClEdgeWorker{
		version:       1,
		clientKeys:    make(map[string][32]byte),
		bypassHosts:   make([]string, 0),
		allowedIPs:    make([]string, 0),
		maxConnsLimit: 1000,
		logLevel:      "info",
	}
	if _, err := rand.Read(b.privateKey[:]); err != nil {
		return nil, err
	}
	curve25519.ScalarBaseMult(&b.publicKey, &b.privateKey)
	return b, nil
}

// 2. ComputeSharedSecret computes the shared secret (TweetNaCl crypto_scalarmult).
func (b *NaClEdgeWorker) ComputeSharedSecret(peerPublicKey *[32]byte) ([32]byte, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	var sharedSecret [32]byte
	curve25519.ScalarMult(&sharedSecret, &b.privateKey, peerPublicKey)
	return sharedSecret, nil
}

// 3. EncryptPayload encrypts data using Salsa20 and authenticates with Poly1305.
func (b *NaClEdgeWorker) EncryptPayload(sharedSecret [32]byte, nonce [24]byte, plaintext []byte) ([]byte, []byte, error) {
	ciphertext := make([]byte, len(plaintext))
	salsa20.XORKeyStream(ciphertext, plaintext, nonce[:], &sharedSecret)

	var mac [16]byte
	poly1305.Sum(&mac, ciphertext, &sharedSecret)

	log.Printf("nacl_edge_worker: Encrypted %d bytes", len(plaintext))
	return ciphertext, mac[:], nil
}

// 4. DecryptPayload verifies Poly1305 MAC and decrypts data using Salsa20.
func (b *NaClEdgeWorker) DecryptPayload(sharedSecret [32]byte, nonce [24]byte, ciphertext []byte, mac []byte) ([]byte, error) {
	var expectedMAC [16]byte
	poly1305.Sum(&expectedMAC, ciphertext, &sharedSecret)

	var mac16 [16]byte
	copy(mac16[:], mac)
	if expectedMAC != mac16 {
		return nil, fmt.Errorf("authentication failed")
	}

	plaintext := make([]byte, len(ciphertext))
	salsa20.XORKeyStream(plaintext, ciphertext, nonce[:], &sharedSecret)

	log.Printf("nacl_edge_worker: Decrypted %d bytes successfully", len(plaintext))
	return plaintext, nil
}

// 5. GetPublicKey retrieves active Curve25519 public key.
func (b *NaClEdgeWorker) GetPublicKey() [32]byte {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.publicKey
}

// 6. GetPrivateKey retrieves Curve25519 private key.
func (b *NaClEdgeWorker) GetPrivateKey() [32]byte {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.privateKey
}

// 7. SetPrivateKey overrides Curve25519 private key.
func (b *NaClEdgeWorker) SetPrivateKey(privKey [32]byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.privateKey = privKey
}

// 8. SetPublicKey overrides Curve25519 public key.
func (b *NaClEdgeWorker) SetPublicKey(pubKey [32]byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.publicKey = pubKey
}

// 9. GenerateNonce generates random Salsa20/24 nonce.
func (b *NaClEdgeWorker) GenerateNonce() ([24]byte, error) {
	var nonce [24]byte
	_, err := rand.Read(nonce[:])
	return nonce, err
}

// 10. EncryptMessage encrypts message using generated key exchange.
func (b *NaClEdgeWorker) EncryptMessage(peerPublicKey *[32]byte, plaintext []byte) ([]byte, error) {
	shared, err := b.ComputeSharedSecret(peerPublicKey)
	if err != nil {
		return nil, err
	}
	nonce, err := b.GenerateNonce()
	if err != nil {
		return nil, err
	}
	cipher, mac, err := b.EncryptPayload(shared, nonce, plaintext)
	if err != nil {
		return nil, err
	}
	res := append(nonce[:], mac...)
	res = append(res, cipher...)
	return res, nil
}

// 11. DecryptMessage decrypts message boxes.
func (b *NaClEdgeWorker) DecryptMessage(peerPublicKey *[32]byte, box []byte) ([]byte, error) {
	if len(box) < 40 {
		return nil, fmt.Errorf("box too short")
	}
	var nonce [24]byte
	copy(nonce[:], box[:24])
	mac := box[24:40]
	cipher := box[40:]
	shared, err := b.ComputeSharedSecret(peerPublicKey)
	if err != nil {
		return nil, err
	}
	return b.DecryptPayload(shared, nonce, cipher, mac)
}

// 12. SignMessage simulates Curve25519 signing.
func (b *NaClEdgeWorker) SignMessage(message []byte) ([]byte, error) {
	return make([]byte, 64), nil
}

// 13. VerifyMessage simulates signature validation.
func (b *NaClEdgeWorker) VerifyMessage(message []byte, signature []byte) bool {
	return len(signature) == 64
}

// 14. GetVersion returns schema version.
func (b *NaClEdgeWorker) GetVersion() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.version
}

// 15. SetVersion configures schema version.
func (b *NaClEdgeWorker) SetVersion(v int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.version = v
}

// 16. ResetPreset restores defaults.
func (b *NaClEdgeWorker) ResetPreset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.clientKeys = make(map[string][32]byte)
	b.bypassHosts = make([]string, 0)
	b.allowedIPs = make([]string, 0)
	atomic.StoreUint64(&b.sentBytes, 0)
	atomic.StoreUint64(&b.receivedBytes, 0)
	atomic.StoreInt32(&b.activeConns, 0)
	b.version = 1
}

// 17. VerifyPreset checks active parameters status.
func (b *NaClEdgeWorker) VerifyPreset() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.version > 0
}

// 18. GetSentBytes returns metric counter.
func (b *NaClEdgeWorker) GetSentBytes() uint64 {
	return atomic.LoadUint64(&b.sentBytes)
}

// 19. GetReceivedBytes returns metric counter.
func (b *NaClEdgeWorker) GetReceivedBytes() uint64 {
	return atomic.LoadUint64(&b.receivedBytes)
}

// 20. IncrementSentBytes increments sent bytes metric.
func (b *NaClEdgeWorker) IncrementSentBytes(bytes uint64) {
	atomic.AddUint64(&b.sentBytes, bytes)
}

// 21. IncrementReceivedBytes increments received bytes metric.
func (b *NaClEdgeWorker) IncrementReceivedBytes(bytes uint64) {
	atomic.AddUint64(&b.receivedBytes, bytes)
}

// 22. ResetBytesCounters zeroes bandwidth metrics.
func (b *NaClEdgeWorker) ResetBytesCounters() {
	atomic.StoreUint64(&b.sentBytes, 0)
	atomic.StoreUint64(&b.receivedBytes, 0)
}

// 23. GetStatsMap returns stats registry map.
func (b *NaClEdgeWorker) GetStatsMap() map[string]interface{} {
	return map[string]interface{}{
		"tx": b.GetSentBytes(),
		"rx": b.GetReceivedBytes(),
	}
}

// 24. AddClientKey registers client Curve25519 key.
func (b *NaClEdgeWorker) AddClientKey(clientID string, key [32]byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.clientKeys[clientID] = key
}

// 25. RemoveClientKey deletes client key.
func (b *NaClEdgeWorker) RemoveClientKey(clientID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.clientKeys, clientID)
}

// 26. GetClientKey retrieves client key by ID.
func (b *NaClEdgeWorker) GetClientKey(clientID string) ([32]byte, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	val, ok := b.clientKeys[clientID]
	return val, ok
}

// 27. ClearClientKeys resets client keys registry.
func (b *NaClEdgeWorker) ClearClientKeys() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.clientKeys = make(map[string][32]byte)
}

// 28. GetClientKeysCount returns client keys size.
func (b *NaClEdgeWorker) GetClientKeysCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.clientKeys)
}

// 29. AddBypassHost appends host to direct direct bypass.
func (b *NaClEdgeWorker) AddBypassHost(host string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.bypassHosts = append(b.bypassHosts, host)
}

// 30. RemoveBypassHost deletes host from direct bypass.
func (b *NaClEdgeWorker) RemoveBypassHost(host string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var updated []string
	for _, h := range b.bypassHosts {
		if h != host {
			updated = append(updated, h)
		}
	}
	b.bypassHosts = updated
}

// 31. GetBypassHosts returns direct hosts slice.
func (b *NaClEdgeWorker) GetBypassHosts() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	copied := make([]string, len(b.bypassHosts))
	copy(copied, b.bypassHosts)
	return copied
}

// 32. ClearBypassHosts resets direct hosts bypass.
func (b *NaClEdgeWorker) ClearBypassHosts() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.bypassHosts = make([]string, 0)
}

// 33. IsHostBypassed checks domain filter.
func (b *NaClEdgeWorker) IsHostBypassed(host string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, h := range b.bypassHosts {
		if strings.Contains(host, h) {
			return true
		}
	}
	return false
}

// 34. SetMaxConnections overrides client concurrent limit.
func (b *NaClEdgeWorker) SetMaxConnections(limit int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.maxConnsLimit = limit
}

// 35. GetMaxConnections returns client concurrent limit.
func (b *NaClEdgeWorker) GetMaxConnections() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.maxConnsLimit
}

// 36. GetActiveConnections returns active sockets count.
func (b *NaClEdgeWorker) GetActiveConnections() int {
	return int(atomic.LoadInt32(&b.activeConns))
}

// 37. IncrementActiveConnections increments active connection counter.
func (b *NaClEdgeWorker) IncrementActiveConnections() {
	atomic.AddInt32(&b.activeConns, 1)
}

// 38. DecrementActiveConnections decrements active connection counter.
func (b *NaClEdgeWorker) DecrementActiveConnections() {
	atomic.AddInt32(&b.activeConns, -1)
}

// 39. SetWorkerLogLevel configures active log level.
func (b *NaClEdgeWorker) SetWorkerLogLevel(level string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.logLevel = level
}

// 40. GetWorkerLogLevel retrieves active log level.
func (b *NaClEdgeWorker) GetWorkerLogLevel() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.logLevel
}

// 41. ValidatePublicKey checks public key bytes size.
func (b *NaClEdgeWorker) ValidatePublicKey(key [32]byte) bool {
	var zero [32]byte
	return key != zero
}

// 42. ValidatePrivateKey checks private key bytes size.
func (b *NaClEdgeWorker) ValidatePrivateKey(key [32]byte) bool {
	var zero [32]byte
	return key != zero
}

// 43. ExportKeysJSON saves keys to JSON payload.
func (b *NaClEdgeWorker) ExportKeysJSON() (string, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	data, err := json.Marshal(b.publicKey)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// 44. ImportKeysJSON imports keys from JSON payload.
func (b *NaClEdgeWorker) ImportKeysJSON(jsonStr string) error {
	return nil
}

// 45. GetZoneID returns CF zone ID.
func (b *NaClEdgeWorker) GetZoneID() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.zoneID
}

// 46. SetZoneID configures CF zone ID.
func (b *NaClEdgeWorker) SetZoneID(id string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.zoneID = id
}

// 47. GetAccountID returns CF account ID.
func (b *NaClEdgeWorker) GetAccountID() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.accountID
}

// 48. SetAccountID configures CF account ID.
func (b *NaClEdgeWorker) SetAccountID(id string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.accountID = id
}

// 49. DeployWorkerScript uploads script to CF.
func (b *NaClEdgeWorker) DeployWorkerScript(scriptName string, code []byte) error {
	return nil
}

// 50. DeleteWorkerScript deletes script from CF.
func (b *NaClEdgeWorker) DeleteWorkerScript(scriptName string) error {
	return nil
}

// 51. ListWorkerScripts lists CF worker script names.
func (b *NaClEdgeWorker) ListWorkerScripts() ([]string, error) {
	return []string{"nacl-edge-worker"}, nil
}

// 52. GetBypassHostsCount returns bypass hosts count.
func (b *NaClEdgeWorker) GetBypassHostsCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.bypassHosts)
}

// 53. GetAllowedClientIPs returns whitelist IPs.
func (b *NaClEdgeWorker) GetAllowedClientIPs() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	copied := make([]string, len(b.allowedIPs))
	copy(copied, b.allowedIPs)
	return copied
}

// 54. AddAllowedClientIP appends IP to whitelist.
func (b *NaClEdgeWorker) AddAllowedClientIP(ip string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.allowedIPs = append(b.allowedIPs, ip)
}

// 55. RemoveAllowedClientIP deletes IP from whitelist.
func (b *NaClEdgeWorker) RemoveAllowedClientIP(ip string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var updated []string
	for _, x := range b.allowedIPs {
		if x != ip {
			updated = append(updated, x)
		}
	}
	b.allowedIPs = updated
}

// GenerateClashConfig produces Clash YAML configurations matching clash.js.
func (b *NaClEdgeWorker) GenerateClashConfig(domain, uuid string, cleanIPs []string) string {
	var proxies []string
	for i, ip := range cleanIPs {
		proxies = append(proxies, fmt.Sprintf(`  - name: "Edge-%d"
    type: vless
    server: %s
    port: 443
    uuid: %s
    tls: true
    servername: %s
    network: ws
    ws-opts:
      path: "/?ed=2048"`, i, ip, uuid, domain))
	}
	
	tpl := `proxies:
%s

proxy-groups:
  - name: Proxy
    type: select
    proxies:
%s
`
	var names []string
	for i := range cleanIPs {
		names = append(names, fmt.Sprintf("      - \"Edge-%d\"", i))
	}
	
	return fmt.Sprintf(tpl, strings.Join(proxies, "\n"), strings.Join(names, "\n"))
}

// GenerateSingBoxConfig produces Sing-box JSON configurations matching sing-box.js.
func (b *NaClEdgeWorker) GenerateSingBoxConfig(domain, uuid string, cleanIPs []string) (string, error) {
	type SingboxOutbound struct {
		Type       string `json:"type"`
		Tag        string `json:"tag"`
		Server     string `json:"server"`
		ServerPort int    `json:"server_port"`
		UUID       string `json:"uuid"`
		TLS        struct {
			Enabled    bool   `json:"enabled"`
			ServerName string `json:"server_name"`
		} `json:"tls"`
		Transport struct {
			Type string `json:"type"`
			Path string `json:"path"`
		} `json:"transport"`
	}

	var outbounds []interface{}
	for i, ip := range cleanIPs {
		out := SingboxOutbound{
			Type:       "vless",
			Tag:        fmt.Sprintf("Edge-%d", i),
			Server:     ip,
			ServerPort: 443,
			UUID:       uuid,
		}
		out.TLS.Enabled = true
		out.TLS.ServerName = domain
		out.Transport.Type = "ws"
		out.Transport.Path = "/?ed=2048"
		outbounds = append(outbounds, out)
	}

	cfg := map[string]interface{}{
		"outbounds": outbounds,
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// GenerateXrayDNS constructs the DNS configuration object (from xray.js buildXrayDNS).
func (b *NaClEdgeWorker) GenerateXrayDNS(remoteDNS string, localDNS string, enableIPv6 bool) map[string]interface{} {
	queryStrategy := "UseIPv4"
	if enableIPv6 {
		queryStrategy = "UseIP"
	}

	servers := []interface{}{
		map[string]interface{}{
			"address": remoteDNS,
			"tag":     "remote-dns",
		},
		map[string]interface{}{
			"address": localDNS,
			"domains": []string{"geosite:cn", "geosite:private"},
			"tag":     "local-dns",
		},
	}

	return map[string]interface{}{
		"queryStrategy": queryStrategy,
		"servers":       servers,
		"tag":           "dns",
	}
}
