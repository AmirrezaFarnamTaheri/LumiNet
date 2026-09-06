package security

import (
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

type GeneratedCert struct {
	CommonName     string    `json:"common_name"`
	SerialNumber   uint64    `json:"serial_number"`
	NotBefore      time.Time `json:"not_before"`
	NotAfter       time.Time `json:"not_after"`
	CertPayload    []byte    `json:"cert_payload"`
}

type DynamicCaManager struct {
	mu            sync.Mutex
	caName        string
	serialCounter uint64
	certCache     map[string]*GeneratedCert
}

func NewDynamicCaManager(caName string) *DynamicCaManager {
	return &DynamicCaManager{
		caName:        caName,
		serialCounter: 1000,
		certCache:     make(map[string]*GeneratedCert),
	}
}

func (m *DynamicCaManager) IssueOrGetCert(commonName string, validity time.Duration) *GeneratedCert {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	if cached, exists := m.certCache[commonName]; exists {
		if now.Before(cached.NotAfter) {
			return cached
		}
	}

	m.serialCounter++
	payload := []byte(fmt.Sprintf("MOCK-CERT:%s:%s", m.caName, commonName))
	serBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(serBytes, m.serialCounter)
	payload = append(payload, serBytes...)

	cert := &GeneratedCert{
		CommonName:   commonName,
		SerialNumber: m.serialCounter,
		NotBefore:    now,
		NotAfter:     now.Add(validity),
		CertPayload:  payload,
	}
	m.certCache[commonName] = cert
	return cert
}
