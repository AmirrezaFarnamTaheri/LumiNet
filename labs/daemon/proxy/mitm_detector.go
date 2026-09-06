package proxy

import (
	"fmt"
	"strings"
	"sync"
)

// ClientHelloSpec represents the TLS fingerprint of a ClientHello.
type ClientHelloSpec struct {
	Version      uint16
	CipherSuites []uint16
	Extensions   []uint16
	Curves       []uint16
	PointFormats []byte
}

// BrowserSignature defines the expected client hello specs for a browser.
type BrowserSignature struct {
	BrowserName string
	MinVersion  string
	MaxVersion  string
	Spec        ClientHelloSpec
}

// InterceptionReport defines the result of a MITM detection check.
type InterceptionReport struct {
	Intercepted    bool
	MatchedBrowser string
	Reason         string
}

// MitmDetector detects HTTPS interception by comparing ClientHello specs with User Agent.
type MitmDetector struct {
	mu         sync.RWMutex
	signatures []BrowserSignature
}

// NewMitmDetector creates a new MITM detection processor.
func NewMitmDetector() *MitmDetector {
	detector := &MitmDetector{
		signatures: make([]BrowserSignature, 0),
	}
	detector.loadDefaultSignatures()
	return detector
}

// AddSignature adds a reference browser signature to the detector.
func (d *MitmDetector) AddSignature(sig BrowserSignature) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.signatures = append(d.signatures, sig)
}

// Check compares the actual ClientHello spec against the User-Agent browser version.
// If the User-Agent indicates Chrome but the ClientHello cipher suites or extensions
// mismatch Chrome's signature spec, it flags a potential MITM interception.
func (d *MitmDetector) Check(userAgent string, actual ClientHelloSpec) InterceptionReport {
	d.mu.RLock()
	defer d.mu.RUnlock()

	uaLower := strings.ToLower(userAgent)
	var expected *BrowserSignature

	// Match expected browser signature by parsing UA string simply
	for _, sig := range d.signatures {
		if strings.Contains(uaLower, strings.ToLower(sig.BrowserName)) {
			expected = &sig
			break
		}
	}

	if expected == nil {
		return InterceptionReport{Intercepted: false, Reason: "unknown user agent"}
	}

	// Compare cipher suites: check if there's a significant mismatch
	suiteMatch := false
	for _, sActual := range actual.CipherSuites {
		for _, sExpected := range expected.Spec.CipherSuites {
			if sActual == sExpected {
				suiteMatch = true
				break
			}
		}
	}

	if !suiteMatch && len(expected.Spec.CipherSuites) > 0 {
		return InterceptionReport{
			Intercepted:    true,
			MatchedBrowser: expected.BrowserName,
			Reason:         "cipher suite mismatch (possible middlebox interception)",
		}
	}

	// Compare extension profiles
	for _, extExpected := range expected.Spec.Extensions {
		found := false
		for _, extActual := range actual.Extensions {
			if extExpected == extActual {
				found = true
				break
			}
		}
		if !found {
			return InterceptionReport{
				Intercepted:    true,
				MatchedBrowser: expected.BrowserName,
				Reason:         fmt.Sprintf("missing expected TLS extension: %d", extExpected),
			}
		}
	}

	return InterceptionReport{
		Intercepted:    false,
		MatchedBrowser: expected.BrowserName,
		Reason:         "clean connection matching browser signature",
	}
}

func (d *MitmDetector) loadDefaultSignatures() {
	// Standard Chrome Signature
	d.signatures = append(d.signatures, BrowserSignature{
		BrowserName: "Chrome",
		Spec: ClientHelloSpec{
			Version:      0x0303, // TLS 1.2
			CipherSuites: []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8},
			Extensions:   []uint16{0, 23, 65281, 10, 11, 35, 16, 5, 13},
		},
	})

	// Standard Firefox Signature
	d.signatures = append(d.signatures, BrowserSignature{
		BrowserName: "Firefox",
		Spec: ClientHelloSpec{
			Version:      0x0303, // TLS 1.2
			CipherSuites: []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8},
			Extensions:   []uint16{0, 23, 10, 11, 35, 16, 5, 13, 51},
		},
	})
}
