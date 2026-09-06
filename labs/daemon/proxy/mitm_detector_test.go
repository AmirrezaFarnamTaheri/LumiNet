package proxy

import (
	"testing"
)

func TestMitmDetector(t *testing.T) {
	detector := NewMitmDetector()

	chromeUA := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

	// Valid Chrome ClientHello Spec
	cleanChromeSpec := ClientHelloSpec{
		Version:      0x0303,
		CipherSuites: []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8},
		Extensions:   []uint16{0, 23, 65281, 10, 11, 35, 16, 5, 13},
	}

	report := detector.Check(chromeUA, cleanChromeSpec)
	if report.Intercepted {
		t.Errorf("expected clean Chrome connection, got intercepted: %s", report.Reason)
	}

	// Mismatched CipherSuites (e.g. only supports older ciphers)
	interceptedSpecCiphers := ClientHelloSpec{
		Version:      0x0303,
		CipherSuites: []uint16{0x000a, 0x002f}, // Weak/outdated ciphers common in legacy middleboxes
		Extensions:   []uint16{0, 23, 65281, 10, 11, 35, 16, 5, 13},
	}

	reportCiphers := detector.Check(chromeUA, interceptedSpecCiphers)
	if !reportCiphers.Intercepted {
		t.Error("expected cipher suite mismatch to be flagged as intercepted")
	}

	// Missing Extension (e.g. missing Server Name Indication - SNI (0))
	interceptedSpecExt := ClientHelloSpec{
		Version:      0x0303,
		CipherSuites: []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8},
		Extensions:   []uint16{23, 65281, 10, 11, 35, 16, 5, 13}, // extension 0 (SNI) is missing
	}

	reportExt := detector.Check(chromeUA, interceptedSpecExt)
	if !reportExt.Intercepted {
		t.Error("expected missing extension to be flagged as intercepted")
	}
}
