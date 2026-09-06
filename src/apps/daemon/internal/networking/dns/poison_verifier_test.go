package dns

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

func TestPoisonVerifier_NoAnchorsNoDefaults(t *testing.T) {
	t.Parallel()
	v := NewPoisonVerifier()
	// Without anchors or defaults, all responses are trusted.
	res := v.VerifyResponse(buildSimpleQuery("example.com", 1), buildSimpleResponse("example.com", 1, []string{"1.2.3.4"}), "any-upstream")
	if !res.Trusted {
		t.Errorf("expected trusted, got anomaly %s", res.Anomaly)
	}
}

func TestPoisonVerifier_IPMismatchDetected(t *testing.T) {
	t.Parallel()
	v := NewPoisonVerifier()
	v.AddAnchor(Anchor{
		DomainPatterns: []string{"trusted.example.com"},
		AllowedIPs:     []string{"10.0.0.1"},
	})
	res := v.VerifyRecord("trusted.example.com", []string{"1.2.3.4"}, "trusted-upstream")
	if res.Trusted {
		t.Fatal("expected IP mismatch to be flagged")
	}
	if res.Anomaly != AnomalyIPMismatch {
		t.Errorf("expected AnomalyIPMismatch, got %s", res.Anomaly)
	}
}

func TestPoisonVerifier_IPMatch(t *testing.T) {
	t.Parallel()
	v := NewPoisonVerifier()
	v.AddAnchor(Anchor{
		DomainPatterns: []string{"trusted.example.com"},
		AllowedIPs:     []string{"10.0.0.1", "10.0.0.2"},
	})
	res := v.VerifyRecord("trusted.example.com", []string{"10.0.0.2"}, "upstream")
	if !res.Trusted {
		t.Errorf("expected trusted, got anomaly %s reason=%s", res.Anomaly, res.Reason)
	}
}

func TestPoisonVerifier_CIDRMatch(t *testing.T) {
	t.Parallel()
	v := NewPoisonVerifier()
	v.AddAnchor(Anchor{
		DomainPatterns: []string{"*.corp.example.com"},
		AllowedCIDRs:   []string{"10.0.0.0/8", "192.168.0.0/16"},
	})
	res := v.VerifyRecord("api.corp.example.com", []string{"10.1.2.3", "192.168.99.1"}, "u")
	if !res.Trusted {
		t.Errorf("expected trusted, got anomaly %s reason=%s", res.Anomaly, res.Reason)
	}
	res = v.VerifyRecord("api.corp.example.com", []string{"8.8.8.8"}, "u")
	if res.Trusted {
		t.Error("expected 8.8.8.8 to fail CIDR check")
	}
}

func TestPoisonVerifier_TransactionIDMismatch(t *testing.T) {
	t.Parallel()
	v := NewPoisonVerifier()
	q := buildSimpleQuery("example.com", 1)
	r := buildSimpleResponse("example.com", 1, []string{"1.2.3.4"})
	r[0] = 0xFF // corrupt transaction ID
	res := v.VerifyResponse(q, r, "u")
	if res.Trusted {
		t.Fatal("expected anomaly for txid mismatch")
	}
	if res.Anomaly != AnomalyTransactionMismatch {
		t.Errorf("expected AnomalyTransactionMismatch, got %s", res.Anomaly)
	}
}

func TestPoisonVerifier_QuestionMismatch(t *testing.T) {
	t.Parallel()
	v := NewPoisonVerifier()
	q := buildSimpleQuery("example.com", 1)
	r := buildSimpleResponse("evil.com", 1, []string{"1.2.3.4"})
	res := v.VerifyResponse(q, r, "u")
	if res.Trusted {
		t.Fatal("expected anomaly for question mismatch")
	}
	if res.Anomaly != AnomalyQuestionMismatch {
		t.Errorf("expected AnomalyQuestionMismatch, got %s", res.Anomaly)
	}
}

func TestPoisonVerifier_UnexpectedRCode(t *testing.T) {
	t.Parallel()
	v := NewPoisonVerifier()
	v.AddAnchor(Anchor{
		DomainPatterns: []string{"example.com"},
		AllowedRCodes:  []int{0}, // only NOERROR
	})
	q := buildSimpleQuery("example.com", 1)
	r := buildSimpleResponse("example.com", 1, []string{"1.2.3.4"})
	r[3] = 0x83 // REFUSED
	res := v.VerifyResponse(q, r, "u")
	if res.Trusted {
		t.Fatal("expected anomaly for unexpected rcode")
	}
	if res.Anomaly != AnomalyUnexpectedRCode {
		t.Errorf("expected AnomalyUnexpectedRCode, got %s", res.Anomaly)
	}
}

func TestPoisonVerifier_UnknownServer(t *testing.T) {
	t.Parallel()
	v := NewPoisonVerifier()
	v.AddAnchor(Anchor{
		DomainPatterns: []string{"example.com"},
		UpstreamIDs:    []string{"trusted"},
	})
	q := buildSimpleQuery("example.com", 1)
	r := buildSimpleResponse("example.com", 1, []string{"1.2.3.4"})
	res := v.VerifyResponse(q, r, "evil-upstream")
	if res.Trusted {
		t.Fatal("expected anomaly for unknown upstream")
	}
	if res.Anomaly != AnomalyUnknownServer {
		t.Errorf("expected AnomalyUnknownServer, got %s", res.Anomaly)
	}
}

func TestPoisonVerifier_TrustedUpstream(t *testing.T) {
	t.Parallel()
	v := NewPoisonVerifier()
	v.AddAnchor(Anchor{
		DomainPatterns: []string{"example.com"},
		UpstreamIDs:    []string{"trusted"},
	})
	q := buildSimpleQuery("example.com", 1)
	r := buildSimpleResponse("example.com", 1, []string{"1.2.3.4"})
	res := v.VerifyResponse(q, r, "trusted")
	if !res.Trusted {
		t.Errorf("expected trusted, got anomaly %s reason=%s", res.Anomaly, res.Reason)
	}
}

func TestPoisonVerifier_TTLDrift(t *testing.T) {
	t.Parallel()
	v := NewPoisonVerifier()
	v.AddAnchor(Anchor{
		DomainPatterns: []string{"example.com"},
		MinTTL:         300,
	})
	q := buildSimpleQuery("example.com", 1)
	r := buildSimpleResponseWithTTL("example.com", 1, []string{"1.2.3.4"}, 10) // TTL 10
	res := v.VerifyResponse(q, r, "u")
	if res.Trusted {
		t.Fatal("expected anomaly for low TTL")
	}
	if res.Anomaly != AnomalyTTLDrift {
		t.Errorf("expected AnomalyTTLDrift, got %s", res.Anomaly)
	}
}

func TestPoisonVerifier_WildcardMatch(t *testing.T) {
	t.Parallel()
	v := NewPoisonVerifier()
	v.AddAnchor(Anchor{
		DomainPatterns: []string{"*.example.com"},
		AllowedIPs:     []string{"1.1.1.1"},
	})
	res := v.VerifyRecord("sub.example.com", []string{"1.1.1.1"}, "u")
	if !res.Trusted {
		t.Errorf("wildcard should match, got anomaly %s", res.Anomaly)
	}
	res = v.VerifyRecord("example.com", []string{"1.1.1.1"}, "u")
	if !res.Trusted {
		t.Errorf("apex should also match via wildcard-fallback, got anomaly %s", res.Anomaly)
	}
}

func TestPoisonVerifier_DefaultUpstreamIDs(t *testing.T) {
	t.Parallel()
	v := NewPoisonVerifier()
	v.SetDefaultUpstreamIDs([]string{"a", "b"})
	v.AddAnchor(Anchor{
		DomainPatterns: []string{"example.com"},
		// No UpstreamIDs - falls back to defaults.
	})
	q := buildSimpleQuery("example.com", 1)
	r := buildSimpleResponse("example.com", 1, []string{"1.2.3.4"})
	res := v.VerifyResponse(q, r, "a")
	if !res.Trusted {
		t.Errorf("expected trusted with default upstream 'a', got %s", res.Anomaly)
	}
	res = v.VerifyResponse(q, r, "evil")
	if res.Trusted {
		t.Error("'evil' upstream should be rejected")
	}
}

func TestPoisonVerifier_TruncatedInput(t *testing.T) {
	t.Parallel()
	v := NewPoisonVerifier()
	res := v.VerifyResponse([]byte{0x00, 0x01}, []byte{0x00, 0x01, 0x00}, "u")
	if res.Trusted {
		t.Error("truncated input must be flagged")
	}
}

func TestAnomalyString(t *testing.T) {
	t.Parallel()
	cases := []struct {
		anomaly Anomaly
		want    string
	}{
		{AnomalyNone, "none"},
		{AnomalyUnknownServer, "unknown_server"},
		{AnomalyIPMismatch, "ip_mismatch"},
		{AnomalyIPRangeMismatch, "ip_range_mismatch"},
		{AnomalyTransactionMismatch, "transaction_id_mismatch"},
		{AnomalyQuestionMismatch, "question_mismatch"},
		{AnomalyUnexpectedRCode, "unexpected_rcode"},
		{AnomalyTTLDrift, "ttl_drift"},
		{Anomaly(99), "anomaly(99)"},
	}
	for _, c := range cases {
		if got := c.anomaly.String(); got != c.want {
			t.Errorf("Anomaly(%d).String() = %q, want %q", int(c.anomaly), got, c.want)
		}
	}
}

// Helper to build a minimal DNS query wire-format for example.com / A (1) / IN (1).
func buildSimpleQuery(name string, txid uint16) []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, txid)
	buf.Write([]byte{0x01, 0x00}) // RD=1
	buf.Write([]byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			continue
		}
		buf.WriteByte(byte(len(label)))
		buf.WriteString(label)
	}
	buf.WriteByte(0)
	buf.Write([]byte{0x00, 0x01, 0x00, 0x01}) // A IN
	return buf.Bytes()
}

func buildSimpleResponse(name string, txid uint16, ips []string) []byte {
	return buildSimpleResponseWithTTL(name, txid, ips, 300)
}

func buildSimpleResponseWithTTL(name string, txid uint16, ips []string, ttl uint32) []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, txid)
	buf.Write([]byte{0x81, 0x80}) // QR=1, RD=1, RA=1
	// QDCOUNT=1, ANCOUNT=len(ips), NSCOUNT=0, ARCOUNT=0 (12-byte header).
	buf.Write([]byte{0x00, 0x01, 0x00, byte(len(ips)), 0x00, 0x00, 0x00, 0x00})
	// Question section.
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			continue
		}
		buf.WriteByte(byte(len(label)))
		buf.WriteString(label)
	}
	buf.WriteByte(0)
	buf.Write([]byte{0x00, 0x01, 0x00, 0x01}) // QTYPE A, QCLASS IN
	// Answer section.
	for _, ip := range ips {
		// Name pointer to offset 12 (question).
		buf.Write([]byte{0xC0, 0x0C})
		buf.Write([]byte{0x00, 0x01}) // A
		buf.Write([]byte{0x00, 0x01}) // IN
		binary.Write(&buf, binary.BigEndian, ttl)
		buf.Write([]byte{0x00, 0x04}) // RDLENGTH=4
		parts := strings.Split(ip, ".")
		if len(parts) != 4 {
			panic(fmt.Sprintf("invalid IP: %s", ip))
		}
		var octets [4]byte
		fmt.Sscanf(ip, "%d.%d.%d.%d", &octets[0], &octets[1], &octets[2], &octets[3])
		buf.Write(octets[:])
	}
	return buf.Bytes()
}
