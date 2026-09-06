package crypt1

import "testing"

func TestRoundTrip(t *testing.T) {
	pt := "hello, world! こんにちは 🌍"
	p, err := Encrypt(pt, "sekret", "test-kid")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if p.V != "crypt1" {
		t.Fatalf("version = %q, want crypt1", p.V)
	}
	if p.Kid != "test-kid" {
		t.Fatalf("kid = %q, want test-kid", p.Kid)
	}
	out, err := Decrypt(p, "sekret")
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if out.Text != pt {
		t.Fatalf("text = %q, want %q", out.Text, pt)
	}
	if out.Kid != "test-kid" {
		t.Fatalf("kid roundtrip = %q, want test-kid", out.Kid)
	}
}

func TestWrongPassphraseFails(t *testing.T) {
	p, err := Encrypt("top secret", "correct", "k1")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := Decrypt(p, "incorrect"); err == nil {
		t.Fatalf("expected decrypt with wrong passphrase to fail")
	}
}

func TestDifferentKIDsProduceDifferentCiphertexts(t *testing.T) {
	a, _ := Encrypt("hi", "pp", "k1")
	b, _ := Encrypt("hi", "pp", "k2")
	if a.D == b.D {
		t.Fatalf("same ciphertext under different kids — likely kid is ignored")
	}
}

func TestEmptyPassphraseRejected(t *testing.T) {
	if _, err := Encrypt("x", "", "k1"); err == nil {
		t.Fatalf("expected empty passphrase to be rejected on encrypt")
	}
	p, _ := Encrypt("x", "ok", "k1")
	if _, err := Decrypt(p, ""); err == nil {
		t.Fatalf("expected empty passphrase to be rejected on decrypt")
	}
}

func TestUnknownVersionRejected(t *testing.T) {
	p, _ := Encrypt("x", "pp", "k1")
	p.V = "crypt2"
	if _, err := Decrypt(p, "pp"); err == nil {
		t.Fatalf("expected unknown version to be rejected")
	}
}

func TestTruncatedPayloadFails(t *testing.T) {
	p, _ := Encrypt("x", "pp", "k1")
	p.D = "AAAA" // too short
	if _, err := Decrypt(p, "pp"); err == nil {
		t.Fatalf("expected truncated payload to be rejected")
	}
}

func TestEmptyPlaintextRoundTrip(t *testing.T) {
	p, err := Encrypt("", "pp", "k1")
	if err != nil {
		t.Fatalf("encrypt empty: %v", err)
	}
	out, err := Decrypt(p, "pp")
	if err != nil {
		t.Fatalf("decrypt empty: %v", err)
	}
	if out.Text != "" {
		t.Fatalf("text = %q, want empty", out.Text)
	}
}

func TestDefaultKidIsApp(t *testing.T) {
	p, _ := Encrypt("x", "pp", "")
	if p.Kid != "app" {
		t.Fatalf("default kid = %q, want app", p.Kid)
	}
}

func TestConstantTimeEqual(t *testing.T) {
	if !ConstantTimeEqual("abc", "abc") {
		t.Fatalf("expected equal strings to be reported equal")
	}
	if ConstantTimeEqual("abc", "abd") {
		t.Fatalf("expected different strings to be reported different")
	}
	if ConstantTimeEqual("abc", "abcd") {
		t.Fatalf("expected different-length strings to be reported different")
	}
}

func TestMultipleEncryptionsHaveDistinctNonces(t *testing.T) {
	// Two encryptions of the same plaintext under the same key should
	// produce different ciphertexts because the nonce varies.
	a, _ := Encrypt("hi", "pp", "k1")
	b, _ := Encrypt("hi", "pp", "k1")
	if a.D == b.D {
		t.Fatalf("expected different ciphertexts, got identical (nonce likely fixed)")
	}
}
