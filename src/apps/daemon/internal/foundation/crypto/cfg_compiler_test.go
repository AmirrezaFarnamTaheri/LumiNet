package crypto

import (
	"bytes"
	"net"
	"testing"
)

func TestCFGCompiler_CompileDecompileSymmetry(t *testing.T) {
	seed := []byte("highly_secure_covert_shared_secret_key_12345")
	compiler := NewCFGCompiler(seed)

	payloads := [][]byte{
		[]byte("hello world"),
		[]byte("lumiNet anti-censorship platform bypass mechanisms"),
		make([]byte, 1000), // Larger blank payload
	}

	mimicTypes := []string{"default", "tls", "https", "dns", "stun"}

	for _, payload := range payloads {
		for _, mimic := range mimicTypes {
			obfuscated, err := compiler.Compile(payload, mimic)
			if err != nil {
				t.Fatalf("failed to compile: %v", err)
			}

			if len(obfuscated) < 13 {
				t.Fatalf("obfuscated packet too short: %d bytes", len(obfuscated))
			}

			decompiled, err := compiler.Decompile(obfuscated)
			if err != nil {
				t.Fatalf("failed to decompile payload (mimic=%s): %v", mimic, err)
			}

			if !bytes.Equal(payload, decompiled) {
				t.Errorf("de-obfuscated payload mismatch (mimic=%s)", mimic)
			}
		}
	}
}

func TestCFGCompiler_DifferentSeeds(t *testing.T) {
	seed1 := []byte("secret_1")
	seed2 := []byte("secret_2")

	compiler1 := NewCFGCompiler(seed1)
	compiler2 := NewCFGCompiler(seed2)

	payload := []byte("covert data stream validation")

	obfuscated1, err := compiler1.Compile(payload, "default")
	if err != nil {
		t.Fatalf("failed compile: %v", err)
	}

	// Decompiling obfuscated1 with seed2 must fail validation checks
	_, err = compiler2.Decompile(obfuscated1)
	if err == nil {
		t.Error("expected decryption failure when using incorrect secret seed key, but got nil error")
	}
}

func TestCFGCompiler_CorruptedHeader(t *testing.T) {
	seed := []byte("shared_secret")
	compiler := NewCFGCompiler(seed)
	payload := []byte("test payload for corruption checks")

	obfuscated, err := compiler.Compile(payload, "default")
	if err != nil {
		t.Fatalf("failed compile: %v", err)
	}

	// Corrupt one byte of the header (offset 8 to 12)
	corrupted := make([]byte, len(obfuscated))
	copy(corrupted, obfuscated)
	corrupted[10] ^= 0xFF

	_, err = compiler.Decompile(corrupted)
	if err == nil {
		t.Error("expected validation failure on header corruption, but got none")
	}
}

func TestCFGConn_ReadWrite(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	seed := []byte("cfg-shared-secret-key")

	cfgC1 := NewCFGConn(c1, seed, "https")
	cfgC2 := NewCFGConn(c2, seed, "https")

	payload := []byte("obfuscated connection payload over virtual pipe using CFG")

	errChan := make(chan error, 1)
	go func() {
		_, err := cfgC1.Write(payload)
		errChan <- err
	}()

	buf := make([]byte, len(payload))
	n, err := cfgC2.Read(buf)
	if err != nil {
		t.Fatalf("failed to read from CFG conn: %v", err)
	}

	if err := <-errChan; err != nil {
		t.Fatalf("failed to write to CFG conn: %v", err)
	}

	if n != len(payload) {
		t.Errorf("expected read length %d, got %d", len(payload), n)
	}

	if !bytes.Equal(buf, payload) {
		t.Errorf("expected payload %q, got %q", payload, buf)
	}
}
