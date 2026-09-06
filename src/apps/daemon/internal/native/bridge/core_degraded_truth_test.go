//go:build !cgo || android || ios

package bridge

import (
	"errors"
	"fmt"
	"net"
	"testing"
)

func TestNativeOnlyFallbacksFailClosed(t *testing.T) {
	if NativeCoreLinked {
		t.Fatal("degraded build must report native core unlinked")
	}
	if _, err := NegotiateVersion(); !errors.Is(err, ErrNativeCoreUnavailable) {
		t.Fatalf("NegotiateVersion: got %v, want native-unavailable", err)
	}
	if _, err := IcmpScan([]string{"127.0.0.1"}, ScanConfig{}); !errors.Is(err, ErrNativeCoreUnavailable) {
		t.Fatalf("IcmpScan: got %v, want native-unavailable", err)
	}
	if _, err := SniDetect("example.com", 100); !errors.Is(err, ErrNativeCoreUnavailable) {
		t.Fatalf("SniDetect: got %v, want native-unavailable", err)
	}
	if _, err := SpeedTest("https://example.com", 100); !errors.Is(err, ErrNativeCoreUnavailable) {
		t.Fatalf("SpeedTest: got %v, want native-unavailable", err)
	}
	if _, err := WgProbe("127.0.0.1", 51820, 100, 0); !errors.Is(err, ErrNativeCoreUnavailable) {
		t.Fatalf("WgProbe: got %v, want native-unavailable", err)
	}
	if err := InjectFakePacket("127.0.0.1", 443, 1, nil, nil, nil, ""); !errors.Is(err, ErrNativeCoreUnavailable) {
		t.Fatalf("InjectFakePacket: got %v, want native-unavailable", err)
	}
	if _, err := DisassemblePayload([]byte{0x90}, "x64"); !errors.Is(err, ErrNativeCoreUnavailable) {
		t.Fatalf("DisassemblePayload: got %v, want native-unavailable", err)
	}
}

func TestPureGoPortScanHandlesZeroConcurrency(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	results, err := PortScan("127.0.0.1", []uint16{port}, ScanConfig{Timeout: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || !results[0].Open {
		t.Fatalf("unexpected port result: %+v", results)
	}
}

func TestPureGoDNSFallbackUsesRequestedServer(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 512)
		n, peer, err := pc.ReadFrom(buf)
		if err != nil {
			done <- err
			return
		}
		req := buf[:n]
		if n < 17 {
			done <- fmt.Errorf("short DNS query: %d", n)
			return
		}
		off := 12
		for off < n && req[off] != 0 {
			off += int(req[off]) + 1
		}
		off++ // root label
		if off+4 > n {
			done <- fmt.Errorf("malformed DNS question")
			return
		}
		questionEnd := off + 4
		resp := make([]byte, 0, questionEnd+16)
		resp = append(resp, req[0], req[1], 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00)
		resp = append(resp, req[12:questionEnd]...)
		resp = append(resp,
			0xc0, 0x0c, // compressed owner name
			0x00, 0x01, // A
			0x00, 0x01, // IN
			0x00, 0x00, 0x00, 0x3c, // wire TTL (fallback intentionally reports unknown=0)
			0x00, 0x04,
			203, 0, 113, 9,
		)
		_, err = pc.WriteTo(resp, peer)
		done <- err
	}()

	result, err := DnsResolveWithTimeout(pc.LocalAddr().String(), "example.com", "A", 1000)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !result.Success || len(result.Records) != 1 || result.Records[0].Value != "203.0.113.9" {
		t.Fatalf("unexpected DNS result: %+v", result)
	}
	if result.Records[0].TTL != 0 {
		t.Fatalf("fallback must not fabricate TTL, got %d", result.Records[0].TTL)
	}
}
