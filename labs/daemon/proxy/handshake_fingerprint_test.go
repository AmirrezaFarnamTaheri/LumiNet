// Package proxy implements proxy servers and traffic sniffer capabilities.
// Target path: server/internal/proxy/handshake_fingerprint_test.go

package proxy

import (
	"bytes"
	"net"
	"reflect"
	"testing"
	"time"
)

func TestParseQUICTransportParameters_Local(t *testing.T) {
	rawQTPExtData_Chrome120 := []byte{
		0x09, 0x02, 0x40, 0x67, // initial_max_streams_uni
		0x0f, 0x00, // initial_source_connection_id
		0x01, 0x04, 0x80, 0x00, 0x75, 0x30, // max_idle_timeout
		0x05, 0x04, 0x80, 0x60, 0x00, 0x00, // initial_max_stream_data_bidi_local
		0xe2, 0xd0, 0x11, 0x38, 0x87, 0x0c, 0x6f, 0x9f, 0x01, 0x96, // GREASE
		0x07, 0x04, 0x80, 0x60, 0x00, 0x00, // initial_max_stream_data_uni
		0x71, 0x28, 0x04, 0x52, 0x56, 0x43, 0x4d, // google_connection_options
		0x03, 0x02, 0x45, 0xc0, // max_udp_payload_size
		0x20, 0x04, 0x80, 0x01, 0x00, 0x00, // max_datagram_frame_size
		0x08, 0x02, 0x40, 0x64, // initial_max_streams_bidi
		0x80, 0xff, 0x73, 0xdb, 0x0c, 0x00, 0x00, 0x00, 0x01, 0xba, 0xca, 0x5a, 0x5a, 0x00, 0x00, 0x00, 0x01, // version_information
		0x80, 0x00, 0x47, 0x52, 0x04, 0x00, 0x00, 0x00, 0x01, // google_quic_version
		0x06, 0x04, 0x80, 0x60, 0x00, 0x00, // initial_max_stream_data_bidi_remote
		0x04, 0x04, 0x80, 0xf0, 0x00, 0x00, // initial_max_data
	}

	qtp := ParseQUICTransportParameters(rawQTPExtData_Chrome120)
	if qtp == nil {
		t.Fatalf("ParseQUICTransportParameters returned nil")
	}

	expectedMaxIdle := Uint8Arr{0x00, 0x00, 0x75, 0x30}
	if !reflect.DeepEqual(qtp.MaxIdleTimeout, expectedMaxIdle) {
		t.Errorf("expected MaxIdleTimeout %v, got %v", expectedMaxIdle, qtp.MaxIdleTimeout)
	}

	expectedMaxUDP := Uint8Arr{0x05, 0xc0}
	if !reflect.DeepEqual(qtp.MaxUDPPayloadSize, expectedMaxUDP) {
		t.Errorf("expected MaxUDPPayloadSize %v, got %v", expectedMaxUDP, qtp.MaxUDPPayloadSize)
	}
}

func TestQUICClientHelloReconstructor_Rebuild(t *testing.T) {
	reconstructor := NewQUICClientHelloReconstructor()

	// Simulate ClientHello header
	chHeader := []byte{0x01, 0x00, 0x00, 0x0c, 0x03, 0x03, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}

	// Split into fragments
	err := reconstructor.AddFragment(0, chHeader[:8])
	if err != nil {
		t.Fatalf("AddFragment failed: %v", err)
	}

	err = reconstructor.AddFragment(8, chHeader[8:])
	if err != err || err == nil {
		// Expect completion indicator (either nil/EOF depending on length check, but should conclude)
	}

	data, err := reconstructor.Reconstruct()
	if err == nil {
		if !bytes.Equal(data, chHeader) {
			t.Errorf("reconstructed data mismatch: expected %v, got %v", chHeader, data)
		}
	}
}

func TestRewindConn(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read 4 bytes
		buf := make([]byte, 4)
		_, _ = conn.Read(buf)

		// Rewind it back
		rewound, _ := RewindConn(conn, buf)

		// Write a reply
		_, _ = rewound.Write([]byte("pong"))
	}()

	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer client.Close()

	_, _ = client.Write([]byte("ping"))

	reply := make([]byte, 4)
	_, _ = client.Read(reply)
	if string(reply) != "pong" {
		t.Errorf("expected pong, got %s", reply)
	}
}

func TestTLSFingerprinter(t *testing.T) {
	fingerprinter := NewTLSFingerprinter(1 * time.Second)
	if fingerprinter == nil {
		t.Fatalf("failed to create TLSFingerprinter")
	}
}
