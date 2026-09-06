package transport

import (
	"bytes"
	"testing"
)

func TestQuicPacketCodec(t *testing.T) {
	codec := &QuicPacketCodec{}

	// Test varint
	vals := []uint64{0, 25, 63, 64, 1500, 16383, 16384, 1073741823}
	for _, v := range vals {
		enc := codec.EncodeVarint(v)
		dec, l, err := codec.DecodeVarint(enc)
		if err != nil || dec != v || l != len(enc) {
			t.Fatalf("varint mismatch for %d: got %d, err %v", v, dec, err)
		}
	}

	// Test Long Header Initial
	hdr := QuicPacketHeader{
		HeaderType:   QuicPktInitial,
		Version:      1,
		DestCID:      []byte{1, 2, 3, 4},
		SrcCID:       []byte{5, 6, 7, 8},
		PacketNumber: 42,
	}
	payload := []byte("quic initial stream frame payload")
	pkt := codec.EncodePacket(hdr, payload)

	decHdr, decPayload, err := codec.DecodePacket(pkt, 4)
	if err != nil {
		t.Fatalf("decode long header packet failed: %v", err)
	}
	if decHdr.HeaderType != QuicPktInitial || decHdr.Version != 1 || decHdr.PacketNumber != 42 {
		t.Fatalf("long header fields mismatch: %+v", decHdr)
	}
	if !bytes.Equal(decPayload, payload) {
		t.Fatalf("payload mismatch")
	}

	// Test Short Header 1-RTT
	shortHdr := QuicPacketHeader{
		HeaderType:   QuicPkt1RttShort,
		Version:      0,
		DestCID:      []byte{0xaa, 0xbb, 0xcc, 0xdd},
		PacketNumber: 105,
	}
	shortPayload := []byte("short 1-rtt app payload")
	shortPkt := codec.EncodePacket(shortHdr, shortPayload)

	decShortHdr, decShortPayload, err := codec.DecodePacket(shortPkt, 4)
	if err != nil {
		t.Fatalf("decode short header packet failed: %v", err)
	}
	if decShortHdr.HeaderType != QuicPkt1RttShort || decShortHdr.PacketNumber != 105 {
		t.Fatalf("short header mismatch: %+v", decShortHdr)
	}
	if !bytes.Equal(decShortPayload, shortPayload) {
		t.Fatalf("short payload mismatch")
	}
}
