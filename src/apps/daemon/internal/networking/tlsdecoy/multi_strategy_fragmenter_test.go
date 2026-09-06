package tlsdecoy

import (
	"bytes"
	"testing"
	"time"
)

func buildTestClientHello(sniHost string) []byte {
	hostBytes := []byte(sniHost)
	var pkt []byte

	// TLS Record Header: Handshake (0x16), TLS 1.0 (0x03, 0x01), Length placeholder
	pkt = append(pkt, 0x16, 0x03, 0x01, 0x00, 0x00)

	handshakeStart := len(pkt)
	// Handshake Header: ClientHello (0x01), Handshake Length placeholder (3 bytes)
	pkt = append(pkt, 0x01, 0x00, 0x00, 0x00)

	// Version: TLS 1.2 (0x03, 0x03)
	pkt = append(pkt, 0x03, 0x03)

	// Random: 32 bytes
	pkt = append(pkt, bytes.Repeat([]byte{0x42}, 32)...)

	// Session ID: len 0
	pkt = append(pkt, 0x00)

	// Cipher Suites: 2 bytes len + 2 suites (4 bytes)
	pkt = append(pkt, 0x00, 0x04, 0x13, 0x01, 0x13, 0x02)

	// Compression: len 1 + null compression (0x00)
	pkt = append(pkt, 0x01, 0x00)

	// Extensions
	extLenPos := len(pkt)
	pkt = append(pkt, 0x00, 0x00) // placeholder

	extStart := len(pkt)

	// Extension: Server Name Indication (0x0000)
	sniExtLen := 2 + 1 + 2 + len(hostBytes)
	pkt = append(pkt, 0x00, 0x00, byte((sniExtLen>>8)&0xff), byte(sniExtLen&0xff))

	listLen := 1 + 2 + len(hostBytes)
	pkt = append(pkt, byte((listLen>>8)&0xff), byte(listLen&0xff), 0x00, byte((len(hostBytes)>>8)&0xff), byte(len(hostBytes)&0xff))
	pkt = append(pkt, hostBytes...)

	// Fill extensions length
	extLen := len(pkt) - extStart
	pkt[extLenPos] = byte((extLen >> 8) & 0xff)
	pkt[extLenPos+1] = byte(extLen & 0xff)

	// Fill handshake length
	hsLen := len(pkt) - handshakeStart - 4
	pkt[handshakeStart+1] = byte((hsLen >> 16) & 0xff)
	pkt[handshakeStart+2] = byte((hsLen >> 8) & 0xff)
	pkt[handshakeStart+3] = byte(hsLen & 0xff)

	// Fill record length
	recLen := len(pkt) - 5
	pkt[3] = byte((recLen >> 8) & 0xff)
	pkt[4] = byte(recLen & 0xff)

	return pkt
}

func TestLocateSNI_And_ExtractSNI(t *testing.T) {
	pkt := buildTestClientHello("speedtest.net")
	offset, length, found := LocateSNI(pkt)
	if !found {
		t.Fatalf("LocateSNI failed to find SNI")
	}
	if string(pkt[offset:offset+length]) != "speedtest.net" {
		t.Fatalf("unexpected extracted host slice: %s", string(pkt[offset:offset+length]))
	}

	extracted := ExtractSNI(pkt)
	if extracted != "speedtest.net" {
		t.Fatalf("unexpected ExtractSNI output: %s", extracted)
	}
}

func TestTenFragmentationStrategies(t *testing.T) {
	pkt := buildTestClientHello("speedtest.net")
	settings := DefaultFinalMaskSettings()

	// 1. Raw
	raw := FragmentPacket(pkt, FragmentStrategyRaw, settings)
	if len(raw) != 1 || !bytes.Equal(raw[0], pkt) {
		t.Fatalf("Raw fragmentation failed")
	}

	// 2. Full5
	full5 := FragmentPacket(pkt, FragmentStrategyFull5, settings)
	if len(full5) <= 1 || len(full5[0]) != 5 {
		t.Fatalf("Full5 chunking failed")
	}
	if !bytes.Equal(bytes.Join(full5, nil), pkt) {
		t.Fatalf("Full5 reconstruction failed")
	}

	// 3. Full10
	full10 := FragmentPacket(pkt, FragmentStrategyFull10, settings)
	if len(full10[0]) != 10 || !bytes.Equal(bytes.Join(full10, nil), pkt) {
		t.Fatalf("Full10 chunking failed")
	}

	// 4. Full20
	full20 := FragmentPacket(pkt, FragmentStrategyFull20, settings)
	if len(full20[0]) != 20 || !bytes.Equal(bytes.Join(full20, nil), pkt) {
		t.Fatalf("Full20 chunking failed")
	}

	// 5. Half
	half := FragmentPacket(pkt, FragmentStrategyHalf, settings)
	if len(half) != 2 || !bytes.Equal(bytes.Join(half, nil), pkt) {
		t.Fatalf("Half fragmentation failed")
	}

	// 6. SniBoundary
	sniBoundary := FragmentPacket(pkt, FragmentStrategySniBoundary, settings)
	if len(sniBoundary) != 2 || !bytes.Equal(bytes.Join(sniBoundary, nil), pkt) {
		t.Fatalf("SniBoundary fragmentation failed")
	}
	offset, _, _ := LocateSNI(pkt)
	if len(sniBoundary[0]) != offset {
		t.Fatalf("SniBoundary expected offset %d, got %d", offset, len(sniBoundary[0]))
	}

	// 7. SniSplit
	sniSplit := FragmentPacket(pkt, FragmentStrategySniSplit, settings)
	if len(sniSplit) != 2 || !bytes.Equal(bytes.Join(sniSplit, nil), pkt) {
		t.Fatalf("SniSplit fragmentation failed")
	}

	// 8. TlsRecordFrag
	tlsFrag := FragmentPacket(pkt, FragmentStrategyTlsRecordFrag, settings)
	if len(tlsFrag) != 2 || tlsFrag[0][0] != 0x16 || tlsFrag[1][0] != 0x16 {
		t.Fatalf("TlsRecordFrag failed")
	}

	// 9. TlsSniRecords
	tlsSni := FragmentPacket(pkt, FragmentStrategyTlsSniRecords, settings)
	if len(tlsSni) != 2 || tlsSni[0][0] != 0x16 || tlsSni[1][0] != 0x16 {
		t.Fatalf("TlsSniRecords failed")
	}

	// 10. FinalMaskTlsHello
	finalMask := FragmentPacket(pkt, FragmentStrategyFinalMaskTlsHello, settings)
	if len(finalMask) == 0 {
		t.Fatalf("FinalMaskTlsHello failed")
	}
}

func TestRewriteFinalMaskWrites(t *testing.T) {
	pkt := buildTestClientHello("ignitelimit.com")
	settings := DefaultFinalMaskSettings()

	rewrite := RewriteFinalMaskWrites(pkt, settings)
	if len(rewrite.FirstWrite) < 10 || rewrite.FirstWrite[0] != 0x16 {
		t.Fatalf("RewriteFinalMaskWrites first write invalid")
	}
	recordLen := (int(rewrite.FirstWrite[3]) << 8) | int(rewrite.FirstWrite[4])
	if recordLen != 5 {
		t.Fatalf("expected record len 5, got %d", recordLen)
	}

	contiguous := RewriteFinalMaskTlsHello(pkt, settings)
	if !bytes.Equal(contiguous, rewrite.FirstWrite) {
		t.Fatalf("contiguous bytes mismatch")
	}
}

func TestCarrierRouteSelector(t *testing.T) {
	edge1 := CarrierEdgeProfile{Address: "104.18.1.1", Port: 443, Role: "primary", FinalmaskMaxSplit: 2}
	edge2 := CarrierEdgeProfile{Address: "104.18.1.2", Port: 443, Role: "irancell", FinalmaskMaxSplit: 100}
	edge3 := CarrierEdgeProfile{Address: "172.66.0.1", Port: 443, Role: "fallback", FinalmaskMaxSplit: 2}

	edges := []CarrierEdgeProfile{edge1, edge2, edge3}
	selector := NewCarrierRouteSelector(100 * time.Millisecond)

	ordered := selector.OrderedEdges(edges)
	if len(ordered) != 3 || ordered[0].Address != "104.18.1.1" {
		t.Fatalf("unexpected ordered edges initial: %v", ordered)
	}

	selector.RecordFailure(edge1)
	if !selector.IsInCooldown(edge1) {
		t.Fatalf("edge1 should be in cooldown")
	}

	orderedAfterFail := selector.OrderedEdges(edges)
	if orderedAfterFail[0].Address != "104.18.1.2" || orderedAfterFail[2].Address != "104.18.1.1" {
		t.Fatalf("edge1 should be sorted to the end: %v", orderedAfterFail)
	}

	selector.RecordSuccess(edge1)
	if selector.IsInCooldown(edge1) {
		t.Fatalf("edge1 cooldown should be cleared")
	}
	orderedAfterSuccess := selector.OrderedEdges(edges)
	if orderedAfterSuccess[0].Address != "104.18.1.1" {
		t.Fatalf("edge1 should be restored to front: %v", orderedAfterSuccess)
	}
}
