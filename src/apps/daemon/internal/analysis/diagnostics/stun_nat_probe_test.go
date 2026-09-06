package diagnostics

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestBuildSTUNBindingRequest(t *testing.T) {
	transactionID, packet, err := buildSTUNBindingRequest()
	if err != nil {
		t.Fatal(err)
	}
	if len(packet) != 20 || binary.BigEndian.Uint16(packet[:2]) != stunBindingRequest || binary.BigEndian.Uint32(packet[4:8]) != stunMagicCookie {
		t.Fatalf("invalid binding request: %x", packet)
	}
	if string(packet[8:20]) != string(transactionID[:]) {
		t.Fatal("transaction ID missing from request")
	}
}

func TestParseSTUNBindingResponseIPv4(t *testing.T) {
	tx := [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	mapped := &net.UDPAddr{IP: net.ParseIP("8.8.8.8").To4(), Port: 54321}
	origin := &net.UDPAddr{IP: net.ParseIP("1.1.1.1").To4(), Port: 3478}
	other := &net.UDPAddr{IP: net.ParseIP("9.9.9.9").To4(), Port: 3479}
	packet := stunResponsePacket(tx,
		stunAddressAttribute(stunAttrXORMappedAddress, mapped, tx, true),
		stunAddressAttribute(stunAttrResponseOrigin, origin, tx, false),
		stunAddressAttribute(stunAttrOtherAddress, other, tx, false),
	)
	obs, err := parseSTUNBindingResponse(packet, tx)
	if err != nil {
		t.Fatal(err)
	}
	if !sameUDPEndpoint(obs.mapped, mapped) || !sameUDPEndpoint(obs.responseOrigin, origin) || !sameUDPEndpoint(obs.other, other) {
		t.Fatalf("unexpected observation: %+v", obs)
	}
}

func TestParseSTUNBindingResponseIPv6(t *testing.T) {
	tx := [12]byte{12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
	mapped := &net.UDPAddr{IP: net.ParseIP("2001:4860:4860::8888"), Port: 40000}
	packet := stunResponsePacket(tx, stunAddressAttribute(stunAttrXORMappedAddress, mapped, tx, true))
	obs, err := parseSTUNBindingResponse(packet, tx)
	if err != nil {
		t.Fatal(err)
	}
	if !sameUDPEndpoint(obs.mapped, mapped) {
		t.Fatalf("mapped=%v, want %v", obs.mapped, mapped)
	}
}

func TestParseSTUNBindingResponseRejectsTransactionMismatch(t *testing.T) {
	tx := [12]byte{1, 2, 3}
	otherTx := [12]byte{9, 8, 7}
	mapped := &net.UDPAddr{IP: net.ParseIP("8.8.4.4").To4(), Port: 40000}
	packet := stunResponsePacket(tx, stunAddressAttribute(stunAttrXORMappedAddress, mapped, tx, true))
	if _, err := parseSTUNBindingResponse(packet, otherTx); err == nil {
		t.Fatal("transaction mismatch accepted")
	}
}

func stunResponsePacket(tx [12]byte, attrs ...[]byte) []byte {
	bodyLen := 0
	for _, attr := range attrs {
		bodyLen += len(attr)
	}
	packet := make([]byte, 20, 20+bodyLen)
	binary.BigEndian.PutUint16(packet[0:2], stunBindingSuccess)
	binary.BigEndian.PutUint16(packet[2:4], uint16(bodyLen))
	binary.BigEndian.PutUint32(packet[4:8], stunMagicCookie)
	copy(packet[8:20], tx[:])
	for _, attr := range attrs {
		packet = append(packet, attr...)
	}
	return packet
}

func stunAddressAttribute(attrType uint16, address *net.UDPAddr, tx [12]byte, xor bool) []byte {
	ip4 := address.IP.To4()
	family := byte(0x01)
	ip := append([]byte(nil), ip4...)
	if ip4 == nil {
		family = 0x02
		ip = append([]byte(nil), address.IP.To16()...)
	}
	value := make([]byte, 4+len(ip))
	value[1] = family
	port := uint16(address.Port)
	if xor {
		port ^= uint16(stunMagicCookie >> 16)
	}
	binary.BigEndian.PutUint16(value[2:4], port)
	copy(value[4:], ip)
	if xor {
		mask := make([]byte, len(ip))
		binary.BigEndian.PutUint32(mask[:4], stunMagicCookie)
		if len(mask) > 4 {
			copy(mask[4:], tx[:])
		}
		for i := range ip {
			value[4+i] ^= mask[i]
		}
	}
	padded := (len(value) + 3) &^ 3
	attr := make([]byte, 4+padded)
	binary.BigEndian.PutUint16(attr[:2], attrType)
	binary.BigEndian.PutUint16(attr[2:4], uint16(len(value)))
	copy(attr[4:], value)
	return attr
}
