package peerdiscovery

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"io"
	"net/netip"
	"strings"
)

const NodeIDSize = 20

type NodeID [NodeIDSize]byte

var crc32cTable = crc32.MakeTable(crc32.Castagnoli)

func ParseNodeID(raw string) (NodeID, error) {
	var id NodeID
	raw = strings.TrimSpace(raw)
	if len(raw) != NodeIDSize*2 {
		return id, fmt.Errorf("node ID must be exactly %d hexadecimal characters", NodeIDSize*2)
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil {
		return id, fmt.Errorf("node ID must be hexadecimal: %w", err)
	}
	copy(id[:], decoded)
	return id, nil
}

func (id NodeID) String() string { return hex.EncodeToString(id[:]) }

// GenerateIPv4NodeID creates an IPv4 BEP42 node ID. randomByte is stored in
// the final ID byte and its low three bits bind the CRC prefix to the IP. The
// remaining random bytes come from entropy; nil uses crypto/rand.Reader.
func GenerateIPv4NodeID(address netip.Addr, randomByte byte, entropy io.Reader) (NodeID, error) {
	var id NodeID
	address = address.Unmap()
	if !address.Is4() {
		return id, fmt.Errorf("BEP42 IPv4 node IDs require an IPv4 address")
	}
	if entropy == nil {
		entropy = rand.Reader
	}
	if _, err := io.ReadFull(entropy, id[2:19]); err != nil {
		return id, fmt.Errorf("read node ID entropy: %w", err)
	}
	prefix := bep42IPv4CRC(address, randomByte)
	id[0] = byte(prefix >> 24)
	id[1] = byte(prefix >> 16)
	id[2] = byte(prefix>>8)&0xf8 | id[2]&0x07
	id[19] = randomByte
	return id, nil
}

// ValidIPv4NodeID verifies the 21 BEP42 identity bits against address. The
// lower three bits of byte 2 and bytes 3..18 are intentionally random and are
// therefore not part of the identity check.
func ValidIPv4NodeID(id NodeID, address netip.Addr) bool {
	address = address.Unmap()
	if !address.Is4() {
		return false
	}
	prefix := bep42IPv4CRC(address, id[19])
	return id[0] == byte(prefix>>24) &&
		id[1] == byte(prefix>>16) &&
		id[2]&0xf8 == byte(prefix>>8)&0xf8
}

func bep42IPv4CRC(address netip.Addr, randomByte byte) uint32 {
	bytes := address.As4()
	ip := binary.BigEndian.Uint32(bytes[:])
	masked := (ip & 0x030f3fff) | (uint32(randomByte&0x07) << 29)
	var input [4]byte
	binary.BigEndian.PutUint32(input[:], masked)
	return crc32.Checksum(input[:], crc32cTable)
}
